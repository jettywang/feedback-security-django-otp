"""
Support for requiring specific device capabilities.

A :term:`capability` is an opaque string describing something a device can be
used for, such as authorizing a money transfer. The meaning of each capability
is defined entirely by the application that declares it; django-otp only
provides the plumbing to compare the capabilities required by a view with those
offered by the device that verified the current session.

Applications supply a callable that maps a device to the capabilities it
provides. This keeps the policy decision in the application while letting
django-otp enforce it consistently for every request, including sessions that
were verified on an earlier request.
"""
import inspect

from asgiref.sync import iscoroutinefunction

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def _resolve_setting(name):
    return getattr(settings, name, None)


def as_capability_set(capabilities):
    """
    Normalize a single capability or an iterable of capabilities into a
    frozenset.
    """
    if capabilities is None:
        return frozenset()
    if isinstance(capabilities, str):
        return frozenset((capabilities,))
    return frozenset(capabilities)


def get_capability_resolver():
    """
    Return the configured callable that maps a device to its capabilities, or
    ``None`` if no callable has been configured.

    The callable is taken from the :setting:`OTP_DEVICE_CAPABILITIES` setting
    and is called with a single :class:`~django_otp.models.Device` argument. It
    must return a single capability string or an iterable of capability
    strings.
    """
    resolver = _resolve_setting('OTP_DEVICE_CAPABILITIES')
    if resolver is None:
        return None
    if not callable(resolver):
        raise ImproperlyConfigured(
            'The OTP_DEVICE_CAPABILITIES setting must be a callable that '
            'accepts a device and returns its capabilities.'
        )

    return resolver


def get_device_capabilities(device):
    """
    Return the frozenset of capabilities provided by ``device``.

    This delegates to the callable configured via
    :setting:`OTP_DEVICE_CAPABILITIES`. With no callable configured, every
    device has no capabilities.
    """
    if device is None:
        return frozenset()

    resolver = get_capability_resolver()
    if resolver is None:
        return frozenset()

    result = resolver(device)
    if inspect.isawaitable(result):
        # A coroutine resolver can only be consumed by the asynchronous
        # helper; fail loudly rather than treat the coroutine as a value.
        result.close()
        raise ImproperlyConfigured(
            'The OTP_DEVICE_CAPABILITIES callable is a coroutine function, '
            'but get_device_capabilities() was called synchronously. Use '
            'aget_device_capabilities() instead.'
        )

    return as_capability_set(result)


async def aget_device_capabilities(device):
    """
    Asynchronous counterpart of :func:`get_device_capabilities`.

    The configured callable may itself be a coroutine function; its result is
    awaited when it is.
    """
    if device is None:
        return frozenset()

    resolver = get_capability_resolver()
    if resolver is None:
        return frozenset()

    if iscoroutinefunction(resolver):
        result = await resolver(device)
    else:
        result = resolver(device)

    return as_capability_set(result)


def device_has_capabilities(device, required_capabilities):
    """
    Return ``True`` if ``device`` provides every capability in
    ``required_capabilities``.
    """
    required = as_capability_set(required_capabilities)
    if not required:
        return device is not None

    if device is None:
        return False

    return required <= get_device_capabilities(device)


async def adevice_has_capabilities(device, required_capabilities):
    """
    Asynchronous counterpart of :func:`device_has_capabilities`.
    """
    required = as_capability_set(required_capabilities)
    if not required:
        return device is not None

    if device is None:
        return False

    return required <= await aget_device_capabilities(device)


def devices_with_capabilities(devices, required_capabilities):
    """
    Yield the devices in ``devices`` that provide every capability in
    ``required_capabilities``.

    With no required capabilities, every device is yielded unchanged.
    """
    required = as_capability_set(required_capabilities)
    if not required:
        yield from devices
        return

    for device in devices:
        if required <= get_device_capabilities(device):
            yield device
