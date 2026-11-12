import enum
from typing import NamedTuple

from django.contrib.auth.signals import user_logged_in
from django.db import transaction
from django.dispatch import Signal

DEVICE_ID_SESSION_KEY = 'otp_device_id'

#: Emitted when an OTP verification attempt fails, whether it was made
#: through one of the authentication forms or through :func:`verify_token`.
#: Receivers are called with the ``sender``, the ``user`` that attempted the
#: verification and a public ``reason`` from :class:`VerificationFailure`.
#: The submitted token is deliberately never included in the event.
otp_verification_failed = Signal()


class VerificationFailure(enum.Enum):
    """
    Public classification of OTP verification failures.

    These values are safe to expose to alerting and logging: they describe
    the category of a failure without revealing anything about the submitted
    token or the internals of a device.

    .. data:: NO_DEVICE

       No device was selected, the selected device does not exist, or it does
       not belong to the user. These are deliberately indistinguishable so as
       not to reveal which devices exist.

    .. data:: NOT_ALLOWED

       The device refused verification, e.g. because it is throttled. See
       :meth:`~django_otp.models.Device.verify_is_allowed`.

    .. data:: INVALID_TOKEN

       The device accepted the attempt, but the token did not match.

    """

    NO_DEVICE = 'no_device'
    NOT_ALLOWED = 'not_allowed'
    INVALID_TOKEN = 'invalid_token'


class VerificationResult(NamedTuple):
    """
    The outcome of :func:`verify_device`.

    On success, ``device`` is the verified device and ``reason`` is ``None``.
    On failure, ``device`` is ``None`` and ``reason`` is a
    :class:`VerificationFailure` member. ``extra`` carries the data dict
    returned by :meth:`~django_otp.models.Device.verify_is_allowed` when
    verification was not allowed, for local error reporting; it is not part
    of the public classification and is never sent with the signal.
    """

    device: object
    reason: object
    extra: object


def verify_device(user, device, token, sender=None):
    """
    Verifies a :term:`token` against a specific device on behalf of a user.

    This is the shared verification boundary used by both the authentication
    forms and :func:`verify_token`, so that all entry points classify
    failures the same way. Custom devices plug in through the usual
    :meth:`~django_otp.models.Device.verify_is_allowed` and
    :meth:`~django_otp.models.Device.verify_token` methods.

    On failure, :data:`otp_verification_failed` is emitted with a public
    :class:`VerificationFailure` ``reason``; the token is never included in
    the event.

    :param user: The user supplying the token.
    :type user: :class:`~django.contrib.auth.models.User`

    :param device: The device to verify against, or ``None``.
    :type device: :class:`~django_otp.models.Device` or ``None``

    :param str token: An OTP token to verify.

    :param sender: The ``sender`` to report when emitting
        :data:`otp_verification_failed`.

    :rtype: :class:`VerificationResult`

    """
    if (device is None) or (device.user_id != user.pk):
        # SECURITY: A device that doesn't exist and one that belongs to
        # another user must be indistinguishable here.
        result = VerificationResult(None, VerificationFailure.NO_DEVICE, None)
    else:
        verify_is_allowed, extra = device.verify_is_allowed()
        if not verify_is_allowed:
            result = VerificationResult(None, VerificationFailure.NOT_ALLOWED, extra)
        elif device.verify_token(token):
            result = VerificationResult(device, None, None)
        else:
            result = VerificationResult(None, VerificationFailure.INVALID_TOKEN, None)

    if result.reason is not None:
        otp_verification_failed.send(sender, user=user, reason=result.reason)

    return result


def login(request, device):
    """
    Persist the given OTP device in the current session. The device will be
    rejected if it does not belong to ``request.user``.

    This is called automatically any time :func:`django.contrib.auth.login` is
    called with a user having an ``otp_device`` atribute. If you use Django's
    :class:`~django.contrib.auth.views.LoginView` view with the django-otp
    authentication forms, then you won't need to call this.

    :param request: The HTTP request
    :type request: :class:`~django.http.HttpRequest`

    :param device: The OTP device used to verify the user.
    :type device: :class:`~django_otp.models.Device`
    """
    user = getattr(request, 'user', None)

    if (user is not None) and (device is not None) and (device.user_id == user.pk):
        request.session[DEVICE_ID_SESSION_KEY] = device.persistent_id
        request.user.otp_device = device


def _handle_auth_login(sender, request, user, **kwargs):
    """
    Automatically persists an OTP device that was set by an OTP-aware
    AuthenticationForm.
    """
    if hasattr(user, 'otp_device'):
        login(request, user.otp_device)


user_logged_in.connect(_handle_auth_login)


def verify_token(user, device_id, token):
    """
    Attempts to verify a :term:`token` against a specific device, identified by
    :attr:`~django_otp.models.Device.persistent_id`.

    This wraps the verification process in a transaction to ensure that things
    like throttling polices are properly enforced.

    Verification goes through :func:`verify_device`, so failures are
    classified and reported via :data:`otp_verification_failed` exactly as
    they are by the authentication forms.

    :param user: The user supplying the token.
    :type user: :class:`~django.contrib.auth.models.User`

    :param str device_id: A device's persistent_id value.

    :param str token: An OTP token to verify.

    :returns: The device that accepted ``token``, if any.
    :rtype: :class:`~django_otp.models.Device` or ``None``

    """
    from django_otp.models import Device

    with transaction.atomic():
        device = Device.from_persistent_id(device_id, for_verify=True)
        result = verify_device(user, device, token)

    return result.device


def match_token(user, token):
    """
    Attempts to verify a :term:`token` on every device attached to the given
    user until one of them succeeds.

    .. warning::

        This originally existed for more convenient integration with the admin
        site. Its use is no longer recommended and it is not guaranteed to
        interact well with more recent features (such as throttling). Tokens
        should always be verified against specific devices.

    :param user: The user supplying the token.
    :type user: :class:`~django.contrib.auth.models.User`

    :param str token: An OTP token to verify.

    :returns: The device that accepted ``token``, if any.
    :rtype: :class:`~django_otp.models.Device` or ``None``
    """
    with transaction.atomic():
        for device in devices_for_user(user, for_verify=True):
            if device.verify_token(token):
                break
        else:
            device = None

    return device


def devices_for_user(user, confirmed=True, for_verify=False):
    """
    Return an iterable of all devices registered to the given user.

    Returns an empty iterable for anonymous users.

    :param user: standard or custom user object.
    :type user: :class:`~django.contrib.auth.models.User`

    :param bool confirmed: If ``None``, all matching devices are returned.
        Otherwise, this can be any true or false value to limit the query
        to confirmed or unconfirmed devices, respectively.

    :param bool for_verify: If ``True``, we'll load the devices with
        :meth:`~django.db.models.query.QuerySet.select_for_update` to prevent
        concurrent verifications from succeeding. In which case, this must be
        called inside a transaction.

    :rtype: iterable
    """
    if user.is_anonymous:
        return

    for model in device_classes():
        device_set = model.objects.devices_for_user(user, confirmed=confirmed)
        if for_verify:
            device_set = device_set.select_for_update()

        yield from device_set


def user_has_device(user, confirmed=True):
    """
    Return ``True`` if the user has at least one device.

    Returns ``False`` for anonymous users.

    :param user: standard or custom user object.
    :type user: :class:`~django.contrib.auth.models.User`

    :param confirmed: If ``None``, all matching devices are considered.
        Otherwise, this can be any true or false value to limit the query
        to confirmed or unconfirmed devices, respectively.
    """
    try:
        next(devices_for_user(user, confirmed=confirmed))
    except StopIteration:
        has_device = False
    else:
        has_device = True

    return has_device


def device_classes():
    """
    Returns an iterable of all loaded device models.
    """
    from django.apps import apps  # isort: skip
    from django_otp.models import Device

    for config in apps.get_app_configs():
        for model in config.get_models():
            if issubclass(model, Device) and not model._meta.proxy:
                yield model
