import functools

from django.contrib.auth.decorators import user_passes_test

from django_otp import (
    REQUIRED_DEVICE_CAPABILITIES_SESSION_KEY,
    user_has_device,
)
from django_otp.capabilities import as_capability_set
from django_otp.conf import settings


def otp_required(
    view=None,
    redirect_field_name='next',
    login_url=None,
    if_configured=False,
    device_capabilities=None,
):
    """
    Similar to :func:`~django.contrib.auth.decorators.login_required`, but
    requires the user to be :term:`verified`. By default, this redirects users
    to :setting:`OTP_LOGIN_URL`.

    :param if_configured: If ``True``, an authenticated user with no confirmed
        OTP devices will be allowed. Default is ``False``.
    :type if_configured: bool

    :param device_capabilities: An optional capability string or iterable of
        capability strings that the verifying device must provide, as
        determined by the :setting:`OTP_DEVICE_CAPABILITIES` callable. A
        session verified by a device that lacks any of these capabilities is
        treated as unverified. On redirect, the required capabilities are
        stashed in the session under
        :data:`~django_otp.REQUIRED_DEVICE_CAPABILITIES_SESSION_KEY` so that the
        login view can offer only suitable devices. Default is ``None``, which
        accepts any verified device.
    """
    if login_url is None:
        login_url = settings.OTP_LOGIN_URL

    required_capabilities = as_capability_set(device_capabilities)

    def test(user):
        if user.is_verified(required_capabilities or None):
            return True

        return (
            if_configured
            and user.is_authenticated
            and not user_has_device(user)
        )

    def decorator(view_func):
        decorated = user_passes_test(
            test, login_url=login_url, redirect_field_name=redirect_field_name
        )(view_func)

        if not required_capabilities:
            return decorated

        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not test(request.user):
                request.session[
                    REQUIRED_DEVICE_CAPABILITIES_SESSION_KEY
                ] = sorted(required_capabilities)
            return decorated(request, *args, **kwargs)

        return wrapper

    return decorator if (view is None) else decorator(view)
