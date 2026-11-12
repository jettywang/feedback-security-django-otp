from functools import partial

from django.contrib.auth import BACKEND_SESSION_KEY
from django.contrib.auth import views as auth_views
from django.utils.functional import cached_property

from django_otp import REQUIRED_DEVICE_CAPABILITIES_SESSION_KEY
from django_otp.forms import OTPAuthenticationForm, OTPTokenForm


class LoginView(auth_views.LoginView):
    """
    This is a replacement for :class:`django.contrib.auth.views.LoginView` that
    requires two-factor authentication. It's slightly clever: if the user is
    already authenticated but not verified, it will only ask the user for their
    OTP token. If the user is anonymous or is already verified by an OTP
    device, it will use the full username/password/token form. In order to use
    this, you must supply a template that is compatible with both
    :class:`~django_otp.forms.OTPAuthenticationForm` and
    :class:`~django_otp.forms.OTPTokenForm`. This is a good view for
    :setting:`OTP_LOGIN_URL`.

    When :func:`~django_otp.decorators.otp_required` redirects a session that
    was verified by an insufficiently capable device, it records the required
    device capabilities in the session. This view reads them and limits the
    devices offered by the token form accordingly, so the user can only
    re-verify with a suitable device.

    """

    otp_authentication_form = OTPAuthenticationForm
    otp_token_form = OTPTokenForm

    @cached_property
    def authentication_form(self):
        user = self.request.user
        required_capabilities = self.get_required_device_capabilities()
        if user.is_anonymous or user.is_verified(required_capabilities):
            form = self.otp_authentication_form
        else:
            form = partial(
                self.otp_token_form,
                user,
                request=self.request,
                device_capabilities=required_capabilities,
            )

        return form

    def get_required_device_capabilities(self):
        return self.request.session.get(
            REQUIRED_DEVICE_CAPABILITIES_SESSION_KEY
        )

    def form_valid(self, form):
        # OTPTokenForm does not call authenticate(), so we may need to populate
        # user.backend ourselves to keep login() happy.
        user = form.get_user()
        if not hasattr(user, 'backend'):
            user.backend = self.request.session[BACKEND_SESSION_KEY]

        response = super().form_valid(form)

        # The capabilities were only needed to scope this re-verification.
        self.request.session.pop(REQUIRED_DEVICE_CAPABILITIES_SESSION_KEY, None)

        return response


# Backwards compatibility.
login = LoginView.as_view()
