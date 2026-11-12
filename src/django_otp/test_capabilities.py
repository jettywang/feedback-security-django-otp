from asgiref.sync import async_to_sync

from django.conf import settings as django_settings
from django.contrib.auth import SESSION_KEY
from django.core.exceptions import ImproperlyConfigured
from django.test import AsyncRequestFactory, RequestFactory, override_settings
from django.urls import reverse

from django_otp import (
    DEVICE_ID_SESSION_KEY,
    REQUIRED_DEVICE_CAPABILITIES_SESSION_KEY,
    device_has_capabilities,
    devices_for_user,
    devices_with_capabilities,
    get_device_capabilities,
    oath,
)
from django_otp.capabilities import (
    adevice_has_capabilities,
    aget_device_capabilities,
)
from django_otp.forms import OTPTokenForm
from django_otp.middleware import OTPMiddleware
from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from .test_utils import TestCase


TRANSFER = 'transfer'


def device_capabilities(device):
    """
    Dedicated, registered devices (TOTP) may authorize transfers; email and
    static recovery devices may only satisfy generic OTP verification.
    """
    if isinstance(device, TOTPDevice):
        return [TRANSFER]
    return []


async def adevice_capabilities(device):
    return device_capabilities(device)


CAPABILITIES_OVERRIDE = override_settings(
    OTP_DEVICE_CAPABILITIES=device_capabilities
)


@CAPABILITIES_OVERRIDE
class DeviceCapabilitiesTestCase(TestCase):
    def setUp(self):
        self.alice = self.create_user('alice', 'password')
        self.email_device = self.alice.emaildevice_set.create(name='email')
        self.totp_device = self.alice.totpdevice_set.create(name='totp')
        self.static_device = self.alice.staticdevice_set.create(name='static')

    def test_get_device_capabilities(self):
        self.assertEqual(
            get_device_capabilities(self.totp_device), frozenset((TRANSFER,))
        )
        self.assertEqual(get_device_capabilities(self.email_device), frozenset())
        self.assertEqual(get_device_capabilities(None), frozenset())

    def test_string_and_iterable_capabilities(self):
        self.assertTrue(device_has_capabilities(self.totp_device, TRANSFER))
        self.assertTrue(device_has_capabilities(self.totp_device, [TRANSFER]))
        self.assertFalse(device_has_capabilities(self.email_device, TRANSFER))
        # A device must provide every required capability.
        self.assertFalse(
            device_has_capabilities(self.totp_device, [TRANSFER, 'withdraw'])
        )

    def test_no_required_capabilities_requires_a_device(self):
        self.assertTrue(device_has_capabilities(self.totp_device, None))
        self.assertFalse(device_has_capabilities(None, None))

    def test_devices_with_capabilities_filters(self):
        devices = list(devices_for_user(self.alice))
        capable = list(devices_with_capabilities(devices, TRANSFER))

        self.assertEqual(capable, [self.totp_device])

    def test_devices_with_capabilities_no_requirement(self):
        devices = list(devices_for_user(self.alice))

        self.assertEqual(
            list(devices_with_capabilities(devices, None)), devices
        )

    def test_async_resolution(self):
        self.assertEqual(
            async_to_sync(aget_device_capabilities)(self.totp_device),
            frozenset((TRANSFER,)),
        )
        self.assertTrue(
            async_to_sync(adevice_has_capabilities)(
                self.totp_device, TRANSFER
            )
        )
        self.assertFalse(
            async_to_sync(adevice_has_capabilities)(
                self.email_device, TRANSFER
            )
        )

    @override_settings(OTP_DEVICE_CAPABILITIES=adevice_capabilities)
    def test_async_resolver_coroutine_function(self):
        self.assertEqual(
            async_to_sync(aget_device_capabilities)(self.totp_device),
            frozenset((TRANSFER,)),
        )

        with self.assertRaises(ImproperlyConfigured):
            get_device_capabilities(self.totp_device)


class DeviceCapabilitiesConfigurationTestCase(TestCase):
    def test_no_setting_means_no_capabilities(self):
        device = StaticDevice.objects.create(
            user=self.create_user('carol', 'password'), name='static'
        )

        self.assertEqual(get_device_capabilities(device), frozenset())
        self.assertFalse(device_has_capabilities(device, TRANSFER))

    @override_settings(OTP_DEVICE_CAPABILITIES='not-a-callable')
    def test_invalid_setting_raises(self):
        device = StaticDevice.objects.create(
            user=self.create_user('dave', 'password'), name='static'
        )

        with self.assertRaises(ImproperlyConfigured):
            get_device_capabilities(device)


@CAPABILITIES_OVERRIDE
class CapableDecoratorTestCase(TestCase):
    def setUp(self):
        self.alice = self.create_user('alice', 'password')
        self.totp_device = self.alice.totpdevice_set.create(name='totp')

    def test_if_configured_allows_user_without_devices(self):
        bob = self.create_user('bob', 'password')
        self.client.force_login(bob)

        response = self.client.get(reverse('require-transfer'))
        # Bob has no confirmed devices; the decorated view's if_configured is
        # not enabled, so he is redirected to re-authentication.
        self.assertEqual(response.status_code, 302)

    def test_stashed_capabilities_are_sorted_and_persisted(self):
        from django_otp.decorators import otp_required

        @otp_required(device_capabilities=['zebra', TRANSFER])
        def protected(request):
            return None

        middleware = OTPMiddleware(lambda r: None)
        request = RequestFactory().get('/')
        request.user = self.alice
        request.session = {}
        middleware(request)

        # The user is authenticated but not verified, so the wrapper stashes
        # the (sorted) required capabilities and redirects to re-verify.
        response = protected(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            request.session[REQUIRED_DEVICE_CAPABILITIES_SESSION_KEY],
            [TRANSFER, 'zebra'],
        )


@CAPABILITIES_OVERRIDE
class CapableMiddlewareTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.alice = self.create_user('alice', 'password')
        self.email_device = self.alice.emaildevice_set.create(name='email')
        self.totp_device = self.alice.totpdevice_set.create(name='totp')
        self.middleware = OTPMiddleware(lambda r: None)

    def _verified_request(self, device):
        request = self.factory.get('/')
        request.user = self.alice
        request.session = {DEVICE_ID_SESSION_KEY: device.persistent_id}
        self.middleware(request)
        return request

    def test_plain_verification_ignores_capabilities(self):
        request = self._verified_request(self.email_device)

        self.assertTrue(request.user.is_verified())

    def test_capability_check_uses_actual_device(self):
        request = self._verified_request(self.email_device)

        self.assertFalse(request.user.is_verified(TRANSFER))
        self.assertTrue(request.user.is_verified())

        request = self._verified_request(self.totp_device)
        self.assertTrue(request.user.is_verified(TRANSFER))

    def test_capability_check_is_per_request(self):
        request = self._verified_request(self.totp_device)
        self.assertTrue(request.user.is_verified(TRANSFER))

        # Disabling the qualifying device forces a fresh decision next request.
        self.totp_device.confirmed = False
        self.totp_device.save(update_fields=['confirmed'])

        request = self._verified_request(self.totp_device)
        self.assertFalse(request.user.is_verified())
        self.assertFalse(request.user.is_verified(TRANSFER))

    def test_async_verification_check(self):
        factory = AsyncRequestFactory()

        async def auser():
            return self.alice

        async def run():
            request = factory.get('/')
            request.session = {
                DEVICE_ID_SESSION_KEY: self.totp_device.persistent_id
            }
            request.user = self.alice
            request.auser = auser

            self.middleware(request)
            user = await request.auser()
            return await user.ais_verified(TRANSFER)

        self.assertTrue(async_to_sync(run)())


@CAPABILITIES_OVERRIDE
@override_settings(OTP_TOTP_THROTTLE_FACTOR=0, OTP_EMAIL_THROTTLE_FACTOR=0)
class CapableTokenFormTestCase(TestCase):
    def setUp(self):
        self.alice = self.create_user('alice', 'password')
        self.email_device = self.alice.emaildevice_set.create(name='email')
        self.totp_device = self.alice.totpdevice_set.create(name='totp')

    def test_choices_filtered_by_capabilities(self):
        form = OTPTokenForm(self.alice, device_capabilities=TRANSFER)
        choices = {value for value, label in form.fields['otp_device'].choices}

        self.assertIn(self.totp_device.persistent_id, choices)
        self.assertNotIn(self.email_device.persistent_id, choices)

    def test_choices_unfiltered_without_capabilities(self):
        form = OTPTokenForm(self.alice)
        choices = {value for value, label in form.fields['otp_device'].choices}

        self.assertIn(self.totp_device.persistent_id, choices)
        self.assertIn(self.email_device.persistent_id, choices)

    def test_verification_with_filtered_form(self):
        token = str(oath.totp(self.totp_device.bin_key)).zfill(6)
        form = OTPTokenForm(
            self.alice,
            None,
            device_capabilities=TRANSFER,
            data={
                'otp_device': self.totp_device.persistent_id,
                'otp_token': token,
            },
        )

        self.assertTrue(form.is_valid())
        self.assertEqual(form.get_user().otp_device, self.totp_device)

    def test_unsuitable_submitted_device_is_rejected(self):
        # The email device is absent from the choices, but a crafted POST can
        # still name it. It must be rejected regardless of token validity.
        self.email_device.generate_token()
        form = OTPTokenForm(
            self.alice,
            None,
            device_capabilities=TRANSFER,
            data={
                'otp_device': self.email_device.persistent_id,
                'otp_token': self.email_device.token,
            },
        )

        self.assertFalse(form.is_valid())
        self.assertEqual(
            form.errors['__all__'].as_data()[0].code,
            'device_required',
        )


@CAPABILITIES_OVERRIDE
@override_settings(OTP_TOTP_THROTTLE_FACTOR=0, OTP_EMAIL_THROTTLE_FACTOR=0)
class CapableViewFlowTestCase(TestCase):
    def setUp(self):
        self.alice = self.create_user(
            'alice', 'password', email='alice@example.com'
        )
        self.email_device = self.alice.emaildevice_set.create(name='email')
        self.totp_device = self.alice.totpdevice_set.create(name='totp')

    def _session_verified_with(self, device):
        self.client.force_login(self.alice)
        session_key = self.client.cookies[
            django_settings.SESSION_COOKIE_NAME
        ].value
        engine = self.client.session.__class__
        session = engine(session_key)
        assert SESSION_KEY in session
        session[DEVICE_ID_SESSION_KEY] = device.persistent_id
        session.save()

    def test_email_verification_enters_generic_page(self):
        self._session_verified_with(self.email_device)

        response = self.client.get(reverse('require-otp'))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('home'))

    def test_email_verification_blocked_from_transfer_page(self):
        self._session_verified_with(self.email_device)

        response = self.client.get(reverse('require-transfer'))
        self.assertRedirects(
            response,
            reverse('login-otp') + '?next=' + reverse('require-transfer'),
            fetch_redirect_response=False,
        )
        session = self.client.session
        self.assertEqual(
            session[REQUIRED_DEVICE_CAPABILITIES_SESSION_KEY], [TRANSFER]
        )

    def test_reverification_offers_only_capable_devices(self):
        self._session_verified_with(self.email_device)

        bounced = self.client.get(reverse('require-transfer'))
        self.assertEqual(bounced.status_code, 302)

        response = self.client.get(bounced.url)
        content = response.content.decode(response.charset)

        self.assertIn(self.totp_device.name, content)
        self.assertNotIn(self.email_device.name, content)

    def test_full_flow_then_device_disabled(self):
        self._session_verified_with(self.email_device)

        # Bounced to re-verification with only the TOTP device available.
        response = self.client.get(reverse('require-transfer'))
        self.assertEqual(response.status_code, 302)

        token = str(oath.totp(self.totp_device.bin_key)).zfill(6)
        response = self.client.post(
            reverse('login-otp'),
            {
                'otp_device': self.totp_device.persistent_id,
                'otp_token': token,
                'next': reverse('require-transfer'),
            },
        )
        self.assertRedirects(
            response,
            reverse('require-transfer'),
            fetch_redirect_response=False,
        )

        # Qualifying verification now reaches both generic and transfer views.
        self.assertEqual(
            self.client.get(reverse('require-otp')).status_code, 302
        )
        self.assertEqual(
            self.client.get(reverse('require-transfer')).status_code, 302
        )
        self.assertNotIn(
            REQUIRED_DEVICE_CAPABILITIES_SESSION_KEY, self.client.session
        )

        # Disabling the device invalidates the session on the next request.
        self.totp_device.confirmed = False
        self.totp_device.save(update_fields=['confirmed'])

        response = self.client.get(reverse('require-transfer'))
        self.assertRedirects(
            response,
            reverse('login-otp') + '?next=' + reverse('require-transfer'),
            fetch_redirect_response=False,
        )
