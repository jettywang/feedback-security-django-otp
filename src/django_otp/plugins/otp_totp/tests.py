from time import time
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from django.contrib.admin.sites import AdminSite
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError
from django.test import RequestFactory
from django.test.utils import override_settings
from django.urls import reverse

from django_otp.admin import (
    CONFIG_VIEW_DENIED,
    CONFIG_VIEW_GRANTED,
    otp_admin_config_accessed,
)
from django_otp.test_utils import TestCase, ThrottlingTestMixin, TimestampTestMixin

from .admin import TOTPDeviceAdmin
from .models import TOTPDevice


class TOTPDeviceMixin:
    """
    A TestCase helper that gives us a TOTPDevice to work with.
    """

    # The next ten tokens
    tokens = [
        179225,
        656163,
        839400,
        154567,
        346912,
        471576,
        45675,
        101397,
        491039,
        784503,
    ]

    def setUp(self):
        """
        Create a device at the fourth time step. The current token is 154567.
        """
        try:
            self.alice = self.create_user(
                'alice', 'password', email='alice@example.com'
            )
        except IntegrityError:
            self.skipTest("Unable to create the test user.")
        else:
            self.device = self.alice.totpdevice_set.create(
                key='2a2bbba1092ffdd25a328ad1a0a5f5d61d7aacc4',
                step=30,
                t0=int(time() - (30 * 3)),
                digits=6,
                tolerance=0,
                drift=0,
            )


@override_settings(
    OTP_TOTP_SYNC=False,
    OTP_TOTP_THROTTLE_FACTOR=0,
)
class TOTPTest(TOTPDeviceMixin, TestCase):
    def test_default_key(self):
        device = self.alice.totpdevice_set.create()

        # Make sure we can decode the key.
        device.bin_key

    def test_single(self):
        results = [self.device.verify_token(token) for token in self.tokens]

        self.assertEqual(results, [False] * 3 + [True] + [False] * 6)

    def test_tolerance(self):
        self.device.tolerance = 1
        results = [self.device.verify_token(token) for token in self.tokens]

        self.assertEqual(results, [False] * 2 + [True] * 3 + [False] * 5)

    def test_drift(self):
        self.device.tolerance = 1
        self.device.drift = -1
        results = [self.device.verify_token(token) for token in self.tokens]

        self.assertEqual(results, [False] * 1 + [True] * 3 + [False] * 6)

    def test_sync_drift(self):
        self.device.tolerance = 2
        with self.settings(OTP_TOTP_SYNC=True):
            ok = self.device.verify_token(self.tokens[5])

        self.assertTrue(ok)
        self.assertEqual(self.device.drift, 2)

    def test_no_reuse(self):
        verified1 = self.device.verify_token(self.tokens[3])
        verified2 = self.device.verify_token(self.tokens[3])

        self.assertEqual(self.device.last_t, 3)
        self.assertTrue(verified1)
        self.assertFalse(verified2)

    def test_config_url(self):
        with override_settings(OTP_TOTP_ISSUER=None):
            url = self.device.config_url

        parsed = urlsplit(url)
        params = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, 'otpauth')
        self.assertEqual(parsed.netloc, 'totp')
        self.assertEqual(parsed.path, '/alice')
        self.assertIn('secret', params)
        self.assertNotIn('issuer', params)

    def test_config_url_issuer(self):
        with override_settings(OTP_TOTP_ISSUER='example.com'):
            url = self.device.config_url

        parsed = urlsplit(url)
        params = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, 'otpauth')
        self.assertEqual(parsed.netloc, 'totp')
        self.assertEqual(parsed.path, '/example.com%3Aalice')
        self.assertIn('secret', params)
        self.assertIn('issuer', params)
        self.assertEqual(params['issuer'][0], 'example.com')

    def test_config_url_issuer_spaces(self):
        with override_settings(OTP_TOTP_ISSUER='Very Trustworthy Source'):
            url = self.device.config_url

        parsed = urlsplit(url)
        params = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, 'otpauth')
        self.assertEqual(parsed.netloc, 'totp')
        self.assertEqual(parsed.path, '/Very%20Trustworthy%20Source%3Aalice')
        self.assertIn('secret', params)
        self.assertIn('issuer', params)
        self.assertEqual(params['issuer'][0], 'Very Trustworthy Source')

    def test_config_url_issuer_method(self):
        with override_settings(OTP_TOTP_ISSUER=lambda d: d.user.email):
            url = self.device.config_url

        parsed = urlsplit(url)
        params = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, 'otpauth')
        self.assertEqual(parsed.netloc, 'totp')
        self.assertEqual(parsed.path, '/alice%40example.com%3Aalice')
        self.assertIn('secret', params)
        self.assertIn('issuer', params)
        self.assertEqual(params['issuer'][0], 'alice@example.com')

    def test_config_url_image(self):
        image_url = "https://test.invalid/square.png"

        with override_settings(OTP_TOTP_ISSUER=None, OTP_TOTP_IMAGE=image_url):
            url = self.device.config_url

        parsed = urlsplit(url)
        params = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, 'otpauth')
        self.assertEqual(parsed.netloc, 'totp')
        self.assertEqual(parsed.path, '/alice')
        self.assertIn('secret', params)
        self.assertEqual(params['image'][0], image_url)


class TOTPAdminTest(TestCase):
    def setUp(self):
        """
        Create a device at the fourth time step. The current token is 154567.
        """
        try:
            self.admin = self.create_user(
                'admin', 'password', email='admin@example.com', is_staff=True
            )
        except IntegrityError:
            self.skipTest("Unable to create the test user.")
        else:
            self.device = self.admin.totpdevice_set.create(
                key='2a2bbba1092ffdd25a328ad1a0a5f5d61d7aacc4',
                step=30,
                t0=int(time() - (30 * 3)),
                digits=6,
                tolerance=0,
                drift=0,
            )
        self.device_admin = TOTPDeviceAdmin(TOTPDevice, AdminSite())
        self.get_request = RequestFactory().get('/')
        self.get_request.user = self.admin
        self.audit_events = []

    def _connect_audit(self):
        otp_admin_config_accessed.connect(self._record_audit)
        self.addCleanup(otp_admin_config_accessed.disconnect, self._record_audit)

    def _record_audit(self, sender, **kwargs):
        self.audit_events.append(
            {key: value for key, value in kwargs.items() if key != 'signal'}
        )

    def test_anonymous(self):
        for suffix in ['config', 'qrcode']:
            with self.subTest(view=suffix):
                url = reverse(
                    'admin:otp_totp_totpdevice_' + suffix, kwargs={'pk': self.device.pk}
                )
                response = self.client.get(url)
                self.assertEqual(response.status_code, 302)

    def test_unauthorized(self):
        self.client.login(username='admin', password='password')

        for suffix in ['config', 'qrcode']:
            with self.subTest(view=suffix):
                url = reverse(
                    'admin:otp_totp_totpdevice_' + suffix, kwargs={'pk': self.device.pk}
                )
                response = self.client.get(url)
                self.assertEqual(response.status_code, 403)

    def test_metadata_view_perm_does_not_expose_configuration(self):
        self._add_device_perms('view_totpdevice')
        self.client.login(username='admin', password='password')

        list_url = reverse('admin:otp_totp_totpdevice_changelist')
        response = self.client.get(list_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'qrcode')

        detail_url = reverse(
            'admin:otp_totp_totpdevice_change', kwargs={'object_id': self.device.pk}
        )
        response = self.client.get(detail_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, self.device.key)
        self.assertNotContains(response, 'qrcode')

        for suffix in ['config', 'qrcode']:
            with self.subTest(view=suffix):
                url = reverse(
                    'admin:otp_totp_totpdevice_' + suffix, kwargs={'pk': self.device.pk}
                )
                response = self.client.get(url)
                self.assertEqual(response.status_code, 403)

    def test_metadata_change_perm_does_not_expose_configuration(self):
        self._add_device_perms('change_totpdevice')
        self.client.login(username='admin', password='password')

        list_url = reverse('admin:otp_totp_totpdevice_changelist')
        response = self.client.get(list_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, self.device.key)

        for suffix in ['config', 'qrcode']:
            with self.subTest(view=suffix):
                url = reverse(
                    'admin:otp_totp_totpdevice_' + suffix, kwargs={'pk': self.device.pk}
                )
                response = self.client.get(url)
                self.assertEqual(response.status_code, 403)

    def test_config_perm(self):
        self._add_device_perms('view_totpdevice', 'view_totpdevice_config')
        self.client.login(username='admin', password='password')

        for suffix in ['config', 'qrcode']:
            with self.subTest(view=suffix):
                url = reverse(
                    'admin:otp_totp_totpdevice_' + suffix, kwargs={'pk': self.device.pk}
                )
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)

    def test_config_perm_requires_model_permission(self):
        self._add_device_perms('view_totpdevice_config')
        self.client.login(username='admin', password='password')

        url = reverse('admin:otp_totp_totpdevice_config', kwargs={'pk': self.device.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

    def test_config_perm_with_change_perm(self):
        self._add_device_perms('change_totpdevice', 'view_totpdevice_config')
        self.client.login(username='admin', password='password')

        for suffix in ['config', 'qrcode']:
            with self.subTest(view=suffix):
                url = reverse(
                    'admin:otp_totp_totpdevice_' + suffix, kwargs={'pk': self.device.pk}
                )
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)

    def test_detail_with_config_perm_exposes_key(self):
        self._add_device_perms('view_totpdevice', 'view_totpdevice_config')
        self.client.login(username='admin', password='password')

        detail_url = reverse(
            'admin:otp_totp_totpdevice_change', kwargs={'object_id': self.device.pk}
        )
        response = self.client.get(detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.device.key)
        self.assertContains(response, 'qrcode')

    def test_config_page_has_no_inline_style_or_script(self):
        """
        The QR code config page shouldn't rely on inline style attributes,
        <style> blocks, or event handler attributes (e.g. onerror), since
        those are blocked by a strict Content-Security-Policy.

        https://github.com/django-otp/django-otp/issues/143
        """
        self._add_device_perms('view_totpdevice', 'view_totpdevice_config')
        self.client.login(username='admin', password='password')

        url = reverse('admin:otp_totp_totpdevice_config', kwargs={'pk': self.device.pk})
        response = self.client.get(url)
        content = response.content.decode()

        self.assertNotIn('style="', content)
        self.assertNotIn('<style', content)
        self.assertNotIn('onerror=', content)
        self.assertIn('otp_totp/css/qrcode.css', content)
        self.assertIn('otp_totp/js/qrcode.js', content)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=True)
    def test_sensitive_information_hidden_while_adding_device(self):
        fields = self._get_fields(device=None)
        self.assertIn('key', fields)
        self.assertNotIn('qrcode_link', fields)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=True)
    def test_sensitive_information_hidden_while_changing_device(self):
        self._add_device_perms('view_totpdevice_config')
        fields = self._get_fields(device=self.device)
        self.assertNotIn('key', fields)
        self.assertNotIn('qrcode_link', fields)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_sensitive_information_shown_while_adding_device(self):
        fields = self._get_fields(device=None)
        self.assertIn('key', fields)
        self.assertNotIn('qrcode_link', fields)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_sensitive_information_needs_config_perm_while_changing_device(self):
        fields = self._get_fields(device=self.device)
        self.assertNotIn('key', fields)
        self.assertNotIn('qrcode_link', fields)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_sensitive_information_shown_while_changing_device(self):
        self._add_device_perms('view_totpdevice_config')
        fields = self._get_fields(device=self.device)
        self.assertIn('key', fields)
        self.assertIn('qrcode_link', fields)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=True)
    def test_list_display_when_sensitive_information_hidden(self):
        self._add_device_perms('view_totpdevice_config')
        self.assertEqual(
            self.device_admin.get_list_display(self.get_request),
            ['user', 'name', 'created_at', 'last_used_at', 'confirmed'],
        )

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_list_display_without_config_perm(self):
        self.assertEqual(
            self.device_admin.get_list_display(self.get_request),
            ['user', 'name', 'created_at', 'last_used_at', 'confirmed'],
        )

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_list_display_when_sensitive_information_shown(self):
        self._add_device_perms('view_totpdevice_config')
        self.assertEqual(
            self.device_admin.get_list_display(self.get_request),
            ['user', 'name', 'created_at', 'last_used_at', 'confirmed', 'qrcode_link'],
        )

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=True)
    def test_config_view_when_sensitive_information_hidden(self):
        self._add_device_perms('change_totpdevice', 'view_totpdevice_config')
        with self.assertRaises(PermissionDenied):
            self.device_admin.config_view(self.get_request, self.device.id)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_config_view_without_config_perm(self):
        self._add_device_perms('change_totpdevice')
        with self.assertRaises(PermissionDenied):
            self.device_admin.config_view(self.get_request, self.device.id)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_config_view_when_sensitive_information_shown(self):
        self._add_device_perms('change_totpdevice', 'view_totpdevice_config')
        response = self.device_admin.config_view(self.get_request, self.device.id)
        self.assertEqual(response.status_code, 200)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=True)
    def test_qrcode_view_when_sensitive_information_hidden(self):
        self._add_device_perms('change_totpdevice', 'view_totpdevice_config')
        with self.assertRaises(PermissionDenied):
            self.device_admin.qrcode_view(self.get_request, self.device.id)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_qrcode_view_without_config_perm(self):
        self._add_device_perms('change_totpdevice')
        with self.assertRaises(PermissionDenied):
            self.device_admin.qrcode_view(self.get_request, self.device.id)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_qrcode_view_when_sensitive_information_shown(self):
        self._add_device_perms('change_totpdevice', 'view_totpdevice_config')
        response = self.device_admin.qrcode_view(self.get_request, self.device.id)
        self.assertEqual(response.status_code, 200)

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_qrcode_audit_not_granted_when_image_unavailable(self):
        self._connect_audit()
        self._add_device_perms('change_totpdevice', 'view_totpdevice_config')

        with mock.patch(
            'django_otp.plugins.otp_totp.admin.write_qrcode_image',
            side_effect=ModuleNotFoundError,
        ):
            response = self.device_admin.qrcode_view(self.get_request, self.device.id)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.audit_events, [])

    #
    # Audit tests
    #

    def test_config_access_audit_granted(self):
        self._connect_audit()
        self._add_device_perms('change_totpdevice', 'view_totpdevice_config')

        self.device_admin.config_view(self.get_request, self.device.id)

        self.assertEqual(
            self.audit_events,
            [{'event': CONFIG_VIEW_GRANTED, 'device_id': self.device.id}],
        )

    def test_qrcode_access_audit_granted(self):
        self._connect_audit()
        self._add_device_perms('change_totpdevice', 'view_totpdevice_config')

        self.device_admin.qrcode_view(self.get_request, self.device.id)

        self.assertEqual(
            self.audit_events,
            [{'event': CONFIG_VIEW_GRANTED, 'device_id': self.device.id}],
        )

    def test_config_access_audit_denied_without_config_perm(self):
        self._connect_audit()
        self._add_device_perms('change_totpdevice')

        with self.assertRaises(PermissionDenied):
            self.device_admin.config_view(self.get_request, self.device.id)

        self.assertEqual(
            self.audit_events,
            [{'event': CONFIG_VIEW_DENIED, 'device_id': self.device.id}],
        )

    def test_qrcode_access_audit_denied_without_config_perm(self):
        self._connect_audit()
        self._add_device_perms('change_totpdevice')

        with self.assertRaises(PermissionDenied):
            self.device_admin.qrcode_view(self.get_request, self.device.id)

        self.assertEqual(
            self.audit_events,
            [{'event': CONFIG_VIEW_DENIED, 'device_id': self.device.id}],
        )

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=True)
    def test_config_access_audit_denied_when_hidden(self):
        self._connect_audit()
        self._add_device_perms('change_totpdevice', 'view_totpdevice_config')

        with self.assertRaises(PermissionDenied):
            self.device_admin.config_view(self.get_request, self.device.id)

        self.assertEqual(
            self.audit_events,
            [{'event': CONFIG_VIEW_DENIED, 'device_id': self.device.id}],
        )

    def test_detail_audit_only_when_key_displayed(self):
        self._connect_audit()
        self._add_device_perms('view_totpdevice')
        self.client.login(username='admin', password='password')

        detail_url = reverse(
            'admin:otp_totp_totpdevice_change', kwargs={'object_id': self.device.pk}
        )
        response = self.client.get(detail_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.audit_events, [])

        self._add_device_perms('view_totpdevice_config')
        response = self.client.get(detail_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            self.audit_events,
            [{'event': CONFIG_VIEW_GRANTED, 'device_id': self.device.id}],
        )

    def test_detail_audit_not_recorded_on_non_get(self):
        self._connect_audit()
        self._add_device_perms('view_totpdevice', 'view_totpdevice_config')
        self.client.login(username='admin', password='password')

        detail_url = reverse(
            'admin:otp_totp_totpdevice_change', kwargs={'object_id': self.device.pk}
        )
        self.client.post(detail_url, {})

        self.assertEqual(self.audit_events, [])

    def test_audit_payload_never_contains_secret_or_identity(self):
        self._connect_audit()
        self._add_device_perms('change_totpdevice', 'view_totpdevice_config')

        self.device_admin.config_view(self.get_request, self.device.id)

        for event in self.audit_events:
            self.assertEqual(set(event), {'event', 'device_id'})
            values = {str(value) for value in event.values()}
            self.assertNotIn(self.device.key, values)
            self.assertNotIn('alice', values)
            self.assertNotIn('admin', values)
            self.assertNotIn(self.device.config_url, values)

    def test_audit_log_record_minimal(self):
        self._add_device_perms('change_totpdevice', 'view_totpdevice_config')

        with self.assertLogs('django_otp.audit', level='INFO') as logs:
            self.device_admin.config_view(self.get_request, self.device.id)

            self.admin.user_permissions.clear()
            for attr in ('_perm_cache', '_user_perm_cache'):
                self.admin.__dict__.pop(attr, None)

            with self.assertRaises(PermissionDenied):
                self.device_admin.config_view(self.get_request, self.device.id)

        self.assertEqual(len(logs.records), 2)
        granted, denied = logs.records

        self.assertEqual(granted.event, CONFIG_VIEW_GRANTED)
        self.assertEqual(granted.device_id, self.device.id)
        self.assertEqual(denied.event, CONFIG_VIEW_DENIED)
        self.assertEqual(denied.device_id, self.device.id)
        self.assertEqual(granted.getMessage(), CONFIG_VIEW_GRANTED)
        self.assertEqual(denied.getMessage(), CONFIG_VIEW_DENIED)
        self.assertNotIn(self.device.key, granted.getMessage())
        self.assertNotIn(self.device.key, denied.getMessage())

    #
    # Helpers
    #

    def _add_device_perms(self, *codenames):
        ct = ContentType.objects.get_for_model(TOTPDevice)

        perms = [
            Permission.objects.get(content_type=ct, codename=codename)
            for codename in codenames
        ]

        self.admin.user_permissions.add(*perms)


    def _get_fields(self, device):
        return {
            field
            for fieldset in self.device_admin.get_fieldsets(
                self.get_request, obj=device
            )
            for field in fieldset[1]['fields']
        }


@override_settings(
    OTP_TOTP_THROTTLE_FACTOR=1,
)
class ThrottlingTestCase(TOTPDeviceMixin, ThrottlingTestMixin, TestCase):
    def valid_token(self):
        return self.tokens[3]

    def invalid_token(self):
        return -1


class TimetstampTestCase(TOTPDeviceMixin, TimestampTestMixin, TestCase):
    def valid_token(self):
        return self.tokens[3]

    def invalid_token(self):
        return -1
