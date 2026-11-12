from io import StringIO

from django.contrib.admin import AdminSite
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.db import IntegrityError
from django.test import RequestFactory
from django.test.utils import override_settings

from django_otp.forms import OTPAuthenticationForm
from django_otp.test_utils import TestCase, ThrottlingTestMixin, TimestampTestMixin

from .admin import StaticDeviceAdmin, StaticTokenInline
from .lib import add_static_token
from .models import StaticDevice, StaticToken, hash_token


def create_legacy_token(device, token):
    """
    Inserts a row the way older versions wrote them: plaintext in ``token``
    and no digest. Bypasses the model so the hashing-on-save behavior does not
    kick in.
    """
    return StaticToken.objects.bulk_create(
        [StaticToken(device=device, token=token, digest='')]
    )[0]


class DeviceTest(TestCase):
    """A few generic tests to get us started."""

    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except Exception:
            self.skipTest("Unable to create the test user.")

    def test_str(self):
        device = StaticDevice.objects.create(user=self.user, name="Device")

        str(device)

    def test_str_unpopulated(self):
        device = StaticDevice()

        str(device)


class LibTest(TestCase):
    """
    Test miscellaneous library functions.
    """

    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except Exception:
            self.skipTest("Unable to create the test user.")

    def test_add_static_token(self):
        statictoken = add_static_token('alice')

        self.assertEqual(statictoken.device.user, self.user)
        self.assertEqual(self.user.staticdevice_set.count(), 1)

    def test_add_static_token_existing_device(self):
        self.user.staticdevice_set.create(name='Test')
        statictoken = add_static_token('alice')

        self.assertEqual(statictoken.device.user, self.user)
        self.assertEqual(self.user.staticdevice_set.count(), 1)
        self.assertEqual(statictoken.device.name, 'Test')

    def test_add_static_token_no_user(self):
        with self.assertRaises(self.User.DoesNotExist):
            add_static_token('bogus')

    def test_add_static_token_specific(self):
        statictoken = add_static_token('alice', 'token')

        self.assertEqual(statictoken.token, '')
        self.assertEqual(statictoken.digest, hash_token('token'))


class AuthFormTest(TestCase):
    """
    Test the auth form with static tokens.

    We try to honor custom user models, but if we can't create users, we'll
    skip the tests.
    """

    def setUp(self):
        for device_id, username in enumerate(['alice', 'bob']):
            try:
                user = self.create_user(username, 'password')
            except IntegrityError:
                self.skipTest("Unable to create a test user.")
            else:
                device = user.staticdevice_set.create(id=device_id + 1)
                device.token_set.create(token=username + '1')
                device.token_set.create(token=username + '1')
                device.token_set.create(token=username + '2')

    def test_empty(self):
        data = {}
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        self.assertEqual(form.get_user(), None)

    def test_bad_password(self):
        data = {
            'username': 'alice',
            'password': 'bogus',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        self.assertEqual(list(form.errors.keys()), ['__all__'])

    def test_no_token(self):
        data = {
            'username': 'alice',
            'password': 'password',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        self.assertEqual(form.get_user().get_username(), 'alice')

    def test_omitted_device(self):
        data = {
            'username': 'alice',
            'password': 'password',
            'otp_token': 'alice1',
        }
        form = OTPAuthenticationForm(None, data)

        # A device must be selected explicitly; we no longer guess by
        # trying the token against each of the user's devices in turn.
        self.assertFalse(form.is_valid())
        alice = form.get_user()
        self.assertEqual(alice.get_username(), 'alice')
        self.assertIsNone(alice.otp_device)

    def test_spoofed_device(self):
        data = {
            'username': 'alice',
            'password': 'password',
            'otp_device': 'otp_static.staticdevice/2',
            'otp_token': 'bob1',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        alice = form.get_user()
        self.assertEqual(alice.get_username(), 'alice')
        self.assertIsNone(alice.otp_device)

    def test_specific_device_fail(self):
        data = {
            'username': 'alice',
            'password': 'password',
            'otp_device': 'otp_email.staticdevice/1',
            'otp_token': 'bogus',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        alice = form.get_user()
        self.assertEqual(alice.get_username(), 'alice')
        self.assertIsNone(alice.otp_device)

    def test_specific_device(self):
        data = {
            'username': 'alice',
            'password': 'password',
            'otp_device': 'otp_static.staticdevice/1',
            'otp_token': 'alice1',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertTrue(form.is_valid())
        alice = form.get_user()
        self.assertEqual(alice.get_username(), 'alice')
        self.assertIsNotNone(alice.otp_device)


@override_settings(
    OTP_STATIC_THROTTLE_FACTOR=1,
)
class ThrottlingTestCase(ThrottlingTestMixin, TestCase):
    def setUp(self):
        try:
            user = self.create_user('alice', 'password')
        except IntegrityError:
            self.skipTest("Unable to create a test user.")
        else:
            self.device = user.staticdevice_set.create()
            self.device.token_set.create(token='valid1')
            self.device.token_set.create(token='valid2')
            self.device.token_set.create(token='valid3')

    def valid_token(self):
        return 'valid1'

    def invalid_token(self):
        return 'bogus'


class TimestampTestCase(TimestampTestMixin, TestCase):
    def setUp(self):
        try:
            user = self.create_user('alice', 'password')
        except IntegrityError:
            self.skipTest("Unable to create a test user.")
        else:
            self.device = user.staticdevice_set.create()
            self.device.token_set.create(token='valid1')
            self.device.token_set.create(token='valid2')
            self.device.token_set.create(token='valid3')

    def valid_token(self):
        return 'valid1'

    def invalid_token(self):
        return 'bogus'


class StaticDeviceAdminTest(TestCase):
    def setUp(self):
        try:
            self.admin = self.create_user(
                'admin',
                'password',
                email='admin@example.com',
                is_staff=True,
            )
        except IntegrityError:
            self.skipTest("Unable to create test user.")
        else:
            self.device = self.admin.staticdevice_set.create()
        self.device_admin = StaticDeviceAdmin(StaticDevice, AdminSite())
        self.get_request = RequestFactory().get('/')
        self.get_request.user = self.admin

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=True)
    def test_inline_instances_when_sensitive_information_hidden(self):
        self._add_device_perms('change_statictoken')
        instances = self.device_admin.get_inline_instances(self.get_request, obj=None)
        self.assertIsInstance(instances, list)
        self.assertEqual(len(instances), 1)
        self.assertIsInstance(instances[0], StaticTokenInline)
        instances = self.device_admin.get_inline_instances(
            self.get_request, obj=self.device
        )
        self.assertEqual(instances, [])

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_inline_instances_when_sensitive_information_shown(self):
        self._add_device_perms('change_statictoken')
        for obj in (None, self.device):
            instances = self.device_admin.get_inline_instances(
                self.get_request, obj=obj
            )
            self.assertIsInstance(instances, list)
            self.assertEqual(len(instances), 1)

    #
    # Helpers
    #

    def _add_device_perms(self, *codenames):
        ct = ContentType.objects.get_for_models(StaticDevice, StaticToken)

        perms = [
            Permission.objects.get(content_type__in=ct.values(), codename=codename)
            for codename in codenames
        ]

        self.admin.user_permissions.add(*perms)


class HashedTokenStorageTest(TestCase):
    """Newly written tokens persist only as digests."""

    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except IntegrityError:
            self.skipTest("Unable to create the test user.")
        self.device = self.user.staticdevice_set.create()

    def test_new_token_stores_digest_only(self):
        statictoken = self.device.token_set.create(token='plain-code')

        self.assertEqual(statictoken.token, '')
        self.assertEqual(statictoken.digest, hash_token('plain-code'))

    def test_database_row_contains_no_plaintext(self):
        self.device.token_set.create(token='plain-code')

        row = StaticToken.objects.get()
        self.assertEqual(row.token, '')
        self.assertNotIn('plain-code', row.digest)
        self.assertEqual(
            StaticToken.objects.filter(token='plain-code').count(), 0
        )

    def test_digest_token_verifies_and_is_consumed(self):
        self.device.token_set.create(token='plain-code')

        self.assertTrue(self.device.verify_token('plain-code'))
        self.assertEqual(self.device.token_set.count(), 0)

    def test_wrong_digest_token_rejected(self):
        self.device.token_set.create(token='plain-code')

        self.assertFalse(self.device.verify_token('other-code'))
        self.assertEqual(self.device.token_set.count(), 1)

    def test_empty_token_does_not_match_digest_rows(self):
        self.device.token_set.create(token='plain-code')

        self.assertFalse(self.device.verify_token(''))
        self.assertEqual(self.device.token_set.count(), 1)


class LegacyTokenTest(TestCase):
    """Plaintext rows written by older versions keep working until consumed."""

    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except IntegrityError:
            self.skipTest("Unable to create the test user.")
        self.device = self.user.staticdevice_set.create()

    def test_legacy_row_shape(self):
        create_legacy_token(self.device, 'legacy-code')

        row = StaticToken.objects.get()
        self.assertEqual(row.token, 'legacy-code')
        self.assertEqual(row.digest, '')

    def test_legacy_token_verifies_and_is_consumed(self):
        create_legacy_token(self.device, 'legacy-code')

        self.assertTrue(self.device.verify_token('legacy-code'))
        self.assertEqual(self.device.token_set.count(), 0)

    def test_legacy_and_digest_rows_coexist(self):
        create_legacy_token(self.device, 'legacy-code')
        self.device.token_set.create(token='new-code')

        self.assertTrue(self.device.verify_token('legacy-code'))
        self.assertEqual(self.device.token_set.count(), 1)
        self.assertTrue(self.device.verify_token('new-code'))
        self.assertEqual(self.device.token_set.count(), 0)

    def test_unknown_legacy_token_rejected(self):
        create_legacy_token(self.device, 'legacy-code')

        self.assertFalse(self.device.verify_token('bogus'))
        self.assertEqual(self.device.token_set.count(), 1)


class MigrateStaticTokensCommandTest(TestCase):
    """The offline migration command is gradual, rerunnable and quiet."""

    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except IntegrityError:
            self.skipTest("Unable to create the test user.")
        self.device = self.user.staticdevice_set.create()

    def test_dry_run_reports_counts_without_writing(self):
        create_legacy_token(self.device, 'legacy-code')

        out = StringIO()
        call_command('migratestatictokens', '--dry-run', stdout=out)
        output = out.getvalue()

        row = StaticToken.objects.get()
        self.assertEqual(row.token, 'legacy-code')
        self.assertEqual(row.digest, '')
        self.assertIn('status: dry-run', output)
        self.assertIn('legacy_rows_remaining: 1', output)
        self.assertIn('rows_converted: 0', output)
        self.assertNotIn('legacy-code', output)

    def test_migration_converts_legacy_row_to_digest(self):
        create_legacy_token(self.device, 'legacy-code')

        out = StringIO()
        call_command('migratestatictokens', stdout=out)
        output = out.getvalue()

        row = StaticToken.objects.get()
        self.assertEqual(row.token, '')
        self.assertEqual(row.digest, hash_token('legacy-code'))
        self.assertTrue(self.device.verify_token('legacy-code'))
        self.assertIn('status: completed', output)
        self.assertIn('rows_converted: 1', output)
        self.assertNotIn('legacy-code', output)

    def test_command_is_rerunnable(self):
        create_legacy_token(self.device, 'legacy-code')
        self.device.token_set.create(token='new-code')

        call_command('migratestatictokens', stdout=StringIO())
        first = StaticToken.objects.get(token='', digest=hash_token('legacy-code'))

        out = StringIO()
        call_command('migratestatictokens', stdout=out)
        output = out.getvalue()

        self.assertEqual(StaticToken.objects.count(), 2)
        self.assertEqual(StaticToken.objects.exclude(token='').count(), 0)
        self.assertEqual(
            StaticToken.objects.get(pk=first.pk).digest,
            hash_token('legacy-code'),
        )
        self.assertIn('legacy_rows_remaining: 0', output)
        self.assertIn('rows_converted: 0', output)

    def test_limit_processes_one_batch_at_a_time(self):
        create_legacy_token(self.device, 'legacy-one')
        create_legacy_token(self.device, 'legacy-two')

        out = StringIO()
        call_command('migratestatictokens', '--limit', '1', stdout=out)
        output = out.getvalue()

        self.assertEqual(
            StaticToken.objects.filter(digest='').exclude(token='').count(), 1
        )
        self.assertIn('rows_converted: 1', output)
        self.assertIn('legacy_rows_remaining: 2', output)

        call_command('migratestatictokens', stdout=StringIO())
        self.assertEqual(
            StaticToken.objects.filter(digest='').exclude(token='').count(), 0
        )
