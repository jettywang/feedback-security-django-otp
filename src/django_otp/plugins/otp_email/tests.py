from datetime import timedelta
from smtplib import SMTPException

from freezegun import freeze_time

from django.core import mail
from django.core.mail.backends.base import BaseEmailBackend
from django.db import IntegrityError
from django.test.utils import override_settings

from django_otp.forms import OTPAuthenticationForm
from django_otp.test_utils import (
    CooldownTestMixin,
    TestCase,
    ThrottlingTestMixin,
    TimestampTestMixin,
)

from .models import EmailDevice


class EmailDeviceMixin:
    def setUp(self):
        try:
            alice = self.create_user('alice', 'password')
        except IntegrityError:
            self.skipTest("Failed to create user.")
        else:
            self.device = alice.emaildevice_set.create()

        if hasattr(alice, 'email'):
            alice.email = 'alice@example.com'
            alice.save()
        else:
            self.skipTest("User model has no email.")


class AuthFormTest(EmailDeviceMixin, TestCase):
    @override_settings(OTP_EMAIL_SENDER='test@example.com')
    def test_email_interaction(self):
        data = {
            'username': 'alice',
            'password': 'password',
            'otp_device': self.device.persistent_id,
            'otp_token': '',
            'otp_challenge': '1',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        alice = form.get_user()
        self.assertEqual(alice.get_username(), 'alice')
        self.assertIsNone(alice.otp_device)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['alice@example.com'])

        self.device.refresh_from_db()
        data['otp_token'] = self.device.token
        del data['otp_challenge']
        form = OTPAuthenticationForm(None, data)

        self.assertTrue(form.is_valid())
        self.assertIsInstance(form.get_user().otp_device, EmailDevice)


@override_settings(
    DEFAULT_FROM_EMAIL="root@localhost",
    OTP_EMAIL_THROTTLE_FACTOR=0,
)
class EmailTest(EmailDeviceMixin, TestCase):
    def test_token_generator(self):
        self.device.generate_token()
        self.device.token.isnumeric()

    def test_invalid_token(self):
        self.device.generate_token()
        self.assertFalse(self.device.verify_token(0))

    def test_no_reuse(self):
        self.device.generate_token()
        token = self.device.token
        self.assertTrue(self.device.verify_token(token))
        self.assertFalse(self.device.verify_token(token))

    def test_token_expiry(self):
        self.device.generate_token()
        token = self.device.token
        with freeze_time() as frozen_time:
            frozen_time.tick(delta=timedelta(seconds=301))
            self.assertFalse(self.device.verify_token(token))

    def test_defaults(self):
        self.device.generate_challenge()

        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        with self.subTest(field='from_email'):
            self.assertEqual(msg.from_email, "root@localhost")
        with self.subTest(field='body'):
            self.assertEqual(
                msg.body, "Test template 1: {}\n".format(self.device.token)
            )

    @override_settings(
        OTP_EMAIL_SENDER="webmaster@example.com",
        OTP_EMAIL_SUBJECT="Test Subject with token: {token}",
        OTP_EMAIL_BODY_TEMPLATE="Test template: {{token}}",
    )
    def test_settings_with_token_in_subject(self):
        self.device.generate_challenge()

        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        with self.subTest(field='from_email'):
            self.assertEqual(msg.from_email, "webmaster@example.com")
        with self.subTest(field='subject'):
            self.assertEqual(
                msg.subject, "Test Subject with token: {}".format(self.device.token)
            )
        with self.subTest(field='body'):
            self.assertEqual(msg.body, "Test template: {}".format(self.device.token))

    @override_settings(
        OTP_EMAIL_SENDER="webmaster@example.com",
        OTP_EMAIL_SUBJECT="Test subject",
        OTP_EMAIL_BODY_TEMPLATE="Test template 2: {{token}}",
    )
    def test_settings(self):
        self.device.generate_challenge()

        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        with self.subTest(field='from_email'):
            self.assertEqual(msg.from_email, "webmaster@example.com")
        with self.subTest(field='subject'):
            self.assertEqual(msg.subject, "Test subject")
        with self.subTest(field='body'):
            self.assertEqual(msg.body, "Test template 2: {}".format(self.device.token))

    @override_settings(
        OTP_EMAIL_SENDER="webmaster@example.com",
        OTP_EMAIL_SUBJECT="Test subject",
        OTP_EMAIL_BODY_HTML_TEMPLATE="<div>{{token}}</div>",
    )
    def test_settings_html_template(self):
        self.device.generate_challenge()

        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        with self.subTest(field='from_email'):
            self.assertEqual(msg.from_email, "webmaster@example.com")
        with self.subTest(field='subject'):
            self.assertEqual(msg.subject, "Test subject")
        with self.subTest(field='body'):
            self.assertEqual(
                msg.body, 'Test template 1: {}\n'.format(self.device.token)
            )
        with self.subTest(field='alternatives'):
            self.assertEqual(
                msg.alternatives[0],
                ('<div>{}</div>'.format(self.device.token), 'text/html'),
            )

    @override_settings(
        OTP_EMAIL_SENDER="webmaster@example.com",
        OTP_EMAIL_SUBJECT="Test subject",
        OTP_EMAIL_BODY_TEMPLATE_PATH="otp/email/custom.txt",
    )
    def test_settings_template_path(self):
        self.device.generate_challenge()

        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        with self.subTest(field='from_email'):
            self.assertEqual(msg.from_email, "webmaster@example.com")
        with self.subTest(field='subject'):
            self.assertEqual(msg.subject, "Test subject")
        with self.subTest(field='body'):
            self.assertEqual(
                msg.body, "Test template 3: {}\n".format(self.device.token)
            )

    @override_settings(
        OTP_EMAIL_SENDER="webmaster@example.com",
        OTP_EMAIL_SUBJECT="Test subject",
        OTP_EMAIL_BODY_HTML_TEMPLATE_PATH="otp/email/custom_html.html",
    )
    def test_settings_html_template_path(self):
        self.device.generate_challenge()

        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        with self.subTest(field='from_email'):
            self.assertEqual(msg.from_email, "webmaster@example.com")
        with self.subTest(field='subject'):
            self.assertEqual(msg.subject, "Test subject")
        with self.subTest(field='body'):
            self.assertEqual(
                msg.body, 'Test template 1: {}\n'.format(self.device.token)
            )
        with self.subTest(field='alternatives'):
            self.assertEqual(
                msg.alternatives[0],
                ('<p>{}</p>'.format(self.device.token), 'text/html'),
            )

    @override_settings(
        OTP_EMAIL_SENDER="webmaster@example.com",
        OTP_EMAIL_SUBJECT="Test subject",
        OTP_EMAIL_BODY_TEMPLATE="Test template 4: {{token}} {{foo}} {{bar}}",
    )
    def test_settings_extra_template_options(self):
        extra_context = {"foo": "extra 1", "bar": "extra 2"}
        self.device.generate_challenge(extra_context)

        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        with self.subTest(field='from_email'):
            self.assertEqual(msg.from_email, "webmaster@example.com")
        with self.subTest(field='subject'):
            self.assertEqual(msg.subject, "Test subject")
        with self.subTest(field='body'):
            self.assertEqual(
                msg.body,
                "Test template 4: {} {} {}".format(
                    self.device.token, extra_context["foo"], extra_context["bar"]
                ),
            )

    def test_alternative_email(self):
        self.device.email = 'alice2@example.com'
        self.device.save()

        self.device.generate_challenge()

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['alice2@example.com'])


class ControllableEmailBackend(BaseEmailBackend):
    """
    A test email backend that records sent messages and can be told to fail.

    Delivery is controlled through class attributes so tests can toggle
    failures between requests:

    .. attribute:: outbox

        A list of all messages sent so far.

    .. attribute:: fail_with

        If not ``None``, the exception to raise from ``send_messages``.

    """

    outbox = []
    fail_with = None

    @classmethod
    def reset(cls):
        cls.outbox = []
        cls.fail_with = None

    def send_messages(self, email_messages):
        if self.fail_with is not None:
            raise self.fail_with
        self.__class__.outbox.extend(email_messages)
        return len(email_messages)


@override_settings(
    EMAIL_BACKEND='django_otp.plugins.otp_email.tests.ControllableEmailBackend',
    OTP_EMAIL_COOLDOWN_DURATION=10,
    OTP_EMAIL_THROTTLE_FACTOR=0,
)
class FailedDeliveryTestCase(EmailDeviceMixin, TestCase):
    def setUp(self):
        super().setUp()
        ControllableEmailBackend.reset()

    def test_failed_first_generation_leaves_no_trace(self):
        """
        If delivery fails on the first challenge, nothing is committed: no
        token, no cooldown, so the user may retry immediately.
        """
        ControllableEmailBackend.fail_with = SMTPException("backend down")

        with self.assertRaises(SMTPException):
            self.device.generate_challenge()

        self.device.refresh_from_db()
        self.assertIsNone(self.device.token)
        self.assertIsNone(self.device.last_generated_timestamp)
        self.assertEqual(ControllableEmailBackend.outbox, [])

        allowed, _ = self.device.generate_is_allowed()
        self.assertTrue(allowed)

    def test_retry_after_failure_succeeds_immediately(self):
        """
        A failed challenge does not impose a cooldown: an immediate retry
        delivers the token and records the generation.
        """
        ControllableEmailBackend.fail_with = SMTPException("backend down")
        with self.assertRaises(SMTPException):
            self.device.generate_challenge()

        ControllableEmailBackend.fail_with = None
        message = self.device.generate_challenge()

        self.assertEqual(message, "sent by email")
        self.assertEqual(len(ControllableEmailBackend.outbox), 1)
        self.device.refresh_from_db()
        self.assertIsNotNone(self.device.token)
        self.assertIsNotNone(self.device.last_generated_timestamp)

    def test_failed_regeneration_preserves_valid_token(self):
        """
        If a retry fails while a valid token exists, the token and the
        cooldown timestamp are left untouched, and the next successful
        attempt re-sends the same token.
        """
        with freeze_time() as frozen_time:
            self.device.generate_challenge()
            self.device.refresh_from_db()
            token = self.device.token
            generated_at = self.device.last_generated_timestamp

            # Cooldown (10s) expires, token (300s) is still valid.
            frozen_time.tick(delta=timedelta(seconds=11))

            ControllableEmailBackend.fail_with = SMTPException("backend down")
            with self.assertRaises(SMTPException):
                self.device.generate_challenge()

            self.device.refresh_from_db()
            self.assertEqual(self.device.token, token)
            self.assertEqual(self.device.last_generated_timestamp, generated_at)

            ControllableEmailBackend.fail_with = None
            message = self.device.generate_challenge()

            self.assertEqual(message, "sent by email")
            self.device.refresh_from_db()
            self.assertEqual(self.device.token, token)
            self.assertEqual(len(ControllableEmailBackend.outbox), 2)

    def test_regeneration_reuses_valid_token(self):
        """
        Repeated challenges within the token validity period re-send the
        same token rather than invalidating it.
        """
        with freeze_time() as frozen_time:
            self.device.generate_challenge()
            self.device.refresh_from_db()
            token = self.device.token

            frozen_time.tick(delta=timedelta(seconds=11))

            self.device.generate_challenge()
            self.device.refresh_from_db()
            self.assertEqual(self.device.token, token)
            self.assertEqual(len(ControllableEmailBackend.outbox), 2)

    def test_regeneration_after_expiry_generates_new_token(self):
        """
        Once the token has expired, a new challenge generates a fresh token.
        """
        with freeze_time() as frozen_time:
            self.device.generate_challenge()
            self.device.refresh_from_db()
            token = self.device.token

            frozen_time.tick(delta=timedelta(seconds=301))

            self.device.generate_challenge()
            self.device.refresh_from_db()
            self.assertIsNotNone(self.device.token)
            self.assertNotEqual(self.device.token, token)


@override_settings(
    OTP_EMAIL_THROTTLE_FACTOR=1,
)
class ThrottlingTestCase(EmailDeviceMixin, ThrottlingTestMixin, TestCase):
    def valid_token(self):
        if self.device.token is None:
            self.device.generate_token()

        return self.device.token

    def invalid_token(self):
        return -1


@override_settings(
    OTP_EMAIL_COOLDOWN_DURATION=10,
)
class CooldownTestCase(EmailDeviceMixin, CooldownTestMixin, TestCase):
    def valid_token(self):
        if self.device.token is None:
            self.device.generate_token()

        return self.device.token

    def invalid_token(self):
        return -1

    def test_cooldown_imposed_message(self):
        with freeze_time():
            message = self.device.generate_challenge()
            self.device.refresh_from_db()
            message = self.device.generate_challenge()
            self.assertTrue(
                message.startswith(
                    'Token generation cooldown period has not expired yet. Next generation allowed'
                )
            )

    def test_cooldown_imposed_expiration_message(self):
        with freeze_time() as frozen_time:
            self.device.generate_challenge()
            frozen_time.tick(delta=timedelta(seconds=5))
            self.device.refresh_from_db()
            message = self.device.generate_challenge()
            self.assertIn("Next generation allowed 5\xa0seconds from now.", message)


class TimestampTestCase(EmailDeviceMixin, TimestampTestMixin, TestCase):
    def valid_token(self):
        if self.device.token is None:
            self.device.generate_token()

        return self.device.token

    def invalid_token(self):
        return -1
