from textwrap import fill

from django.core.management.base import BaseCommand, CommandError
from django.utils.encoding import force_str

from django_otp.plugins.otp_static.lib import add_static_token, get_user_model
from django_otp.plugins.otp_static.models import StaticToken


class Command(BaseCommand):
    help = fill(
        'Adds a single static OTP token to the given user. '
        'The token will be added to an arbitrary static device '
        'attached to the user, creating one if necessary. Only a digest '
        'of the token is stored, so the plaintext printed here is the '
        'only chance to record it.',
        width=78,
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '-t',
            '--token',
            dest='token',
            help='The token to add. If omitted, one will be randomly generated.',
        )
        parser.add_argument(
            'username', help='The user to which the token will be assigned.'
        )

    def handle(self, *args, **options):
        username = options['username']
        token = options.get('token') or StaticToken.random_token()

        try:
            add_static_token(username, token)
        except get_user_model().DoesNotExist:
            raise CommandError('User "{0}" does not exist.'.format(username))

        self.stdout.write(force_str(token))
