from textwrap import fill

from django.core.management.base import BaseCommand

from django_otp.plugins.otp_static.models import StaticToken


class Command(BaseCommand):
    help = fill(
        'Converts legacy static tokens stored as plaintext to digest-only '
        'storage. Already-migrated rows are skipped, so this command is safe '
        'to re-run and to run while the service is serving traffic.',
        width=78,
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--limit',
            type=int,
            default=None,
            help='Maximum number of legacy rows to convert in this run.',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Only report the number of rows that would be converted.',
        )

    def handle(self, *args, **options):
        limit = options['limit']
        dry_run = options['dry_run']

        legacy_rows = StaticToken.objects.filter(digest='').exclude(token='')
        remaining = legacy_rows.count()
        pending = remaining if limit is None else min(remaining, limit)

        if dry_run:
            status = 'dry-run'
            converted = 0
        else:
            status = 'completed'
            converted = 0
            for row in legacy_rows[:limit] if limit is not None else legacy_rows:
                # Model.save() hashes the plaintext and clears it; saving
                # these fields alone leaves every other column untouched.
                row.save(update_fields=['token', 'digest'])
                converted += 1

        self.stdout.write(
            'status: {status}\n'
            'legacy_rows_remaining: {remaining}\n'
            'rows_converted: {converted}\n'
            'rows_pending: {pending}'.format(
                status=status,
                remaining=remaining,
                converted=converted,
                pending=pending,
            )
        )
