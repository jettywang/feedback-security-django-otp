from base64 import b32encode
from hashlib import sha256
from os import urandom

from django.conf import settings
from django.db import models

from django_otp.models import Device, ThrottlingMixin, TimestampMixin


def hash_token(token):
    """
    Returns the SHA-256 digest used to store a static token.

    Tokens are short, high-entropy strings, so an unsalted digest is
    sufficient: it keeps verification an indexed lookup while ensuring the
    database never stores a usable code.

    :rtype: str
    """
    return sha256(token.encode('utf-8')).hexdigest()


class StaticDevice(TimestampMixin, ThrottlingMixin, Device):
    """
    A static :class:`~django_otp.models.Device` simply consists of random
    tokens shared by the database and the user.

    These are frequently used as emergency tokens in case a user's normal
    device is lost or unavailable. They can be consumed in any order; each
    token will be removed from the database as soon as it is used.

    This model has no fields of its own, but serves as a container for
    :class:`StaticToken` objects.

    .. attribute:: token_set

        The RelatedManager for our tokens.

    """

    def get_throttle_factor(self):
        return getattr(settings, 'OTP_STATIC_THROTTLE_FACTOR', 1)

    def verify_token(self, token):
        verify_allowed, _ = self.verify_is_allowed()
        if verify_allowed:
            match = self.token_set.filter(digest=hash_token(token)).first()
            if match is None:
                # Rows written by older versions still hold the plaintext in
                # ``token``. Keep accepting them until they are consumed or
                # migrated offline; never match the empty value of new rows.
                if token:
                    match = self.token_set.filter(token=token).first()
            if match is not None:
                match.delete()
                self.throttle_reset(commit=False)
                self.set_last_used_timestamp(commit=False)
                self.save()
            else:
                self.throttle_increment()
        else:
            match = None

        return match is not None


class StaticToken(models.Model):
    """
    A single token belonging to a :class:`StaticDevice`.

    New rows store only a digest of the token in :attr:`digest`; the
    :attr:`token` field is kept solely to hold plaintext written by older
    versions while those rows are consumed or migrated.

    .. attribute:: device

        *ForeignKey*: A foreign key to :class:`StaticDevice`.

    .. attribute:: token

        *CharField*: The plaintext token for legacy rows. Empty for any row
        written by this version, which stores :attr:`digest` instead.

    .. attribute:: digest

        *CharField*: The SHA-256 digest of the token. Empty only for legacy
        rows that have not been migrated yet.
    """

    device = models.ForeignKey(
        StaticDevice, related_name='token_set', on_delete=models.CASCADE
    )
    token = models.CharField(max_length=16, blank=True, db_index=True)
    digest = models.CharField(max_length=64, blank=True, db_index=True)

    @staticmethod
    def random_token():
        """
        Returns a new random string that can be used as a static token.

        :rtype: str

        """
        return b32encode(urandom(5)).decode('utf-8').lower()

    def save(self, *args, **kwargs):
        if self.token:
            # A plaintext value means a new or legacy row. Persist only the
            # digest so the code itself is never at rest in the database.
            self.digest = hash_token(self.token)
            self.token = ''
        super().save(*args, **kwargs)
