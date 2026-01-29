"""
TOTP MFA provider adapter.

Implements Time-based One-Time Password (RFC 6238) for MFA.
Compatible with Google Authenticator, Authy, and other TOTP apps.
"""

import hashlib
import logging
from typing import List

try:
    import pyotp

    PYOTP_AVAILABLE = True
except ImportError:
    PYOTP_AVAILABLE = False

from auth_core.interfaces.hasher import IPasswordHasher
from auth_core.interfaces.mfa_provider import IMFAProvider
from auth_core.utils.generators import generate_alphanumeric_code

logger = logging.getLogger(__name__)


class TOTPProvider(IMFAProvider):
    """
    TOTP MFA provider implementation.

    Requires: pip install pyotp
    """

    def __init__(self, password_hasher: IPasswordHasher, issuer: str = "AuthCore"):
        if not PYOTP_AVAILABLE:
            raise ImportError("pyotp is not installed. Install it with: pip install pyotp")

        self.password_hasher = password_hasher
        self.issuer = issuer

    def generate_secret(self) -> str:
        """
        Generate a new TOTP secret.

        Returns:
            The generated secret (base32-encoded)
        """
        secret = pyotp.random_base32()
        logger.debug("Generated new TOTP secret")
        return secret

    def generate_qr_uri(self, secret: str, account_name: str, issuer: str) -> str:
        """
        Generate a QR code URI for TOTP setup.

        Args:
            secret: The TOTP secret
            account_name: The account name (typically email)
            issuer: The issuer name (typically app name)

        Returns:
            The QR code URI (otpauth://totp/...)
        """
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=account_name, issuer_name=issuer)
        logger.debug(f"Generated QR URI for account: {account_name}")
        return uri

    def verify_code(self, secret: str, code: str) -> bool:
        """
        Verify a TOTP code.

        Args:
            secret: The TOTP secret
            code: The code to verify

        Returns:
            True if code is valid, False otherwise
        """
        try:
            totp = pyotp.TOTP(secret)
            # Verify with window of 1 (allows for slight time drift)
            is_valid = totp.verify(code, valid_window=1)
            logger.debug(f"TOTP code verification: {is_valid}")
            return is_valid
        except Exception as e:
            logger.warning(f"TOTP verification failed: {str(e)}")
            return False

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """
        Generate backup codes.

        Args:
            count: Number of backup codes to generate

        Returns:
            List of backup codes
        """
        codes = [generate_alphanumeric_code(length=8) for _ in range(count)]
        logger.debug(f"Generated {count} backup codes")
        return codes

    def hash_backup_code(self, code: str) -> str:
        """
        Hash a backup code for storage.

        Args:
            code: The backup code to hash

        Returns:
            The hashed backup code
        """
        return self.password_hasher.hash(code)

    def verify_backup_code(self, code: str, hashed: str) -> bool:
        """
        Verify a backup code against a hash.

        Args:
            code: The backup code
            hashed: The hashed backup code

        Returns:
            True if code matches hash, False otherwise
        """
        return self.password_hasher.verify(code, hashed)
