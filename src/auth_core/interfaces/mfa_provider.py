"""
MFA provider interface for auth-core package.

Defines the contract for MFA implementations (TOTP, SMS, Email).
"""

from abc import ABC, abstractmethod
from typing import List, Tuple


class IMFAProvider(ABC):
    """Abstract interface for MFA providers."""

    @abstractmethod
    def generate_secret(self) -> str:
        """
        Generate a new MFA secret.

        Returns:
            The generated secret
        """
        pass

    @abstractmethod
    def generate_qr_uri(self, secret: str, account_name: str, issuer: str) -> str:
        """
        Generate a QR code URI for MFA setup.

        Args:
            secret: The MFA secret
            account_name: The account name (typically email)
            issuer: The issuer name (typically app name)

        Returns:
            The QR code URI (otpauth://...)
        """
        pass

    @abstractmethod
    def verify_code(self, secret: str, code: str) -> bool:
        """
        Verify an MFA code.

        Args:
            secret: The MFA secret
            code: The code to verify

        Returns:
            True if code is valid, False otherwise
        """
        pass

    @abstractmethod
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """
        Generate backup codes.

        Args:
            count: Number of backup codes to generate

        Returns:
            List of backup codes
        """
        pass

    @abstractmethod
    def hash_backup_code(self, code: str) -> str:
        """
        Hash a backup code for storage.

        Args:
            code: The backup code to hash

        Returns:
            The hashed backup code
        """
        pass

    @abstractmethod
    def verify_backup_code(self, code: str, hashed: str) -> bool:
        """
        Verify a backup code against a hash.

        Args:
            code: The backup code
            hashed: The hashed backup code

        Returns:
            True if code matches hash, False otherwise
        """
        pass
