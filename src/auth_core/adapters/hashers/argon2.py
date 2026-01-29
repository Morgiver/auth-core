"""
Argon2id password hasher adapter.

OWASP recommended hasher for 2026. Provides excellent security against
brute-force attacks with configurable memory and time costs.
"""

import logging

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerifyMismatchError

    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

from auth_core.interfaces.hasher import IPasswordHasher

logger = logging.getLogger(__name__)


class Argon2Hasher(IPasswordHasher):
    """
    Argon2id password hasher implementation.

    Requires: pip install argon2-cffi
    """

    def __init__(
        self,
        time_cost: int = 2,
        memory_cost: int = 65536,  # 64 MB
        parallelism: int = 1,
        hash_len: int = 32,
        salt_len: int = 16,
    ):
        if not ARGON2_AVAILABLE:
            raise ImportError(
                "argon2-cffi is not installed. "
                "Install it with: pip install argon2-cffi"
            )

        self.hasher = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len,
        )

    def hash(self, password: str) -> str:
        """
        Hash a password using Argon2id.

        Args:
            password: The plain text password

        Returns:
            The hashed password
        """
        hashed = self.hasher.hash(password)
        logger.debug("Password hashed with Argon2id")
        return hashed

    def verify(self, password: str, hashed: str) -> bool:
        """
        Verify a password against an Argon2id hash.

        Args:
            password: The plain text password
            hashed: The hashed password

        Returns:
            True if password matches hash, False otherwise
        """
        try:
            self.hasher.verify(hashed, password)
            return True
        except (VerifyMismatchError, InvalidHashError):
            return False

    def needs_rehash(self, hashed: str) -> bool:
        """
        Check if hash needs to be regenerated due to parameter changes.

        Args:
            hashed: The hashed password

        Returns:
            True if hash should be regenerated, False otherwise
        """
        try:
            return self.hasher.check_needs_rehash(hashed)
        except InvalidHashError:
            return True
