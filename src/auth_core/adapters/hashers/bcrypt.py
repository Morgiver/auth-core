"""
Bcrypt password hasher adapter.

Well-established hasher, good for compatibility and migration.
"""

import logging

try:
    import bcrypt

    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

from auth_core.interfaces.hasher import IPasswordHasher

logger = logging.getLogger(__name__)


class BcryptHasher(IPasswordHasher):
    """
    Bcrypt password hasher implementation.

    Requires: pip install bcrypt
    """

    def __init__(self, rounds: int = 12):
        if not BCRYPT_AVAILABLE:
            raise ImportError("bcrypt is not installed. Install it with: pip install bcrypt")

        self.rounds = rounds

    def hash(self, password: str) -> str:
        """
        Hash a password using bcrypt.

        Args:
            password: The plain text password

        Returns:
            The hashed password
        """
        password_bytes = password.encode("utf-8")
        salt = bcrypt.gensalt(rounds=self.rounds)
        hashed = bcrypt.hashpw(password_bytes, salt)
        logger.debug("Password hashed with bcrypt")
        return hashed.decode("utf-8")

    def verify(self, password: str, hashed: str) -> bool:
        """
        Verify a password against a bcrypt hash.

        Args:
            password: The plain text password
            hashed: The hashed password

        Returns:
            True if password matches hash, False otherwise
        """
        try:
            password_bytes = password.encode("utf-8")
            hashed_bytes = hashed.encode("utf-8")
            return bcrypt.checkpw(password_bytes, hashed_bytes)
        except Exception:
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
            hashed_bytes = hashed.encode("utf-8")
            # Extract rounds from hash
            current_rounds = bcrypt.gensalt(rounds=self.rounds).decode("utf-8").split("$")[2]
            hash_rounds = hashed.split("$")[2]
            return current_rounds != hash_rounds
        except Exception:
            return True
