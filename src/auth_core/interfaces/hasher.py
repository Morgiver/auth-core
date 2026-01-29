"""
Password hasher interface for auth-core package.

Defines the contract for password hashing implementations.
"""

from abc import ABC, abstractmethod


class IPasswordHasher(ABC):
    """Abstract interface for password hashing."""

    @abstractmethod
    def hash(self, password: str) -> str:
        """
        Hash a password.

        Args:
            password: The plain text password

        Returns:
            The hashed password
        """
        pass

    @abstractmethod
    def verify(self, password: str, hashed: str) -> bool:
        """
        Verify a password against a hash.

        Args:
            password: The plain text password
            hashed: The hashed password

        Returns:
            True if password matches hash, False otherwise
        """
        pass

    @abstractmethod
    def needs_rehash(self, hashed: str) -> bool:
        """
        Check if a hash needs to be rehashed (e.g., due to parameter changes).

        Args:
            hashed: The hashed password

        Returns:
            True if hash should be regenerated, False otherwise
        """
        pass
