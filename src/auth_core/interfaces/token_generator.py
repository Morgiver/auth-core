"""
Token generator interface for auth-core package.

Defines the contract for generating and verifying tokens (JWT, Fernet, etc.).
"""

from abc import ABC, abstractmethod
from datetime import timedelta
from typing import Any, Dict, Optional


class ITokenGenerator(ABC):
    """Abstract interface for token generation and verification."""

    @abstractmethod
    def generate(
        self, subject: str, expires_in: Optional[timedelta] = None, **claims: Any
    ) -> str:
        """
        Generate a token.

        Args:
            subject: The subject of the token (typically user_id)
            expires_in: Optional expiration duration
            **claims: Additional claims to include in the token

        Returns:
            The generated token string
        """
        pass

    @abstractmethod
    def verify(self, token: str) -> Dict[str, Any]:
        """
        Verify and decode a token.

        Args:
            token: The token to verify

        Returns:
            The decoded claims/payload

        Raises:
            InvalidTokenError: If token is invalid or malformed
            ExpiredTokenError: If token has expired
        """
        pass

    @abstractmethod
    def decode_without_verification(self, token: str) -> Dict[str, Any]:
        """
        Decode a token without verifying its signature.

        Useful for extracting claims from expired tokens.

        Args:
            token: The token to decode

        Returns:
            The decoded claims/payload

        Raises:
            InvalidTokenError: If token is malformed
        """
        pass
