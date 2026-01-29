"""
JWT token generator adapter.

Generates and verifies JSON Web Tokens (JWT) for access tokens.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

try:
    import jwt

    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

from auth_core.domain.exceptions import ExpiredTokenError, InvalidTokenError
from auth_core.interfaces.token_generator import ITokenGenerator

logger = logging.getLogger(__name__)


class JWTGenerator(ITokenGenerator):
    """
    JWT token generator implementation.

    Requires: pip install pyjwt
    """

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
    ):
        if not JWT_AVAILABLE:
            raise ImportError("pyjwt is not installed. Install it with: pip install pyjwt")

        self.secret_key = secret_key
        self.algorithm = algorithm
        self.issuer = issuer
        self.audience = audience

    def generate(
        self, subject: str, expires_in: Optional[timedelta] = None, **claims: Any
    ) -> str:
        """
        Generate a JWT token.

        Args:
            subject: The subject of the token (typically user_id)
            expires_in: Optional expiration duration
            **claims: Additional claims to include in the token

        Returns:
            The generated JWT token string
        """
        now = datetime.utcnow()

        payload: Dict[str, Any] = {
            "sub": subject,
            "iat": now,
            **claims,
        }

        if expires_in:
            payload["exp"] = now + expires_in

        if self.issuer:
            payload["iss"] = self.issuer

        if self.audience:
            payload["aud"] = self.audience

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        logger.debug(f"Generated JWT token for subject: {subject}")
        return token

    def verify(self, token: str) -> Dict[str, Any]:
        """
        Verify and decode a JWT token.

        Args:
            token: The token to verify

        Returns:
            The decoded claims/payload

        Raises:
            InvalidTokenError: If token is invalid or malformed
            ExpiredTokenError: If token has expired
        """
        try:
            options = {"require": ["sub", "iat"]}

            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=self.audience,
                options=options,
            )

            logger.debug(f"Verified JWT token for subject: {payload.get('sub')}")
            return payload

        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            raise ExpiredTokenError("Token has expired")

        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {str(e)}")
            raise InvalidTokenError(f"Invalid token: {str(e)}")

    def decode_without_verification(self, token: str) -> Dict[str, Any]:
        """
        Decode a JWT token without verifying its signature.

        Useful for extracting claims from expired tokens.

        Args:
            token: The token to decode

        Returns:
            The decoded claims/payload

        Raises:
            InvalidTokenError: If token is malformed
        """
        try:
            payload = jwt.decode(
                token, options={"verify_signature": False, "verify_exp": False}
            )
            return payload

        except jwt.InvalidTokenError as e:
            logger.warning(f"Failed to decode JWT token: {str(e)}")
            raise InvalidTokenError(f"Invalid token: {str(e)}")
