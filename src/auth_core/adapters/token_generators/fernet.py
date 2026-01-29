"""
Fernet token generator adapter.

Generates encrypted tokens using Fernet symmetric encryption.
Good for refresh tokens stored in database.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

try:
    from cryptography.fernet import Fernet, InvalidToken

    FERNET_AVAILABLE = True
except ImportError:
    FERNET_AVAILABLE = False

from auth_core.domain.exceptions import ExpiredTokenError, InvalidTokenError
from auth_core.interfaces.token_generator import ITokenGenerator

logger = logging.getLogger(__name__)


class FernetGenerator(ITokenGenerator):
    """
    Fernet token generator implementation.

    Requires: pip install cryptography
    """

    def __init__(self, key: bytes):
        if not FERNET_AVAILABLE:
            raise ImportError(
                "cryptography is not installed. Install it with: pip install cryptography"
            )

        self.fernet = Fernet(key)

    @classmethod
    def generate_key(cls) -> bytes:
        """Generate a new Fernet key."""
        return Fernet.generate_key()

    def generate(
        self, subject: str, expires_in: Optional[timedelta] = None, **claims: Any
    ) -> str:
        """
        Generate a Fernet-encrypted token.

        Args:
            subject: The subject of the token (typically user_id)
            expires_in: Optional expiration duration
            **claims: Additional claims to include in the token

        Returns:
            The generated encrypted token string
        """
        now = datetime.utcnow()

        payload: Dict[str, Any] = {
            "sub": subject,
            "iat": now.isoformat(),
            **claims,
        }

        if expires_in:
            exp = now + expires_in
            payload["exp"] = exp.isoformat()

        # Serialize payload to JSON and encrypt
        payload_json = json.dumps(payload)
        payload_bytes = payload_json.encode("utf-8")
        token = self.fernet.encrypt(payload_bytes)

        logger.debug(f"Generated Fernet token for subject: {subject}")
        return token.decode("utf-8")

    def verify(self, token: str) -> Dict[str, Any]:
        """
        Verify and decode a Fernet token.

        Args:
            token: The token to verify

        Returns:
            The decoded claims/payload

        Raises:
            InvalidTokenError: If token is invalid or malformed
            ExpiredTokenError: If token has expired
        """
        try:
            token_bytes = token.encode("utf-8")
            decrypted = self.fernet.decrypt(token_bytes)
            payload_json = decrypted.decode("utf-8")
            payload = json.loads(payload_json)

            # Check expiration
            if "exp" in payload:
                exp = datetime.fromisoformat(payload["exp"])
                if datetime.utcnow() > exp:
                    logger.warning("Fernet token has expired")
                    raise ExpiredTokenError("Token has expired")

            logger.debug(f"Verified Fernet token for subject: {payload.get('sub')}")
            return payload

        except InvalidToken:
            logger.warning("Invalid Fernet token")
            raise InvalidTokenError("Invalid token")

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Malformed Fernet token: {str(e)}")
            raise InvalidTokenError(f"Malformed token: {str(e)}")

    def decode_without_verification(self, token: str) -> Dict[str, Any]:
        """
        Decode a Fernet token without verifying expiration.

        Args:
            token: The token to decode

        Returns:
            The decoded claims/payload

        Raises:
            InvalidTokenError: If token is malformed
        """
        try:
            token_bytes = token.encode("utf-8")
            decrypted = self.fernet.decrypt(token_bytes)
            payload_json = decrypted.decode("utf-8")
            payload = json.loads(payload_json)
            return payload

        except (InvalidToken, json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to decode Fernet token: {str(e)}")
            raise InvalidTokenError(f"Invalid token: {str(e)}")
