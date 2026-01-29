"""
Unit tests for Token domain model.
"""

import pytest
from datetime import datetime, timedelta

from auth_core.domain.models import Token, TokenType


class TestTokenCreation:
    """Test token creation and initialization."""

    def test_create_token_with_required_fields(self):
        """Test creating token with required fields."""
        now = datetime.utcnow()
        token = Token(
            user_id="user-123",
            token_type=TokenType.ACCESS,
            token_value="jwt_token_string",
            created_at=now,
        )

        assert token.user_id == "user-123"
        assert token.token_type == TokenType.ACCESS
        assert token.token_value == "jwt_token_string"
        assert token.created_at == now

    def test_token_types(self):
        """Test different token types."""
        now = datetime.utcnow()

        access_token = Token(
            user_id="user-123",
            token_type=TokenType.ACCESS,
            token_value="access",
            created_at=now,
        )
        assert access_token.token_type == TokenType.ACCESS

        refresh_token = Token(
            user_id="user-123",
            token_type=TokenType.REFRESH,
            token_value="refresh",
            created_at=now,
        )
        assert refresh_token.token_type == TokenType.REFRESH

        reset_token = Token(
            user_id="user-123",
            token_type=TokenType.RESET_PASSWORD,
            token_value="reset",
            created_at=now,
        )
        assert reset_token.token_type == TokenType.RESET_PASSWORD


class TestTokenExpiration:
    """Test token expiration logic."""

    def test_is_expired_returns_false_for_valid_token(self, valid_token):
        """Test that valid token is not expired."""
        assert valid_token.is_expired() is False

    def test_is_expired_returns_true_for_expired_token(self, expired_token):
        """Test that expired token is detected."""
        assert expired_token.is_expired() is True

    def test_token_without_expiry_never_expires(self):
        """Test that token with no expiry never expires."""
        now = datetime.utcnow()
        token = Token(
            user_id="user-123",
            token_type=TokenType.API_KEY,
            token_value="api_key",
            created_at=now,
            expires_at=None,  # No expiry
        )

        assert token.is_expired() is False


class TestTokenRevocation:
    """Test token revocation logic."""

    def test_revoke_token(self, valid_token):
        """Test revoking a token."""
        assert valid_token.revoked is False

        valid_token.revoke()

        assert valid_token.revoked is True
        assert valid_token.revoked_at is not None

    def test_is_valid_for_active_token(self, valid_token):
        """Test that active token is valid."""
        assert valid_token.is_valid() is True

    def test_is_valid_for_revoked_token(self, valid_token):
        """Test that revoked token is not valid."""
        valid_token.revoke()
        assert valid_token.is_valid() is False

    def test_is_valid_for_expired_token(self, expired_token):
        """Test that expired token is not valid."""
        assert expired_token.is_valid() is False


class TestTokenDefaults:
    """Test token default values."""

    def test_token_defaults(self):
        """Test default token values."""
        now = datetime.utcnow()
        token = Token(
            user_id="user-123",
            token_type=TokenType.ACCESS,
            token_value="value",
            created_at=now,
        )

        assert token.id is None
        assert token.expires_at is None
        assert token.revoked is False
        assert token.revoked_at is None
        assert token.metadata == {}
