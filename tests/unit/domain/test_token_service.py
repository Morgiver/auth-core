"""
Unit tests for TokenService.
"""

import pytest
from datetime import timedelta

from auth_core.domain.exceptions import (
    InvalidTokenError,
    ExpiredTokenError,
    RevokedTokenError,
)
from auth_core.domain.models import TokenType


class TestTokenServiceCreation:
    """Test token creation."""

    def test_create_access_token(self, token_service):
        """Test creating an access token."""
        token = token_service.create_access_token(
            user_id="user-123",
            scope="api:read api:write",
        )

        assert token.user_id == "user-123"
        assert token.token_type == TokenType.ACCESS
        assert token.token_value is not None
        assert token.expires_at is not None
        assert token.metadata["scope"] == "api:read api:write"

    def test_create_refresh_token(self, token_service):
        """Test creating a refresh token."""
        token = token_service.create_refresh_token(user_id="user-123")

        assert token.user_id == "user-123"
        assert token.token_type == TokenType.REFRESH
        assert token.token_value is not None
        assert token.expires_at is not None

    def test_access_token_has_short_lifetime(self, token_service):
        """Test that access token has short lifetime."""
        token = token_service.create_access_token(user_id="user-123")

        # Access token should expire in 15 minutes (default)
        lifetime = token.expires_at - token.created_at
        assert lifetime == timedelta(minutes=15)

    def test_refresh_token_has_long_lifetime(self, token_service):
        """Test that refresh token has long lifetime."""
        token = token_service.create_refresh_token(user_id="user-123")

        # Refresh token should expire in 30 days (default)
        lifetime = token.expires_at - token.created_at
        assert lifetime == timedelta(days=30)


class TestTokenServiceVerification:
    """Test token verification."""

    def test_verify_valid_token(self, token_service):
        """Test verifying a valid token."""
        # Create token
        created_token = token_service.create_access_token(user_id="user-123")

        # Verify it
        verified_token = token_service.verify_token(created_token.token_value)

        assert verified_token.user_id == "user-123"
        assert verified_token.token_type == TokenType.ACCESS

    def test_verify_invalid_token_raises_error(self, token_service):
        """Test that invalid token raises error."""
        with pytest.raises(InvalidTokenError):
            token_service.verify_token("invalid_token_value")

    def test_verify_revoked_token_raises_error(self, token_service):
        """Test that revoked token raises error."""
        # Create and revoke token
        token = token_service.create_access_token(user_id="user-123")
        token_service.revoke_token(token.id)

        # Try to verify
        with pytest.raises(RevokedTokenError):
            token_service.verify_token(token.token_value)


class TestTokenServiceRefresh:
    """Test token refresh."""

    def test_refresh_access_token(self, token_service):
        """Test refreshing an access token."""
        # Create refresh token
        refresh_token = token_service.create_refresh_token(user_id="user-123")

        # Use it to get new access token
        new_access_token = token_service.refresh_access_token(
            refresh_token.token_value
        )

        assert new_access_token.user_id == "user-123"
        assert new_access_token.token_type == TokenType.ACCESS
        assert new_access_token.id != refresh_token.id

    def test_refresh_with_access_token_raises_error(self, token_service):
        """Test that using access token for refresh raises error."""
        # Create access token
        access_token = token_service.create_access_token(user_id="user-123")

        # Try to use it for refresh
        with pytest.raises(InvalidTokenError):
            token_service.refresh_access_token(access_token.token_value)


class TestTokenServiceRevocation:
    """Test token revocation."""

    def test_revoke_token_by_id(self, token_service, token_repo):
        """Test revoking a token by ID."""
        # Create token
        token = token_service.create_access_token(user_id="user-123")

        # Revoke it
        token_service.revoke_token(token.id)

        # Verify revoked
        revoked_token = token_repo.find_by_id(token.id)
        assert revoked_token.revoked is True

    def test_revoke_all_tokens_for_user(self, token_service, token_repo):
        """Test revoking all tokens for a user."""
        # Create multiple tokens
        token1 = token_service.create_access_token(user_id="user-123")
        token2 = token_service.create_refresh_token(user_id="user-123")

        # Revoke all
        token_service.revoke_all_tokens("user-123")

        # Verify all revoked
        revoked1 = token_repo.find_by_id(token1.id)
        revoked2 = token_repo.find_by_id(token2.id)
        assert revoked1.revoked is True
        assert revoked2.revoked is True

    def test_revoke_tokens_by_type(self, token_service, token_repo):
        """Test revoking tokens filtered by type."""
        # Create access and refresh tokens
        access_token = token_service.create_access_token(user_id="user-123")
        refresh_token = token_service.create_refresh_token(user_id="user-123")

        # Revoke only access tokens
        token_service.revoke_all_tokens("user-123", TokenType.ACCESS)

        # Verify only access token revoked
        revoked_access = token_repo.find_by_id(access_token.id)
        not_revoked_refresh = token_repo.find_by_id(refresh_token.id)

        assert revoked_access.revoked is True
        assert not_revoked_refresh.revoked is False
