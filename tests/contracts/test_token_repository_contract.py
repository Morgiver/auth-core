"""
Contract tests for ITokenRepository.

All token repository implementations must pass these tests.
"""

import pytest
from datetime import datetime, timedelta

from auth_core.domain.models import Token, TokenType


class TokenRepositoryContractTests:
    """Base test class that ALL token repository implementations must pass."""

    @pytest.fixture
    def repository(self):
        """Subclasses must provide repository implementation."""
        raise NotImplementedError("Subclasses must provide repository fixture")

    @pytest.fixture
    def sample_token(self):
        """Create a sample token for testing."""
        now = datetime.utcnow()
        return Token(
            user_id="user-123",
            token_type=TokenType.ACCESS,
            token_value="test_token_value",
            created_at=now,
            expires_at=now + timedelta(minutes=15),
        )

    def test_save_and_find_by_id(self, repository, sample_token):
        """Test saving and finding token by ID."""
        saved = repository.save(sample_token)
        assert saved.id is not None

        found = repository.find_by_id(saved.id)
        assert found is not None
        assert found.id == saved.id
        assert found.user_id == "user-123"

    def test_save_and_find_by_value(self, repository, sample_token):
        """Test finding token by value."""
        saved = repository.save(sample_token)

        found = repository.find_by_value("test_token_value")
        assert found is not None
        assert found.id == saved.id
        assert found.token_value == "test_token_value"

    def test_find_by_user_id(self, repository, sample_token):
        """Test finding tokens by user ID."""
        saved = repository.save(sample_token)

        tokens = repository.find_by_user_id("user-123")
        assert len(tokens) == 1
        assert tokens[0].id == saved.id

    def test_find_by_user_id_with_type_filter(self, repository):
        """Test finding tokens by user ID filtered by type."""
        now = datetime.utcnow()

        # Save access token
        access_token = Token(
            user_id="user-123",
            token_type=TokenType.ACCESS,
            token_value="access_token",
            created_at=now,
        )
        repository.save(access_token)

        # Save refresh token
        refresh_token = Token(
            user_id="user-123",
            token_type=TokenType.REFRESH,
            token_value="refresh_token",
            created_at=now,
        )
        repository.save(refresh_token)

        # Find only access tokens
        access_tokens = repository.find_by_user_id("user-123", TokenType.ACCESS)
        assert len(access_tokens) == 1
        assert access_tokens[0].token_type == TokenType.ACCESS

    def test_find_nonexistent_by_id_returns_none(self, repository):
        """Test that finding nonexistent token by ID returns None."""
        found = repository.find_by_id("nonexistent-id")
        assert found is None

    def test_find_nonexistent_by_value_returns_none(self, repository):
        """Test that finding nonexistent token by value returns None."""
        found = repository.find_by_value("nonexistent_value")
        assert found is None

    def test_update_existing_token(self, repository, sample_token):
        """Test updating an existing token."""
        saved = repository.save(sample_token)

        # Update it
        saved.revoked = True
        saved.revoked_at = datetime.utcnow()
        updated = repository.save(saved)

        # Verify update
        found = repository.find_by_id(saved.id)
        assert found.revoked is True
        assert found.revoked_at is not None

    def test_delete_token(self, repository, sample_token):
        """Test deleting a token."""
        saved = repository.save(sample_token)

        repository.delete(saved.id)

        # Verify deleted
        found = repository.find_by_id(saved.id)
        assert found is None

    def test_delete_by_user_id(self, repository, sample_token):
        """Test deleting tokens by user ID."""
        saved = repository.save(sample_token)

        repository.delete_by_user_id("user-123")

        # Verify deleted
        tokens = repository.find_by_user_id("user-123")
        assert len(tokens) == 0

    def test_delete_by_user_id_with_type_filter(self, repository):
        """Test deleting tokens by user ID with type filter."""
        now = datetime.utcnow()

        # Save access token
        access_token = Token(
            user_id="user-123",
            token_type=TokenType.ACCESS,
            token_value="access_token",
            created_at=now,
        )
        repository.save(access_token)

        # Save refresh token
        refresh_token = Token(
            user_id="user-123",
            token_type=TokenType.REFRESH,
            token_value="refresh_token",
            created_at=now,
        )
        saved_refresh = repository.save(refresh_token)

        # Delete only access tokens
        repository.delete_by_user_id("user-123", TokenType.ACCESS)

        # Verify only access token deleted
        tokens = repository.find_by_user_id("user-123")
        assert len(tokens) == 1
        assert tokens[0].token_type == TokenType.REFRESH

    def test_delete_expired_tokens(self, repository):
        """Test deleting expired tokens."""
        now = datetime.utcnow()

        # Create valid token
        valid_token = Token(
            user_id="user-123",
            token_type=TokenType.ACCESS,
            token_value="valid_token",
            created_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        repository.save(valid_token)

        # Create expired token
        expired_token = Token(
            user_id="user-456",
            token_type=TokenType.ACCESS,
            token_value="expired_token",
            created_at=now - timedelta(minutes=20),
            expires_at=now - timedelta(minutes=5),
        )
        expired_saved = repository.save(expired_token)

        # Delete expired
        count = repository.delete_expired()

        # Verify only expired deleted
        assert count == 1
        assert repository.find_by_id(expired_saved.id) is None


# ===== Concrete Test Classes =====

class TestInMemoryTokenRepository(TokenRepositoryContractTests):
    """Test InMemoryTokenRepository against contract."""

    @pytest.fixture
    def repository(self, token_repo):
        """Use the token_repo fixture from conftest."""
        return token_repo
