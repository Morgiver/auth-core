"""
Contract tests for ICredentialRepository.

All credential repository implementations must pass these tests.
"""

import pytest
from datetime import datetime

from auth_core.domain.models import Credential, CredentialStatus
from auth_core.domain.exceptions import DuplicateCredentialError


class CredentialRepositoryContractTests:
    """Base test class that ALL credential repository implementations must pass."""

    @pytest.fixture
    def repository(self):
        """Subclasses must provide repository implementation."""
        raise NotImplementedError("Subclasses must provide repository fixture")

    @pytest.fixture
    def sample_credential(self):
        """Create a sample credential for testing."""
        now = datetime.utcnow()
        return Credential(
            user_id="user-123",
            password_hash="hashed_password",
            status=CredentialStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        )

    def test_save_and_find_by_id(self, repository, sample_credential):
        """Test saving and finding credential by ID."""
        saved = repository.save(sample_credential)
        assert saved.id is not None

        found = repository.find_by_id(saved.id)
        assert found is not None
        assert found.id == saved.id
        assert found.user_id == "user-123"

    def test_save_and_find_by_user_id(self, repository, sample_credential):
        """Test finding credential by user ID."""
        saved = repository.save(sample_credential)

        found = repository.find_by_user_id("user-123")
        assert found is not None
        assert found.id == saved.id
        assert found.user_id == "user-123"

    def test_find_nonexistent_by_id_returns_none(self, repository):
        """Test that finding nonexistent credential by ID returns None."""
        found = repository.find_by_id("nonexistent-id")
        assert found is None

    def test_find_nonexistent_by_user_id_returns_none(self, repository):
        """Test that finding nonexistent credential by user_id returns None."""
        found = repository.find_by_user_id("nonexistent-user")
        assert found is None

    def test_save_duplicate_user_id_raises_error(self, repository, sample_credential):
        """Test that saving duplicate user_id raises error."""
        repository.save(sample_credential)

        # Try to save another credential with same user_id
        now = datetime.utcnow()
        duplicate = Credential(
            user_id="user-123",  # Same user
            password_hash="different_hash",
            status=CredentialStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        )

        with pytest.raises(DuplicateCredentialError):
            repository.save(duplicate)

    def test_update_existing_credential(self, repository, sample_credential):
        """Test updating an existing credential."""
        saved = repository.save(sample_credential)

        # Update it
        saved.status = CredentialStatus.LOCKED
        saved.metadata["lock_reason"] = "Test lock"
        updated = repository.save(saved)

        # Verify update
        found = repository.find_by_id(saved.id)
        assert found.status == CredentialStatus.LOCKED
        assert found.metadata["lock_reason"] == "Test lock"

    def test_delete_credential(self, repository, sample_credential):
        """Test deleting a credential."""
        saved = repository.save(sample_credential)

        repository.delete(saved.id)

        # Verify deleted
        found = repository.find_by_id(saved.id)
        assert found is None

    def test_delete_by_user_id(self, repository, sample_credential):
        """Test deleting credential by user ID."""
        saved = repository.save(sample_credential)

        repository.delete_by_user_id("user-123")

        # Verify deleted
        found = repository.find_by_user_id("user-123")
        assert found is None

    def test_delete_nonexistent_credential_does_not_error(self, repository):
        """Test that deleting nonexistent credential doesn't error."""
        repository.delete("nonexistent-id")  # Should not raise


# ===== Concrete Test Classes =====

class TestInMemoryCredentialRepository(CredentialRepositoryContractTests):
    """Test InMemoryCredentialRepository against contract."""

    @pytest.fixture
    def repository(self, credential_repo):
        """Use the credential_repo fixture from conftest."""
        return credential_repo


class TestSQLAlchemyCredentialRepository(CredentialRepositoryContractTests):
    """Test SQLAlchemyCredentialRepository against contract."""

    @pytest.fixture
    def repository(self, db_session):
        """Create SQLAlchemy repository with test database."""
        from auth_core.adapters.repositories.sqlalchemy import SQLAlchemyCredentialRepository
        return SQLAlchemyCredentialRepository(db_session)


class TestMongoDBCredentialRepository(CredentialRepositoryContractTests):
    """Test MongoDBCredentialRepository against contract."""

    @pytest.fixture
    def repository(self, mongo_db):
        """Create MongoDB repository with test database."""
        from auth_core.adapters.repositories.mongodb import MongoDBCredentialRepository
        return MongoDBCredentialRepository(mongo_db)
