"""
Unit tests for AuthService.
"""

import pytest
from datetime import datetime

from auth_core.domain.exceptions import (
    InvalidCredentialsError,
    CredentialLockedError,
    CredentialNotFoundError,
    WeakPasswordError,
    PasswordMismatchError,
)
from auth_core.domain.models import CredentialStatus


class TestAuthServiceRegistration:
    """Test user registration."""

    def test_register_creates_credential(self, auth_service):
        """Test that registration creates a valid credential."""
        credential = auth_service.register(
            user_id="user-123",
            password="SecurePassword123",
        )

        assert credential.user_id == "user-123"
        assert credential.status == CredentialStatus.ACTIVE
        assert credential.password_hash is not None
        assert credential.password_hash != "SecurePassword123"

    def test_register_with_weak_password_raises_error(self, auth_service):
        """Test that weak password is rejected."""
        with pytest.raises(WeakPasswordError):
            auth_service.register(
                user_id="user-123",
                password="weak",  # Too short
            )

    def test_register_hashes_password(self, auth_service, argon2_hasher):
        """Test that password is properly hashed."""
        credential = auth_service.register(
            user_id="user-123",
            password="SecurePassword123",
        )

        # Verify the hash works
        assert argon2_hasher.verify("SecurePassword123", credential.password_hash)


class TestAuthServiceAuthentication:
    """Test user authentication."""

    def test_authenticate_with_valid_credentials(self, auth_service):
        """Test successful authentication."""
        # Register user
        auth_service.register(
            user_id="user-123",
            password="SecurePassword123",
        )

        # Authenticate
        credential = auth_service.authenticate(
            user_id="user-123",
            password="SecurePassword123",
        )

        assert credential.user_id == "user-123"
        assert credential.last_successful_login is not None
        assert credential.failed_login_attempts == 0

    def test_authenticate_with_invalid_user_id(self, auth_service):
        """Test authentication with non-existent user."""
        with pytest.raises(InvalidCredentialsError):
            auth_service.authenticate(
                user_id="nonexistent-user",
                password="password",
            )

    def test_authenticate_with_invalid_password(self, auth_service):
        """Test authentication with wrong password."""
        # Register user
        auth_service.register(
            user_id="user-123",
            password="SecurePassword123",
        )

        # Try with wrong password
        with pytest.raises(InvalidCredentialsError):
            auth_service.authenticate(
                user_id="user-123",
                password="WrongPassword",
            )

    def test_authenticate_increments_failed_attempts(self, auth_service, credential_repo):
        """Test that failed login increments counter."""
        # Register user
        auth_service.register(
            user_id="user-123",
            password="SecurePassword123",
        )

        # Try wrong password
        try:
            auth_service.authenticate(
                user_id="user-123",
                password="WrongPassword",
            )
        except InvalidCredentialsError:
            pass

        # Check failed attempts
        credential = credential_repo.find_by_user_id("user-123")
        assert credential.failed_login_attempts == 1

    def test_authenticate_locks_after_max_attempts(self, auth_service, credential_repo):
        """Test that account locks after max failed attempts."""
        # Register user
        auth_service.register(
            user_id="user-123",
            password="SecurePassword123",
        )

        # Try wrong password 5 times (max_failed_attempts)
        for _ in range(5):
            try:
                auth_service.authenticate(
                    user_id="user-123",
                    password="WrongPassword",
                )
            except InvalidCredentialsError:
                pass

        # Check that account is locked
        credential = credential_repo.find_by_user_id("user-123")
        assert credential.is_locked()

    def test_authenticate_with_locked_credential_raises_error(self, auth_service):
        """Test that locked credential cannot authenticate."""
        # Register and lock
        credential = auth_service.register(
            user_id="user-123",
            password="SecurePassword123",
        )
        auth_service.lock_credentials("user-123", "Manual lock")

        # Try to authenticate
        with pytest.raises(CredentialLockedError):
            auth_service.authenticate(
                user_id="user-123",
                password="SecurePassword123",
            )


class TestAuthServicePasswordChange:
    """Test password change functionality."""

    def test_change_password_with_valid_credentials(self, auth_service):
        """Test successful password change."""
        # Register user
        auth_service.register(
            user_id="user-123",
            password="OldPassword123",
        )

        # Change password
        auth_service.change_password(
            user_id="user-123",
            old_password="OldPassword123",
            new_password="NewPassword456",
        )

        # Verify new password works
        credential = auth_service.authenticate(
            user_id="user-123",
            password="NewPassword456",
        )
        assert credential.user_id == "user-123"

    def test_change_password_with_wrong_old_password(self, auth_service):
        """Test password change with incorrect old password."""
        # Register user
        auth_service.register(
            user_id="user-123",
            password="OldPassword123",
        )

        # Try to change with wrong old password
        with pytest.raises(PasswordMismatchError):
            auth_service.change_password(
                user_id="user-123",
                old_password="WrongOldPassword",
                new_password="NewPassword456",
            )

    def test_change_password_with_weak_new_password(self, auth_service):
        """Test that weak new password is rejected."""
        # Register user
        auth_service.register(
            user_id="user-123",
            password="OldPassword123",
        )

        # Try to change to weak password
        with pytest.raises(WeakPasswordError):
            auth_service.change_password(
                user_id="user-123",
                old_password="OldPassword123",
                new_password="weak",
            )


class TestAuthServiceCredentialLocking:
    """Test credential locking/unlocking."""

    def test_lock_credentials(self, auth_service, credential_repo):
        """Test locking credentials."""
        # Register user
        auth_service.register(
            user_id="user-123",
            password="SecurePassword123",
        )

        # Lock credentials
        auth_service.lock_credentials("user-123", "Security concern")

        # Verify locked
        credential = credential_repo.find_by_user_id("user-123")
        assert credential.is_locked()
        assert credential.metadata["lock_reason"] == "Security concern"

    def test_unlock_credentials(self, auth_service, credential_repo):
        """Test unlocking credentials."""
        # Register and lock
        auth_service.register(
            user_id="user-123",
            password="SecurePassword123",
        )
        auth_service.lock_credentials("user-123", "Test lock")

        # Unlock
        auth_service.unlock_credentials("user-123")

        # Verify unlocked
        credential = credential_repo.find_by_user_id("user-123")
        assert credential.is_active()
        assert credential.failed_login_attempts == 0

    def test_lock_nonexistent_credential_raises_error(self, auth_service):
        """Test that locking nonexistent credential raises error."""
        with pytest.raises(CredentialNotFoundError):
            auth_service.lock_credentials("nonexistent-user", "reason")

    def test_unlock_nonexistent_credential_raises_error(self, auth_service):
        """Test that unlocking nonexistent credential raises error."""
        with pytest.raises(CredentialNotFoundError):
            auth_service.unlock_credentials("nonexistent-user")
