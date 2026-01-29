"""
Unit tests for Credential domain model.
"""

import pytest
from datetime import datetime

from auth_core.domain.models import Credential, CredentialStatus, MFAType


class TestCredentialCreation:
    """Test credential creation and initialization."""

    def test_create_credential_with_required_fields(self):
        """Test creating credential with required fields."""
        now = datetime.utcnow()
        credential = Credential(
            user_id="user-123",
            password_hash="hashed_password",
            status=CredentialStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        )

        assert credential.user_id == "user-123"
        assert credential.password_hash == "hashed_password"
        assert credential.status == CredentialStatus.ACTIVE
        assert credential.mfa_enabled is False
        assert credential.failed_login_attempts == 0

    def test_credential_defaults(self):
        """Test credential default values."""
        now = datetime.utcnow()
        credential = Credential(
            user_id="user-123",
            password_hash="hashed",
            status=CredentialStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        )

        assert credential.id is None
        assert credential.mfa_enabled is False
        assert credential.mfa_type is None
        assert credential.mfa_secret is None
        assert credential.backup_codes == []
        assert credential.failed_login_attempts == 0
        assert credential.last_failed_login is None
        assert credential.last_successful_login is None
        assert credential.metadata == {}


class TestCredentialStatus:
    """Test credential status checks."""

    def test_is_active(self, valid_credential):
        """Test checking if credential is active."""
        assert valid_credential.is_active() is True

    def test_is_locked(self, valid_credential):
        """Test checking if credential is locked."""
        assert valid_credential.is_locked() is False
        valid_credential.status = CredentialStatus.LOCKED
        assert valid_credential.is_locked() is True

    def test_lock_credential(self, valid_credential):
        """Test locking a credential."""
        reason = "Too many failed attempts"
        valid_credential.lock(reason)

        assert valid_credential.status == CredentialStatus.LOCKED
        assert valid_credential.metadata["lock_reason"] == reason
        assert valid_credential.is_locked() is True

    def test_unlock_credential(self, locked_credential):
        """Test unlocking a credential."""
        locked_credential.unlock()

        assert locked_credential.status == CredentialStatus.ACTIVE
        assert locked_credential.failed_login_attempts == 0
        assert "lock_reason" not in locked_credential.metadata
        assert locked_credential.is_active() is True


class TestCredentialLoginTracking:
    """Test login attempt tracking."""

    def test_record_failed_login(self, valid_credential):
        """Test recording failed login attempt."""
        initial_attempts = valid_credential.failed_login_attempts
        valid_credential.record_failed_login()

        assert valid_credential.failed_login_attempts == initial_attempts + 1
        assert valid_credential.last_failed_login is not None

    def test_record_multiple_failed_logins(self, valid_credential):
        """Test recording multiple failed login attempts."""
        for i in range(5):
            valid_credential.record_failed_login()

        assert valid_credential.failed_login_attempts == 5

    def test_record_successful_login(self, valid_credential):
        """Test recording successful login."""
        # First record some failed attempts
        valid_credential.record_failed_login()
        valid_credential.record_failed_login()

        # Then successful login should reset counter
        valid_credential.record_successful_login()

        assert valid_credential.failed_login_attempts == 0
        assert valid_credential.last_successful_login is not None


class TestCredentialMFA:
    """Test MFA functionality."""

    def test_enable_mfa(self, valid_credential):
        """Test enabling MFA."""
        secret = "JBSWY3DPEHPK3PXP"
        backup_codes = ["code1", "code2", "code3"]

        valid_credential.enable_mfa(MFAType.TOTP, secret, backup_codes)

        assert valid_credential.mfa_enabled is True
        assert valid_credential.mfa_type == MFAType.TOTP
        assert valid_credential.mfa_secret == secret
        assert valid_credential.backup_codes == backup_codes

    def test_disable_mfa(self, valid_credential):
        """Test disabling MFA."""
        # First enable MFA
        valid_credential.enable_mfa(
            MFAType.TOTP, "secret", ["code1", "code2"]
        )

        # Then disable it
        valid_credential.disable_mfa()

        assert valid_credential.mfa_enabled is False
        assert valid_credential.mfa_type is None
        assert valid_credential.mfa_secret is None
        assert valid_credential.backup_codes == []

    def test_mfa_disabled_by_default(self, valid_credential):
        """Test that MFA is disabled by default."""
        assert valid_credential.mfa_enabled is False
        assert valid_credential.mfa_type is None
