"""
E2E tests for complete authentication flows.

These tests verify entire user journeys from start to finish.
"""

import pytest
from datetime import timedelta

from auth_core.domain.exceptions import (
    InvalidCredentialsError,
    CredentialLockedError,
)


class TestCompleteAuthenticationFlow:
    """Test complete authentication flow from registration to login."""

    def test_register_and_login_flow(self, auth_service):
        """Test complete flow: register -> login."""
        # 1. Register user
        credential = auth_service.register(
            user_id="user-123",
            password="SecurePassword123",
        )

        assert credential.user_id == "user-123"

        # 2. Login with correct credentials
        authenticated = auth_service.authenticate(
            user_id="user-123",
            password="SecurePassword123",
        )

        assert authenticated.user_id == "user-123"
        assert authenticated.last_successful_login is not None

    def test_register_login_and_change_password_flow(self, auth_service):
        """Test flow: register -> login -> change password -> login with new password."""
        # 1. Register
        auth_service.register(
            user_id="user-123",
            password="OldPassword123",
        )

        # 2. Login
        auth_service.authenticate(
            user_id="user-123",
            password="OldPassword123",
        )

        # 3. Change password
        auth_service.change_password(
            user_id="user-123",
            old_password="OldPassword123",
            new_password="NewPassword456",
        )

        # 4. Old password should not work
        with pytest.raises(InvalidCredentialsError):
            auth_service.authenticate(
                user_id="user-123",
                password="OldPassword123",
            )

        # 5. New password should work
        authenticated = auth_service.authenticate(
            user_id="user-123",
            password="NewPassword456",
        )
        assert authenticated.user_id == "user-123"

    def test_failed_login_attempts_and_account_lock_flow(self, auth_service):
        """Test flow: register -> multiple failed logins -> account locked."""
        # 1. Register
        auth_service.register(
            user_id="user-123",
            password="SecurePassword123",
        )

        # 2. Attempt 5 failed logins
        for _ in range(5):
            with pytest.raises(InvalidCredentialsError):
                auth_service.authenticate(
                    user_id="user-123",
                    password="WrongPassword",
                )

        # 3. Account should be locked
        with pytest.raises(CredentialLockedError):
            auth_service.authenticate(
                user_id="user-123",
                password="SecurePassword123",  # Even correct password
            )

        # 4. Unlock account
        auth_service.unlock_credentials("user-123")

        # 5. Should be able to login again
        authenticated = auth_service.authenticate(
            user_id="user-123",
            password="SecurePassword123",
        )
        assert authenticated.user_id == "user-123"


class TestTokenLifecycleFlow:
    """Test complete token lifecycle."""

    def test_create_verify_and_revoke_token_flow(self, token_service):
        """Test flow: create -> verify -> revoke -> verify fails."""
        # 1. Create access token
        token = token_service.create_access_token(
            user_id="user-123",
            scope="api:read",
        )

        assert token.id is not None
        assert token.token_value is not None

        # 2. Verify token works
        verified = token_service.verify_token(token.token_value)
        assert verified.user_id == "user-123"

        # 3. Revoke token
        token_service.revoke_token(token.id)

        # 4. Verification should fail
        from auth_core.domain.exceptions import RevokedTokenError
        with pytest.raises(RevokedTokenError):
            token_service.verify_token(token.token_value)

    def test_token_refresh_flow(self, token_service):
        """Test flow: create refresh token -> use it to get new access token."""
        # 1. Create refresh token
        refresh_token = token_service.create_refresh_token(
            user_id="user-123"
        )

        # 2. Verify refresh token
        verified_refresh = token_service.verify_token(refresh_token.token_value)
        assert verified_refresh.user_id == "user-123"

        # 3. Use refresh token to get new access token
        new_access_token = token_service.refresh_access_token(
            refresh_token.token_value
        )

        assert new_access_token.user_id == "user-123"
        assert new_access_token.id != refresh_token.id

        # 4. Verify new access token works
        verified_access = token_service.verify_token(new_access_token.token_value)
        assert verified_access.user_id == "user-123"


class TestSessionLifecycleFlow:
    """Test complete session lifecycle."""

    def test_create_use_and_expire_session_flow(self, session_service):
        """Test flow: create session -> use it -> let it expire."""
        import time
        # 1. Create session
        session = session_service.create_session(
            user_id="user-123",
            ip_address="192.168.1.1",
        )

        assert session.id is not None

        # 2. Retrieve session
        retrieved = session_service.get_session(session.id)
        assert retrieved.user_id == "user-123"

        # 3. Refresh session
        time.sleep(0.01)  # Ensure time difference
        refreshed = session_service.refresh_session(session.id)
        assert refreshed.last_activity_at >= session.last_activity_at

        # 4. Delete session
        session_service.delete_session(session.id)

        # 5. Session should no longer exist
        from auth_core.domain.exceptions import InvalidSessionError
        with pytest.raises(InvalidSessionError):
            session_service.get_session(session.id)

    def test_multiple_sessions_per_user_flow(self, session_service):
        """Test flow: user has multiple sessions -> logout from all."""
        # 1. Create multiple sessions for same user
        session1 = session_service.create_session(
            user_id="user-123",
            ip_address="192.168.1.1",
            user_agent="Desktop",
        )

        session2 = session_service.create_session(
            user_id="user-123",
            ip_address="10.0.0.5",
            user_agent="Mobile",
        )

        # 2. Both sessions work
        assert session_service.get_session(session1.id) is not None
        assert session_service.get_session(session2.id) is not None

        # 3. Delete all sessions for user
        session_service.delete_all_sessions("user-123")

        # 4. Neither session should exist
        from auth_core.domain.exceptions import InvalidSessionError
        with pytest.raises(InvalidSessionError):
            session_service.get_session(session1.id)

        with pytest.raises(InvalidSessionError):
            session_service.get_session(session2.id)


class TestPasswordResetFlow:
    """Test complete password reset flow."""

    def test_request_and_use_password_reset_flow(self, auth_service, password_reset_service):
        """Test flow: register -> request reset -> reset password -> login with new password."""
        # 1. Register user
        auth_service.register(
            user_id="user-123",
            password="OldPassword123",
        )

        # 2. Request password reset
        reset_request = password_reset_service.request_password_reset(
            user_id="user-123",
            ip_address="192.168.1.1",
        )

        assert reset_request.token is not None

        # 3. Reset password using token
        password_reset_service.reset_password(
            token=reset_request.token,
            new_password="NewPassword456",
        )

        # 4. Old password should not work
        with pytest.raises(InvalidCredentialsError):
            auth_service.authenticate(
                user_id="user-123",
                password="OldPassword123",
            )

        # 5. New password should work
        authenticated = auth_service.authenticate(
            user_id="user-123",
            password="NewPassword456",
        )
        assert authenticated.user_id == "user-123"

    def test_password_reset_token_one_time_use_flow(self, auth_service, password_reset_service):
        """Test that password reset token can only be used once."""
        # 1. Register and request reset
        auth_service.register(
            user_id="user-123",
            password="OldPassword123",
        )

        reset_request = password_reset_service.request_password_reset(
            user_id="user-123"
        )

        # 2. Use token once
        password_reset_service.reset_password(
            token=reset_request.token,
            new_password="NewPassword456",
        )

        # 3. Try to use same token again
        from auth_core.domain.exceptions import PasswordResetTokenAlreadyUsedError
        with pytest.raises(PasswordResetTokenAlreadyUsedError):
            password_reset_service.reset_password(
                token=reset_request.token,
                new_password="AnotherPassword789",
            )
