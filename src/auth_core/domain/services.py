"""
Domain services for auth-core package.

These services contain pure business logic with NO external dependencies.
They orchestrate domain entities and use interfaces for external concerns.
"""

import logging
import secrets
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from auth_core.domain.exceptions import (
    CredentialDisabledError,
    CredentialExpiredError,
    CredentialLockedError,
    CredentialNotFoundError,
    ExpiredPasswordResetTokenError,
    ExpiredSessionError,
    ExpiredTokenError,
    InvalidCredentialsError,
    InvalidMFACodeError,
    InvalidPasswordResetTokenError,
    InvalidSessionError,
    InvalidTokenError,
    MFAAlreadyEnabledError,
    MFANotEnabledError,
    MFARequiredError,
    OAuthAccountAlreadyLinkedError,
    OAuthProviderError,
    PasswordMismatchError,
    PasswordResetTokenAlreadyUsedError,
    RevokedTokenError,
    SessionNotFoundError,
    WeakPasswordError,
)
from auth_core.domain.models import (
    Credential,
    CredentialStatus,
    MFAType,
    OAuthAccount,
    OAuthProvider,
    PasswordResetRequest,
    Session,
    Token,
    TokenType,
)
from auth_core.interfaces.event_bus import IEventBus
from auth_core.interfaces.hasher import IPasswordHasher
from auth_core.interfaces.mfa_provider import IMFAProvider
from auth_core.interfaces.oauth_provider import IOAuthProvider
from auth_core.interfaces.repository import (
    ICredentialRepository,
    IOAuthRepository,
    IPasswordResetRepository,
    ISessionRepository,
    ITokenRepository,
)
from auth_core.interfaces.token_generator import ITokenGenerator

logger = logging.getLogger(__name__)


class AuthService:
    """
    Core authentication service.

    Handles user registration, authentication, password management, and account locking.
    """

    def __init__(
        self,
        credential_repo: ICredentialRepository,
        password_hasher: IPasswordHasher,
        event_bus: Optional[IEventBus] = None,
        max_failed_attempts: int = 5,
        min_password_length: int = 8,
    ):
        self.credential_repo = credential_repo
        self.password_hasher = password_hasher
        self.event_bus = event_bus
        self.max_failed_attempts = max_failed_attempts
        self.min_password_length = min_password_length

    def register(self, user_id: str, password: str) -> Credential:
        """
        Register new credentials for a user.

        Note: User must already exist in users-core before calling this.

        Args:
            user_id: The user ID from users-core
            password: The plain text password

        Returns:
            The created credential

        Raises:
            WeakPasswordError: If password doesn't meet requirements
            DuplicateCredentialError: If credentials already exist for this user
        """
        self._validate_password(password)

        password_hash = self.password_hasher.hash(password)
        now = datetime.utcnow()

        credential = Credential(
            user_id=user_id,
            password_hash=password_hash,
            status=CredentialStatus.ACTIVE,
            created_at=now,
            updated_at=now,
            password_changed_at=now,
        )

        saved = self.credential_repo.save(credential)
        logger.info(f"Registered new credential for user {user_id}")

        if self.event_bus:
            from auth_core.events.events import CredentialCreatedEvent

            self.event_bus.publish(
                CredentialCreatedEvent(user_id=user_id, created_at=now)
            )

        return saved

    def authenticate(
        self, user_id: str, password: str, mfa_code: Optional[str] = None
    ) -> Credential:
        """
        Authenticate a user with user_id and password.

        Note: user_id should be obtained from users-core by querying with email first.

        Args:
            user_id: The user ID from users-core
            password: The plain text password
            mfa_code: Optional MFA code (required if MFA is enabled)

        Returns:
            The credential if authentication succeeds

        Raises:
            InvalidCredentialsError: If user_id or password is incorrect
            CredentialLockedError: If account is locked
            CredentialExpiredError: If account has expired
            CredentialDisabledError: If account is disabled
            MFARequiredError: If MFA is enabled but code not provided
            InvalidMFACodeError: If MFA code is invalid
        """
        credential = self.credential_repo.find_by_user_id(user_id)

        if not credential:
            logger.warning(f"Authentication failed: credential not found for user: {user_id}")
            raise InvalidCredentialsError("Invalid credentials")

        # Check credential status
        if credential.status == CredentialStatus.LOCKED:
            logger.warning(f"Authentication failed: account locked for user: {user_id}")
            raise CredentialLockedError("Account is locked")

        if credential.status == CredentialStatus.EXPIRED:
            logger.warning(f"Authentication failed: account expired for user: {user_id}")
            raise CredentialExpiredError("Account has expired")

        if credential.status == CredentialStatus.DISABLED:
            logger.warning(f"Authentication failed: account disabled for user: {user_id}")
            raise CredentialDisabledError("Account is disabled")

        # Verify password
        if not self.password_hasher.verify(password, credential.password_hash):
            credential.record_failed_login()
            self.credential_repo.save(credential)

            # Auto-lock after max failed attempts
            if credential.failed_login_attempts >= self.max_failed_attempts:
                credential.lock(f"Too many failed login attempts")
                self.credential_repo.save(credential)
                logger.warning(f"Account auto-locked after {self.max_failed_attempts} failed attempts for user: {user_id}")

                if self.event_bus:
                    from auth_core.events.events import CredentialLockedEvent

                    self.event_bus.publish(
                        CredentialLockedEvent(
                            user_id=credential.user_id,
                            reason=f"Too many failed login attempts",
                            locked_at=datetime.utcnow(),
                        )
                    )

            logger.warning(f"Authentication failed: invalid password for user: {user_id}")
            raise InvalidCredentialsError("Invalid credentials")

        # Check if MFA is required
        if credential.mfa_enabled:
            if not mfa_code:
                logger.info(f"MFA required for user: {user_id}")
                raise MFARequiredError("MFA code is required")

            # MFA verification will be done by MFAService
            # For now, we just indicate that MFA is required

        # Successful login
        credential.record_successful_login()

        # Check if password needs rehashing
        if self.password_hasher.needs_rehash(credential.password_hash):
            credential.password_hash = self.password_hasher.hash(password)
            logger.info(f"Rehashed password for user: {user_id}")

        self.credential_repo.save(credential)
        logger.info(f"User authenticated successfully: {user_id}")

        if self.event_bus:
            from auth_core.events.events import UserLoggedInEvent

            self.event_bus.publish(
                UserLoggedInEvent(
                    user_id=credential.user_id,
                    ip_address=None,
                    user_agent=None,
                    mfa_used=credential.mfa_enabled,
                    logged_in_at=datetime.utcnow(),
                )
            )

        return credential

    def change_password(
        self, user_id: str, old_password: str, new_password: str
    ) -> None:
        """
        Change user password.

        Args:
            user_id: The user ID
            old_password: The current password
            new_password: The new password

        Raises:
            CredentialNotFoundError: If credential not found
            PasswordMismatchError: If old password is incorrect
            WeakPasswordError: If new password doesn't meet requirements
        """
        credential = self.credential_repo.find_by_user_id(user_id)

        if not credential:
            raise CredentialNotFoundError(f"Credential not found for user {user_id}")

        # Verify old password
        if not self.password_hasher.verify(old_password, credential.password_hash):
            logger.warning(f"Password change failed: incorrect old password for user {user_id}")
            raise PasswordMismatchError("Current password is incorrect")

        # Validate new password
        self._validate_password(new_password)

        # Hash and save new password
        credential.password_hash = self.password_hasher.hash(new_password)
        credential.password_changed_at = datetime.utcnow()
        credential.updated_at = datetime.utcnow()
        self.credential_repo.save(credential)

        logger.info(f"Password changed for user {user_id}")

        if self.event_bus:
            from auth_core.events.events import PasswordChangedEvent

            self.event_bus.publish(
                PasswordChangedEvent(user_id=user_id, changed_at=datetime.utcnow())
            )

    def lock_credentials(self, user_id: str, reason: str) -> None:
        """
        Lock user credentials.

        Args:
            user_id: The user ID
            reason: The reason for locking

        Raises:
            CredentialNotFoundError: If credential not found
        """
        credential = self.credential_repo.find_by_user_id(user_id)

        if not credential:
            raise CredentialNotFoundError(f"Credential not found for user {user_id}")

        credential.lock(reason)
        self.credential_repo.save(credential)

        logger.info(f"Locked credential for user {user_id}: {reason}")

        if self.event_bus:
            from auth_core.events.events import CredentialLockedEvent

            self.event_bus.publish(
                CredentialLockedEvent(
                    user_id=user_id, reason=reason, locked_at=datetime.utcnow()
                )
            )

    def unlock_credentials(self, user_id: str) -> None:
        """
        Unlock user credentials.

        Args:
            user_id: The user ID

        Raises:
            CredentialNotFoundError: If credential not found
        """
        credential = self.credential_repo.find_by_user_id(user_id)

        if not credential:
            raise CredentialNotFoundError(f"Credential not found for user {user_id}")

        credential.unlock()
        self.credential_repo.save(credential)

        logger.info(f"Unlocked credential for user {user_id}")

        if self.event_bus:
            from auth_core.events.events import CredentialUnlockedEvent

            self.event_bus.publish(
                CredentialUnlockedEvent(user_id=user_id, unlocked_at=datetime.utcnow())
            )

    def _validate_password(self, password: str) -> None:
        """
        Validate password strength.

        Args:
            password: The password to validate

        Raises:
            WeakPasswordError: If password doesn't meet requirements
        """
        if len(password) < self.min_password_length:
            raise WeakPasswordError(
                f"Password must be at least {self.min_password_length} characters"
            )

        # Additional validation can be added here
        # (uppercase, lowercase, numbers, special chars, etc.)


class TokenService:
    """
    Token management service.

    Handles creation, verification, and revocation of various token types.
    """

    def __init__(
        self,
        token_repo: ITokenRepository,
        token_generator: ITokenGenerator,
        event_bus: Optional[IEventBus] = None,
        access_token_lifetime: timedelta = timedelta(minutes=15),
        refresh_token_lifetime: timedelta = timedelta(days=30),
    ):
        self.token_repo = token_repo
        self.token_generator = token_generator
        self.event_bus = event_bus
        self.access_token_lifetime = access_token_lifetime
        self.refresh_token_lifetime = refresh_token_lifetime

    def create_access_token(self, user_id: str, **metadata: any) -> Token:
        """
        Create an access token.

        Args:
            user_id: The user ID
            **metadata: Additional metadata to include

        Returns:
            The created token
        """
        token_value = self.token_generator.generate(
            subject=user_id, expires_in=self.access_token_lifetime, **metadata
        )

        now = datetime.utcnow()
        token = Token(
            user_id=user_id,
            token_type=TokenType.ACCESS,
            token_value=token_value,
            created_at=now,
            expires_at=now + self.access_token_lifetime,
            metadata=metadata,
        )

        saved = self.token_repo.save(token)
        logger.info(f"Created access token for user {user_id}")

        return saved

    def create_refresh_token(self, user_id: str, **metadata: any) -> Token:
        """
        Create a refresh token.

        Args:
            user_id: The user ID
            **metadata: Additional metadata to include

        Returns:
            The created token
        """
        token_value = self.token_generator.generate(
            subject=user_id, expires_in=self.refresh_token_lifetime, **metadata
        )

        now = datetime.utcnow()
        token = Token(
            user_id=user_id,
            token_type=TokenType.REFRESH,
            token_value=token_value,
            created_at=now,
            expires_at=now + self.refresh_token_lifetime,
            metadata=metadata,
        )

        saved = self.token_repo.save(token)
        logger.info(f"Created refresh token for user {user_id}")

        return saved

    def refresh_access_token(self, refresh_token_value: str) -> Token:
        """
        Refresh an access token using a refresh token.

        Args:
            refresh_token_value: The refresh token value

        Returns:
            A new access token

        Raises:
            InvalidTokenError: If token is invalid
            ExpiredTokenError: If token has expired
            RevokedTokenError: If token has been revoked
        """
        # Verify the refresh token
        refresh_token = self.verify_token(refresh_token_value)

        if refresh_token.token_type != TokenType.REFRESH:
            raise InvalidTokenError("Token is not a refresh token")

        # Create new access token
        new_access_token = self.create_access_token(
            user_id=refresh_token.user_id, **refresh_token.metadata
        )

        logger.info(f"Refreshed access token for user {refresh_token.user_id}")

        if self.event_bus:
            from auth_core.events.events import TokenRefreshedEvent

            self.event_bus.publish(
                TokenRefreshedEvent(
                    user_id=refresh_token.user_id,
                    token_id=new_access_token.id or "",
                    refreshed_at=datetime.utcnow(),
                )
            )

        return new_access_token

    def verify_token(self, token_value: str) -> Token:
        """
        Verify a token.

        Args:
            token_value: The token value

        Returns:
            The token if valid

        Raises:
            InvalidTokenError: If token is invalid
            ExpiredTokenError: If token has expired
            RevokedTokenError: If token has been revoked
        """
        # Verify with token generator
        try:
            claims = self.token_generator.verify(token_value)
        except Exception as e:
            logger.warning(f"Token verification failed: {str(e)}")
            raise InvalidTokenError(f"Invalid token: {str(e)}")

        # Find token in repository
        token = self.token_repo.find_by_value(token_value)

        if not token:
            raise InvalidTokenError("Token not found")

        if token.revoked:
            raise RevokedTokenError("Token has been revoked")

        if token.is_expired():
            raise ExpiredTokenError("Token has expired")

        return token

    def revoke_token(self, token_id: str) -> None:
        """
        Revoke a token.

        Args:
            token_id: The token ID
        """
        token = self.token_repo.find_by_id(token_id)

        if not token:
            return

        token.revoke()
        self.token_repo.save(token)

        logger.info(f"Revoked token {token_id}")

    def revoke_all_tokens(
        self, user_id: str, token_type: Optional[TokenType] = None
    ) -> None:
        """
        Revoke all tokens for a user.

        Args:
            user_id: The user ID
            token_type: Optional token type filter
        """
        tokens = self.token_repo.find_by_user_id(user_id, token_type)

        for token in tokens:
            token.revoke()
            self.token_repo.save(token)

        logger.info(f"Revoked {len(tokens)} tokens for user {user_id}")


class SessionService:
    """
    Session management service.

    Handles creation, retrieval, and cleanup of user sessions.
    """

    def __init__(
        self,
        session_repo: ISessionRepository,
        event_bus: Optional[IEventBus] = None,
        session_lifetime: timedelta = timedelta(hours=24),
    ):
        self.session_repo = session_repo
        self.event_bus = event_bus
        self.session_lifetime = session_lifetime

    def create_session(
        self, user_id: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None
    ) -> Session:
        """
        Create a new session.

        Args:
            user_id: The user ID
            ip_address: Optional IP address
            user_agent: Optional user agent

        Returns:
            The created session
        """
        now = datetime.utcnow()
        session = Session(
            user_id=user_id,
            created_at=now,
            expires_at=now + self.session_lifetime,
            last_activity_at=now,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        saved = self.session_repo.save(session)
        logger.info(f"Created session for user {user_id}")

        return saved

    def get_session(self, session_id: str) -> Session:
        """
        Get a session by ID.

        Args:
            session_id: The session ID

        Returns:
            The session

        Raises:
            InvalidSessionError: If session not found
            ExpiredSessionError: If session has expired
        """
        session = self.session_repo.find_by_id(session_id)

        if not session:
            raise InvalidSessionError("Session not found")

        if session.is_expired():
            raise ExpiredSessionError("Session has expired")

        return session

    def refresh_session(self, session_id: str) -> Session:
        """
        Refresh a session (extend expiry and update last activity).

        Args:
            session_id: The session ID

        Returns:
            The refreshed session

        Raises:
            InvalidSessionError: If session not found
            ExpiredSessionError: If session has expired
        """
        session = self.get_session(session_id)

        new_expiry = datetime.utcnow() + self.session_lifetime
        session.refresh(new_expiry)
        saved = self.session_repo.save(session)

        logger.info(f"Refreshed session {session_id}")

        return saved

    def delete_session(self, session_id: str) -> None:
        """
        Delete a session.

        Args:
            session_id: The session ID
        """
        session = self.session_repo.find_by_id(session_id)

        if session:
            self.session_repo.delete(session_id)
            logger.info(f"Deleted session {session_id}")

            if self.event_bus:
                from auth_core.events.events import UserLoggedOutEvent

                self.event_bus.publish(
                    UserLoggedOutEvent(
                        user_id=session.user_id,
                        session_id=session_id,
                        logged_out_at=datetime.utcnow(),
                    )
                )

    def delete_all_sessions(self, user_id: str) -> None:
        """
        Delete all sessions for a user.

        Args:
            user_id: The user ID
        """
        sessions = self.session_repo.find_by_user_id(user_id)
        self.session_repo.delete_by_user_id(user_id)

        logger.info(f"Deleted {len(sessions)} sessions for user {user_id}")

    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        count = self.session_repo.delete_expired()
        logger.info(f"Cleaned up {count} expired sessions")
        return count


class MFAService:
    """
    Multi-Factor Authentication service.

    Handles MFA setup, verification, and backup codes.
    """

    def __init__(
        self,
        credential_repo: ICredentialRepository,
        mfa_provider: IMFAProvider,
        event_bus: Optional[IEventBus] = None,
    ):
        self.credential_repo = credential_repo
        self.mfa_provider = mfa_provider
        self.event_bus = event_bus

    def enable_mfa(
        self, user_id: str, mfa_type: MFAType = MFAType.TOTP
    ) -> Tuple[str, str, List[str]]:
        """
        Enable MFA for a user.

        Args:
            user_id: The user ID
            mfa_type: The MFA type (default: TOTP)

        Returns:
            Tuple of (secret, qr_uri, backup_codes)

        Raises:
            CredentialNotFoundError: If credential not found
            MFAAlreadyEnabledError: If MFA is already enabled
        """
        credential = self.credential_repo.find_by_user_id(user_id)

        if not credential:
            raise CredentialNotFoundError(f"Credential not found for user {user_id}")

        if credential.mfa_enabled:
            raise MFAAlreadyEnabledError("MFA is already enabled")

        # Generate secret and backup codes
        secret = self.mfa_provider.generate_secret()
        backup_codes = self.mfa_provider.generate_backup_codes()
        hashed_backup_codes = [
            self.mfa_provider.hash_backup_code(code) for code in backup_codes
        ]

        # Generate QR code URI
        qr_uri = self.mfa_provider.generate_qr_uri(
            secret=secret, account_name=credential.email, issuer="AuthCore"
        )

        # Enable MFA (but don't activate yet - wait for verification)
        credential.enable_mfa(mfa_type, secret, hashed_backup_codes)
        self.credential_repo.save(credential)

        logger.info(f"MFA enabled for user {user_id}")

        if self.event_bus:
            from auth_core.events.events import MFAEnabledEvent

            self.event_bus.publish(
                MFAEnabledEvent(
                    user_id=user_id, mfa_type=mfa_type, enabled_at=datetime.utcnow()
                )
            )

        return secret, qr_uri, backup_codes

    def verify_mfa_setup(self, user_id: str, secret: str, code: str) -> bool:
        """
        Verify MFA setup with a code.

        Args:
            user_id: The user ID
            secret: The MFA secret
            code: The verification code

        Returns:
            True if verification succeeds

        Raises:
            InvalidMFACodeError: If code is invalid
        """
        is_valid = self.mfa_provider.verify_code(secret, code)

        if not is_valid:
            logger.warning(f"MFA setup verification failed for user {user_id}")
            raise InvalidMFACodeError("Invalid MFA code")

        logger.info(f"MFA setup verified for user {user_id}")
        return True

    def disable_mfa(self, user_id: str, password: str) -> None:
        """
        Disable MFA for a user.

        Args:
            user_id: The user ID
            password: The user's password (for confirmation)

        Raises:
            CredentialNotFoundError: If credential not found
            MFANotEnabledError: If MFA is not enabled
            PasswordMismatchError: If password is incorrect
        """
        from auth_core.interfaces.hasher import IPasswordHasher

        credential = self.credential_repo.find_by_user_id(user_id)

        if not credential:
            raise CredentialNotFoundError(f"Credential not found for user {user_id}")

        if not credential.mfa_enabled:
            raise MFANotEnabledError("MFA is not enabled")

        credential.disable_mfa()
        self.credential_repo.save(credential)

        logger.info(f"MFA disabled for user {user_id}")

        if self.event_bus:
            from auth_core.events.events import MFADisabledEvent

            self.event_bus.publish(
                MFADisabledEvent(user_id=user_id, disabled_at=datetime.utcnow())
            )

    def verify_mfa_code(self, user_id: str, code: str) -> bool:
        """
        Verify an MFA code.

        Args:
            user_id: The user ID
            code: The MFA code

        Returns:
            True if code is valid

        Raises:
            CredentialNotFoundError: If credential not found
            MFANotEnabledError: If MFA is not enabled
            InvalidMFACodeError: If code is invalid
        """
        credential = self.credential_repo.find_by_user_id(user_id)

        if not credential:
            raise CredentialNotFoundError(f"Credential not found for user {user_id}")

        if not credential.mfa_enabled or not credential.mfa_secret:
            raise MFANotEnabledError("MFA is not enabled")

        # Try TOTP code first
        if self.mfa_provider.verify_code(credential.mfa_secret, code):
            logger.info(f"MFA code verified for user {user_id}")
            return True

        # Try backup codes
        for hashed_code in credential.backup_codes:
            if self.mfa_provider.verify_backup_code(code, hashed_code):
                # Remove used backup code
                credential.backup_codes.remove(hashed_code)
                self.credential_repo.save(credential)
                logger.info(f"MFA backup code used for user {user_id}")
                return True

        logger.warning(f"Invalid MFA code for user {user_id}")
        raise InvalidMFACodeError("Invalid MFA code")

    def regenerate_backup_codes(self, user_id: str) -> List[str]:
        """
        Regenerate backup codes for a user.

        Args:
            user_id: The user ID

        Returns:
            List of new backup codes

        Raises:
            CredentialNotFoundError: If credential not found
            MFANotEnabledError: If MFA is not enabled
        """
        credential = self.credential_repo.find_by_user_id(user_id)

        if not credential:
            raise CredentialNotFoundError(f"Credential not found for user {user_id}")

        if not credential.mfa_enabled:
            raise MFANotEnabledError("MFA is not enabled")

        # Generate new backup codes
        backup_codes = self.mfa_provider.generate_backup_codes()
        hashed_backup_codes = [
            self.mfa_provider.hash_backup_code(code) for code in backup_codes
        ]

        credential.backup_codes = hashed_backup_codes
        self.credential_repo.save(credential)

        logger.info(f"Regenerated backup codes for user {user_id}")

        return backup_codes


class PasswordResetService:
    """
    Password reset service.

    Handles password reset requests and token verification.
    """

    def __init__(
        self,
        credential_repo: ICredentialRepository,
        reset_repo: IPasswordResetRepository,
        password_hasher: IPasswordHasher,
        event_bus: Optional[IEventBus] = None,
        reset_token_lifetime: timedelta = timedelta(hours=1),
    ):
        self.credential_repo = credential_repo
        self.reset_repo = reset_repo
        self.password_hasher = password_hasher
        self.event_bus = event_bus
        self.reset_token_lifetime = reset_token_lifetime

    def request_password_reset(
        self, user_id: str, ip_address: Optional[str] = None
    ) -> PasswordResetRequest:
        """
        Request a password reset.

        Args:
            user_id: The user ID (from users-core)
            ip_address: Optional IP address

        Returns:
            The password reset request

        Raises:
            CredentialNotFoundError: If credential not found
        """
        credential = self.credential_repo.find_by_user_id(user_id)

        if not credential:
            raise CredentialNotFoundError(f"Credential not found for user {user_id}")

        # Generate secure token
        token = secrets.token_urlsafe(32)

        now = datetime.utcnow()
        reset_request = PasswordResetRequest(
            user_id=user_id,
            token=token,
            created_at=now,
            expires_at=now + self.reset_token_lifetime,
            ip_address=ip_address,
        )

        saved = self.reset_repo.save(reset_request)
        logger.info(f"Password reset requested for user {user_id}")

        if self.event_bus:
            from auth_core.events.events import PasswordResetRequestedEvent

            self.event_bus.publish(
                PasswordResetRequestedEvent(user_id=user_id, requested_at=now)
            )

        return saved

    def reset_password(self, token: str, new_password: str) -> None:
        """
        Reset password using a reset token.

        Args:
            token: The reset token
            new_password: The new password

        Raises:
            InvalidPasswordResetTokenError: If token is invalid
            ExpiredPasswordResetTokenError: If token has expired
            PasswordResetTokenAlreadyUsedError: If token was already used
            WeakPasswordError: If password doesn't meet requirements
        """
        reset_request = self.reset_repo.find_by_token(token)

        if not reset_request:
            raise InvalidPasswordResetTokenError("Invalid reset token")

        if reset_request.used:
            raise PasswordResetTokenAlreadyUsedError("Reset token already used")

        if reset_request.is_expired():
            raise ExpiredPasswordResetTokenError("Reset token has expired")

        # Get credential
        credential = self.credential_repo.find_by_user_id(reset_request.user_id)

        if not credential:
            raise CredentialNotFoundError(
                f"Credential not found for user {reset_request.user_id}"
            )

        # Validate new password
        if len(new_password) < 8:
            raise WeakPasswordError("Password must be at least 8 characters")

        # Update password
        credential.password_hash = self.password_hasher.hash(new_password)
        credential.password_changed_at = datetime.utcnow()
        credential.updated_at = datetime.utcnow()
        self.credential_repo.save(credential)

        # Mark reset request as used
        reset_request.mark_as_used()
        self.reset_repo.save(reset_request)

        logger.info(f"Password reset for user {credential.user_id}")

        if self.event_bus:
            from auth_core.events.events import PasswordChangedEvent

            self.event_bus.publish(
                PasswordChangedEvent(
                    user_id=credential.user_id, changed_at=datetime.utcnow()
                )
            )
