"""
Domain models for auth-core package.

These models represent core business entities with NO external dependencies.
They use Python dataclasses for simplicity and immutability where appropriate.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class CredentialStatus(str, Enum):
    """Status of a credential account."""

    ACTIVE = "active"
    LOCKED = "locked"
    EXPIRED = "expired"
    DISABLED = "disabled"


class MFAType(str, Enum):
    """Type of MFA authentication."""

    TOTP = "totp"  # Time-based One-Time Password (Google Authenticator, Authy)
    SMS = "sms"  # SMS code
    EMAIL = "email"  # Email code


class TokenType(str, Enum):
    """Type of token."""

    ACCESS = "access"  # Short-lived access token
    REFRESH = "refresh"  # Long-lived refresh token
    RESET_PASSWORD = "reset_password"  # Password reset token
    EMAIL_VERIFICATION = "email_verification"  # Email verification token
    API_KEY = "api_key"  # Long-lived API key


class OAuthProvider(str, Enum):
    """OAuth provider."""

    GOOGLE = "google"
    GITHUB = "github"
    MICROSOFT = "microsoft"
    FACEBOOK = "facebook"
    APPLE = "apple"


@dataclass
class Credential:
    """
    Credential entity representing user authentication credentials.

    This is the core entity for password-based authentication.
    Links to users-core via user_id. Email is managed by users-core.
    """

    user_id: str  # Link to users-core package (PRIMARY KEY)
    password_hash: str  # Hashed password (Argon2id by default)
    status: CredentialStatus
    created_at: datetime
    updated_at: datetime
    id: Optional[str] = None  # Repository will set this
    mfa_enabled: bool = False
    mfa_type: Optional[MFAType] = None
    mfa_secret: Optional[str] = None  # Encrypted TOTP secret
    backup_codes: List[str] = field(default_factory=list)  # Hashed backup codes
    failed_login_attempts: int = 0
    last_failed_login: Optional[datetime] = None
    last_successful_login: Optional[datetime] = None
    password_changed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_active(self) -> bool:
        """Check if credential is active."""
        return self.status == CredentialStatus.ACTIVE

    def is_locked(self) -> bool:
        """Check if credential is locked."""
        return self.status == CredentialStatus.LOCKED

    def lock(self, reason: str) -> None:
        """Lock the credential."""
        self.status = CredentialStatus.LOCKED
        self.metadata["lock_reason"] = reason
        self.updated_at = datetime.utcnow()

    def unlock(self) -> None:
        """Unlock the credential."""
        self.status = CredentialStatus.ACTIVE
        self.failed_login_attempts = 0
        self.metadata.pop("lock_reason", None)
        self.updated_at = datetime.utcnow()

    def record_failed_login(self) -> None:
        """Record a failed login attempt."""
        self.failed_login_attempts += 1
        self.last_failed_login = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def record_successful_login(self) -> None:
        """Record a successful login."""
        self.failed_login_attempts = 0
        self.last_successful_login = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def enable_mfa(self, mfa_type: MFAType, secret: str, backup_codes: List[str]) -> None:
        """Enable MFA."""
        self.mfa_enabled = True
        self.mfa_type = mfa_type
        self.mfa_secret = secret
        self.backup_codes = backup_codes
        self.updated_at = datetime.utcnow()

    def disable_mfa(self) -> None:
        """Disable MFA."""
        self.mfa_enabled = False
        self.mfa_type = None
        self.mfa_secret = None
        self.backup_codes = []
        self.updated_at = datetime.utcnow()


@dataclass
class Session:
    """
    Session entity representing an active user session.

    Can be stored in cookies (stateless) or server-side (stateful).
    """

    user_id: str
    created_at: datetime
    expires_at: datetime
    last_activity_at: datetime
    id: Optional[str] = None  # UUID
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.utcnow() > self.expires_at

    def refresh(self, new_expiry: datetime) -> None:
        """Refresh session expiry and update last activity."""
        self.last_activity_at = datetime.utcnow()
        self.expires_at = new_expiry


@dataclass
class Token:
    """
    Token entity representing various types of tokens.

    Supports access tokens, refresh tokens, password reset tokens, etc.
    """

    user_id: str
    token_type: TokenType
    token_value: str  # The actual token (JWT, random string, etc.)
    created_at: datetime
    id: Optional[str] = None  # UUID
    expires_at: Optional[datetime] = None  # None = never expires
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if token has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """Check if token is valid (not revoked and not expired)."""
        return not self.revoked and not self.is_expired()

    def revoke(self) -> None:
        """Revoke the token."""
        self.revoked = True
        self.revoked_at = datetime.utcnow()


@dataclass
class OAuthAccount:
    """
    OAuth account entity representing a linked social account.

    Links a user to their OAuth provider account.
    """

    user_id: str
    provider: OAuthProvider
    provider_user_id: str  # User ID from the OAuth provider
    created_at: datetime
    updated_at: datetime
    id: Optional[str] = None
    provider_email: Optional[str] = None
    provider_username: Optional[str] = None
    access_token: Optional[str] = None  # Encrypted
    refresh_token: Optional[str] = None  # Encrypted
    token_expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_token_expired(self) -> bool:
        """Check if OAuth token has expired."""
        if self.token_expires_at is None:
            return False
        return datetime.utcnow() > self.token_expires_at


@dataclass
class PasswordResetRequest:
    """
    Password reset request entity.

    Represents a one-time password reset request.
    Email is managed by users-core.
    """

    user_id: str  # Link to users-core
    token: str  # Random secure token
    created_at: datetime
    expires_at: datetime  # Typically expires after 1 hour
    id: Optional[str] = None
    used: bool = False
    used_at: Optional[datetime] = None
    ip_address: Optional[str] = None

    def is_expired(self) -> bool:
        """Check if reset request has expired."""
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """Check if reset request is valid (not used and not expired)."""
        return not self.used and not self.is_expired()

    def mark_as_used(self) -> None:
        """Mark the reset request as used."""
        self.used = True
        self.used_at = datetime.utcnow()
