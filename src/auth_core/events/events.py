"""
Domain events for auth-core package.

All events are immutable (frozen dataclasses) and represent facts that have occurred.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from auth_core.domain.models import MFAType, OAuthProvider


@dataclass(frozen=True)
class CredentialCreatedEvent:
    """Fired when new credentials are created."""

    user_id: str
    created_at: datetime


@dataclass(frozen=True)
class UserLoggedInEvent:
    """Fired when a user successfully logs in."""

    user_id: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    mfa_used: bool
    logged_in_at: datetime


@dataclass(frozen=True)
class UserLoggedOutEvent:
    """Fired when a user logs out."""

    user_id: str
    session_id: str
    logged_out_at: datetime


@dataclass(frozen=True)
class TokenRefreshedEvent:
    """Fired when an access token is refreshed."""

    user_id: str
    token_id: str
    refreshed_at: datetime


@dataclass(frozen=True)
class PasswordChangedEvent:
    """Fired when a password is changed."""

    user_id: str
    changed_at: datetime


@dataclass(frozen=True)
class PasswordResetRequestedEvent:
    """Fired when a password reset is requested."""

    user_id: str
    requested_at: datetime


@dataclass(frozen=True)
class MFAEnabledEvent:
    """Fired when MFA is enabled for a user."""

    user_id: str
    mfa_type: MFAType
    enabled_at: datetime


@dataclass(frozen=True)
class MFADisabledEvent:
    """Fired when MFA is disabled for a user."""

    user_id: str
    disabled_at: datetime


@dataclass(frozen=True)
class CredentialLockedEvent:
    """Fired when credentials are locked."""

    user_id: str
    reason: str
    locked_at: datetime


@dataclass(frozen=True)
class CredentialUnlockedEvent:
    """Fired when credentials are unlocked."""

    user_id: str
    unlocked_at: datetime


@dataclass(frozen=True)
class OAuthAccountLinkedEvent:
    """Fired when an OAuth account is linked."""

    user_id: str
    provider: OAuthProvider
    linked_at: datetime


@dataclass(frozen=True)
class OAuthAccountUnlinkedEvent:
    """Fired when an OAuth account is unlinked."""

    user_id: str
    provider: OAuthProvider
    unlinked_at: datetime
