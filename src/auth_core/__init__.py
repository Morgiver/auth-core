"""
auth-core: Authentication and authorization package.

Hexagonal architecture implementation following DDD principles.
Framework-agnostic core for authentication and authorization.
"""

__version__ = "0.1.0"

# Domain models
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

# Domain services
from auth_core.domain.services import (
    AuthService,
    MFAService,
    PasswordResetService,
    SessionService,
    TokenService,
)

# Domain exceptions
from auth_core.domain.exceptions import (
    AuthDomainException,
    AuthenticationError,
    InvalidCredentialsError,
    CredentialLockedError,
    CredentialExpiredError,
    CredentialDisabledError,
    MFARequiredError,
    InvalidMFACodeError,
    PasswordError,
    WeakPasswordError,
    PasswordMismatchError,
    TokenError,
    InvalidTokenError,
    ExpiredTokenError,
    RevokedTokenError,
    SessionError,
    InvalidSessionError,
    ExpiredSessionError,
    OAuthError,
    MFAError,
    RepositoryError,
)

# Interfaces
from auth_core.interfaces.repository import (
    ICredentialRepository,
    ISessionRepository,
    ITokenRepository,
    IOAuthRepository,
    IPasswordResetRepository,
)
from auth_core.interfaces.hasher import IPasswordHasher
from auth_core.interfaces.token_generator import ITokenGenerator
from auth_core.interfaces.session_store import ISessionStore
from auth_core.interfaces.mfa_provider import IMFAProvider
from auth_core.interfaces.oauth_provider import IOAuthProvider, OAuthUserInfo, OAuthTokens
from auth_core.interfaces.event_bus import IEventBus

# DTOs
from auth_core.dto.requests import (
    LoginRequest,
    RegisterRequest,
    RefreshTokenRequest,
    PasswordResetRequest as PasswordResetRequestDTO,
    PasswordResetConfirmRequest,
    ChangePasswordRequest,
    EnableMFARequest,
    VerifyMFARequest,
    DisableMFARequest,
    OAuthLoginRequest,
    OAuthAuthorizationRequest,
)
from auth_core.dto.responses import (
    AuthResponse,
    TokenResponse,
    SessionResponse,
    MFASetupResponse,
    PasswordResetResponse,
    OAuthAuthorizationResponse,
)

# Events
from auth_core.events.events import (
    CredentialCreatedEvent,
    UserLoggedInEvent,
    UserLoggedOutEvent,
    TokenRefreshedEvent,
    PasswordChangedEvent,
    PasswordResetRequestedEvent,
    MFAEnabledEvent,
    MFADisabledEvent,
    CredentialLockedEvent,
    CredentialUnlockedEvent,
    OAuthAccountLinkedEvent,
    OAuthAccountUnlinkedEvent,
)

# Utilities
from auth_core.utils.validators import PasswordStrengthValidator, is_common_password
from auth_core.utils.generators import (
    generate_secure_token,
    generate_numeric_code,
    generate_alphanumeric_code,
    generate_backup_codes,
)

__all__ = [
    # Version
    "__version__",
    # Models
    "Credential",
    "CredentialStatus",
    "MFAType",
    "OAuthAccount",
    "OAuthProvider",
    "PasswordResetRequest",
    "Session",
    "Token",
    "TokenType",
    # Services
    "AuthService",
    "MFAService",
    "PasswordResetService",
    "SessionService",
    "TokenService",
    # Exceptions
    "AuthDomainException",
    "AuthenticationError",
    "InvalidCredentialsError",
    "CredentialLockedError",
    "CredentialExpiredError",
    "CredentialDisabledError",
    "MFARequiredError",
    "InvalidMFACodeError",
    "PasswordError",
    "WeakPasswordError",
    "PasswordMismatchError",
    "TokenError",
    "InvalidTokenError",
    "ExpiredTokenError",
    "RevokedTokenError",
    "SessionError",
    "InvalidSessionError",
    "ExpiredSessionError",
    "OAuthError",
    "MFAError",
    "RepositoryError",
    # Interfaces
    "ICredentialRepository",
    "ISessionRepository",
    "ITokenRepository",
    "IOAuthRepository",
    "IPasswordResetRepository",
    "IPasswordHasher",
    "ITokenGenerator",
    "ISessionStore",
    "IMFAProvider",
    "IOAuthProvider",
    "OAuthUserInfo",
    "OAuthTokens",
    "IEventBus",
    # DTOs
    "LoginRequest",
    "RegisterRequest",
    "RefreshTokenRequest",
    "PasswordResetRequestDTO",
    "PasswordResetConfirmRequest",
    "ChangePasswordRequest",
    "EnableMFARequest",
    "VerifyMFARequest",
    "DisableMFARequest",
    "OAuthLoginRequest",
    "OAuthAuthorizationRequest",
    "AuthResponse",
    "TokenResponse",
    "SessionResponse",
    "MFASetupResponse",
    "PasswordResetResponse",
    "OAuthAuthorizationResponse",
    # Events
    "CredentialCreatedEvent",
    "UserLoggedInEvent",
    "UserLoggedOutEvent",
    "TokenRefreshedEvent",
    "PasswordChangedEvent",
    "PasswordResetRequestedEvent",
    "MFAEnabledEvent",
    "MFADisabledEvent",
    "CredentialLockedEvent",
    "CredentialUnlockedEvent",
    "OAuthAccountLinkedEvent",
    "OAuthAccountUnlinkedEvent",
    # Utilities
    "PasswordStrengthValidator",
    "is_common_password",
    "generate_secure_token",
    "generate_numeric_code",
    "generate_alphanumeric_code",
    "generate_backup_codes",
]
