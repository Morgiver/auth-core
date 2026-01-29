"""
Pytest configuration and shared fixtures for auth-core tests.
"""

import pytest
from datetime import datetime, timedelta
from typing import Generator

# Import domain models
from auth_core.domain.models import (
    Credential,
    CredentialStatus,
    Session,
    Token,
    TokenType,
    OAuthAccount,
    OAuthProvider,
    PasswordResetRequest,
    MFAType,
)

# Import repositories
from auth_core.adapters.repositories.memory import (
    InMemoryCredentialRepository,
    InMemorySessionRepository,
    InMemoryTokenRepository,
    InMemoryOAuthRepository,
    InMemoryPasswordResetRepository,
)

# Import adapters
from auth_core.adapters.hashers.argon2 import Argon2Hasher
from auth_core.adapters.hashers.bcrypt import BcryptHasher
from auth_core.adapters.token_generators.jwt import JWTGenerator
from auth_core.adapters.token_generators.fernet import FernetGenerator
from auth_core.adapters.event_buses.memory import InMemoryEventBus

try:
    from auth_core.adapters.mfa_providers.totp import TOTPProvider
    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False


# ===== Domain Model Fixtures =====

@pytest.fixture
def valid_credential() -> Credential:
    """Create a valid active credential."""
    now = datetime.utcnow()
    return Credential(
        id="cred-123",
        user_id="user-123",
        password_hash="hashed_password",
        status=CredentialStatus.ACTIVE,
        created_at=now,
        updated_at=now,
        password_changed_at=now,
    )


@pytest.fixture
def locked_credential(valid_credential: Credential) -> Credential:
    """Create a locked credential."""
    credential = valid_credential
    credential.lock("Too many failed attempts")
    return credential


@pytest.fixture
def valid_session() -> Session:
    """Create a valid session."""
    now = datetime.utcnow()
    return Session(
        id="session-123",
        user_id="user-123",
        created_at=now,
        expires_at=now + timedelta(hours=24),
        last_activity_at=now,
        ip_address="192.168.1.1",
        user_agent="Mozilla/5.0",
    )


@pytest.fixture
def expired_session() -> Session:
    """Create an expired session."""
    now = datetime.utcnow()
    return Session(
        id="session-expired",
        user_id="user-123",
        created_at=now - timedelta(hours=25),
        expires_at=now - timedelta(hours=1),
        last_activity_at=now - timedelta(hours=1),
    )


@pytest.fixture
def valid_token() -> Token:
    """Create a valid access token."""
    now = datetime.utcnow()
    return Token(
        id="token-123",
        user_id="user-123",
        token_type=TokenType.ACCESS,
        token_value="jwt_token_value",
        created_at=now,
        expires_at=now + timedelta(minutes=15),
    )


@pytest.fixture
def refresh_token() -> Token:
    """Create a refresh token."""
    now = datetime.utcnow()
    return Token(
        id="token-refresh",
        user_id="user-123",
        token_type=TokenType.REFRESH,
        token_value="refresh_token_value",
        created_at=now,
        expires_at=now + timedelta(days=30),
    )


@pytest.fixture
def expired_token() -> Token:
    """Create an expired token."""
    now = datetime.utcnow()
    return Token(
        id="token-expired",
        user_id="user-123",
        token_type=TokenType.ACCESS,
        token_value="expired_token",
        created_at=now - timedelta(minutes=20),
        expires_at=now - timedelta(minutes=5),
    )


@pytest.fixture
def valid_oauth_account() -> OAuthAccount:
    """Create a valid OAuth account."""
    now = datetime.utcnow()
    return OAuthAccount(
        id="oauth-123",
        user_id="user-123",
        provider=OAuthProvider.GOOGLE,
        provider_user_id="google-user-123",
        provider_email="test@gmail.com",
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def valid_password_reset() -> PasswordResetRequest:
    """Create a valid password reset request."""
    now = datetime.utcnow()
    return PasswordResetRequest(
        id="reset-123",
        user_id="user-123",
        token="secure_reset_token",
        created_at=now,
        expires_at=now + timedelta(hours=1),
    )


# ===== Repository Fixtures =====

@pytest.fixture
def credential_repo() -> InMemoryCredentialRepository:
    """Create a fresh credential repository."""
    return InMemoryCredentialRepository()


@pytest.fixture
def session_repo() -> InMemorySessionRepository:
    """Create a fresh session repository."""
    return InMemorySessionRepository()


@pytest.fixture
def token_repo() -> InMemoryTokenRepository:
    """Create a fresh token repository."""
    return InMemoryTokenRepository()


@pytest.fixture
def oauth_repo() -> InMemoryOAuthRepository:
    """Create a fresh OAuth repository."""
    return InMemoryOAuthRepository()


@pytest.fixture
def reset_repo() -> InMemoryPasswordResetRepository:
    """Create a fresh password reset repository."""
    return InMemoryPasswordResetRepository()


# ===== Adapter Fixtures =====

@pytest.fixture
def argon2_hasher() -> Argon2Hasher:
    """Create an Argon2 hasher."""
    try:
        return Argon2Hasher()
    except ImportError:
        pytest.skip("argon2-cffi not installed")


@pytest.fixture
def bcrypt_hasher() -> BcryptHasher:
    """Create a bcrypt hasher."""
    try:
        return BcryptHasher()
    except ImportError:
        pytest.skip("bcrypt not installed")


@pytest.fixture
def jwt_generator() -> JWTGenerator:
    """Create a JWT generator."""
    try:
        return JWTGenerator(
            secret_key="test-secret-key",
            algorithm="HS256",
            issuer="test",
        )
    except ImportError:
        pytest.skip("pyjwt not installed")


@pytest.fixture
def fernet_generator() -> FernetGenerator:
    """Create a Fernet generator."""
    try:
        key = FernetGenerator.generate_key()
        return FernetGenerator(key)
    except ImportError:
        pytest.skip("cryptography not installed")


@pytest.fixture
def totp_provider(argon2_hasher: Argon2Hasher) -> "TOTPProvider":
    """Create a TOTP provider."""
    if not TOTP_AVAILABLE:
        pytest.skip("pyotp not installed")
    return TOTPProvider(password_hasher=argon2_hasher, issuer="test")


@pytest.fixture
def event_bus() -> InMemoryEventBus:
    """Create an event bus."""
    return InMemoryEventBus()


# ===== Service Fixtures =====

@pytest.fixture
def auth_service(credential_repo, argon2_hasher, event_bus):
    """Create an AuthService."""
    from auth_core.domain.services import AuthService
    return AuthService(
        credential_repo=credential_repo,
        password_hasher=argon2_hasher,
        event_bus=event_bus,
        max_failed_attempts=5,
        min_password_length=8,
    )


@pytest.fixture
def token_service(token_repo, jwt_generator, event_bus):
    """Create a TokenService."""
    from auth_core.domain.services import TokenService
    return TokenService(
        token_repo=token_repo,
        token_generator=jwt_generator,
        event_bus=event_bus,
        access_token_lifetime=timedelta(minutes=15),
        refresh_token_lifetime=timedelta(days=30),
    )


@pytest.fixture
def session_service(session_repo, event_bus):
    """Create a SessionService."""
    from auth_core.domain.services import SessionService
    return SessionService(
        session_repo=session_repo,
        event_bus=event_bus,
        session_lifetime=timedelta(hours=24),
    )


@pytest.fixture
def mfa_service(credential_repo, totp_provider, event_bus):
    """Create an MFAService."""
    from auth_core.domain.services import MFAService
    return MFAService(
        credential_repo=credential_repo,
        mfa_provider=totp_provider,
        event_bus=event_bus,
    )


@pytest.fixture
def password_reset_service(credential_repo, reset_repo, argon2_hasher, event_bus):
    """Create a PasswordResetService."""
    from auth_core.domain.services import PasswordResetService
    return PasswordResetService(
        credential_repo=credential_repo,
        reset_repo=reset_repo,
        password_hasher=argon2_hasher,
        event_bus=event_bus,
        reset_token_lifetime=timedelta(hours=1),
    )
