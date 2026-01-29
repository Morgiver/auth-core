"""
Basic Authentication Example

Demonstrates:
- User registration
- Login with email/password
- Token generation (JWT)
- Session management
- Password change
- MFA (TOTP) setup
"""

import logging
from datetime import timedelta

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import auth-core components
from auth_core import (
    AuthService,
    TokenService,
    SessionService,
    MFAService,
    PasswordResetService,
)

# Import adapters
from auth_core.adapters.hashers.argon2 import Argon2Hasher
from auth_core.adapters.token_generators.jwt import JWTGenerator
from auth_core.adapters.mfa_providers.totp import TOTPProvider
from auth_core.adapters.repositories.memory import (
    InMemoryCredentialRepository,
    InMemoryTokenRepository,
    InMemorySessionRepository,
    InMemoryPasswordResetRepository,
)
from auth_core.adapters.event_buses.memory import InMemoryEventBus


def main():
    logger.info("=" * 60)
    logger.info("auth-core: Basic Authentication Example")
    logger.info("=" * 60)

    # Setup dependencies
    logger.info("\n[+] Setting up dependencies...")

    # Hasher
    hasher = Argon2Hasher()

    # Token generator
    token_generator = JWTGenerator(
        secret_key="your-secret-key-change-in-production",
        algorithm="HS256",
        issuer="auth-core-example",
    )

    # Repositories
    credential_repo = InMemoryCredentialRepository()
    token_repo = InMemoryTokenRepository()
    session_repo = InMemorySessionRepository()
    reset_repo = InMemoryPasswordResetRepository()

    # Event bus
    event_bus = InMemoryEventBus()

    # Services
    auth_service = AuthService(
        credential_repo=credential_repo,
        password_hasher=hasher,
        event_bus=event_bus,
        max_failed_attempts=5,
        min_password_length=8,
    )

    token_service = TokenService(
        token_repo=token_repo,
        token_generator=token_generator,
        event_bus=event_bus,
        access_token_lifetime=timedelta(minutes=15),
        refresh_token_lifetime=timedelta(days=30),
    )

    session_service = SessionService(
        session_repo=session_repo,
        event_bus=event_bus,
        session_lifetime=timedelta(hours=24),
    )

    mfa_provider = TOTPProvider(password_hasher=hasher, issuer="AuthCoreExample")

    mfa_service = MFAService(
        credential_repo=credential_repo,
        mfa_provider=mfa_provider,
        event_bus=event_bus,
    )

    password_reset_service = PasswordResetService(
        credential_repo=credential_repo,
        reset_repo=reset_repo,
        password_hasher=hasher,
        event_bus=event_bus,
        reset_token_lifetime=timedelta(hours=1),
    )

    logger.info("    Dependencies configured successfully!")

    # 1. Register a new user
    logger.info("\n[1] Registering new user...")
    user_id = "user-123"
    email = "alice@example.com"
    password = "SecurePassword123"

    try:
        credential = auth_service.register(
            user_id=user_id,
            email=email,
            password=password
        )
        logger.info(f"    User registered: {email}")
        logger.info(f"    Credential ID: {credential.id}")
        logger.info(f"    Status: {credential.status.value}")
    except Exception as e:
        logger.error(f"    Registration failed: {str(e)}")
        return

    # 2. Authenticate user
    logger.info("\n[2] Authenticating user...")
    try:
        authenticated_cred = auth_service.authenticate(
            email=email,
            password=password
        )
        logger.info(f"    Authentication successful!")
        logger.info(f"    User ID: {authenticated_cred.user_id}")
        logger.info(f"    Last login: {authenticated_cred.last_successful_login}")
    except Exception as e:
        logger.error(f"    Authentication failed: {str(e)}")
        return

    # 3. Create tokens
    logger.info("\n[3] Creating access and refresh tokens...")
    try:
        access_token = token_service.create_access_token(
            user_id=user_id,
            scope="api:read api:write"
        )
        refresh_token = token_service.create_refresh_token(
            user_id=user_id
        )
        logger.info(f"    Access token created (expires: {access_token.expires_at})")
        logger.info(f"    Token value: {access_token.token_value[:50]}...")
        logger.info(f"    Refresh token created (expires: {refresh_token.expires_at})")
    except Exception as e:
        logger.error(f"    Token creation failed: {str(e)}")
        return

    # 4. Verify token
    logger.info("\n[4] Verifying access token...")
    try:
        verified_token = token_service.verify_token(access_token.token_value)
        logger.info(f"    Token verified successfully!")
        logger.info(f"    Token ID: {verified_token.id}")
        logger.info(f"    User ID: {verified_token.user_id}")
        logger.info(f"    Valid: {verified_token.is_valid()}")
    except Exception as e:
        logger.error(f"    Token verification failed: {str(e)}")

    # 5. Create session
    logger.info("\n[5] Creating user session...")
    try:
        session = session_service.create_session(
            user_id=user_id,
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0..."
        )
        logger.info(f"    Session created!")
        logger.info(f"    Session ID: {session.id}")
        logger.info(f"    Expires at: {session.expires_at}")
    except Exception as e:
        logger.error(f"    Session creation failed: {str(e)}")

    # 6. Change password
    logger.info("\n[6] Changing user password...")
    new_password = "NewSecurePassword456"
    try:
        auth_service.change_password(
            user_id=user_id,
            old_password=password,
            new_password=new_password
        )
        logger.info(f"    Password changed successfully!")

        # Verify new password works
        auth_service.authenticate(email=email, password=new_password)
        logger.info(f"    New password verified!")
    except Exception as e:
        logger.error(f"    Password change failed: {str(e)}")

    # 7. Enable MFA
    logger.info("\n[7] Enabling MFA (TOTP)...")
    try:
        secret, qr_uri, backup_codes = mfa_service.enable_mfa(
            user_id=user_id
        )
        logger.info(f"    MFA enabled!")
        logger.info(f"    Secret: {secret}")
        logger.info(f"    QR URI: {qr_uri[:60]}...")
        logger.info(f"    Backup codes: {len(backup_codes)} codes generated")

        # Simulate TOTP code generation and verification
        import pyotp
        totp = pyotp.TOTP(secret)
        code = totp.now()
        logger.info(f"    Generated TOTP code: {code}")

        # Verify MFA setup
        mfa_service.verify_mfa_setup(user_id=user_id, secret=secret, code=code)
        logger.info(f"    MFA setup verified!")

    except ImportError:
        logger.warning("    pyotp not installed - skipping MFA demo")
        logger.warning("    Install with: pip install auth-core[mfa]")
    except Exception as e:
        logger.error(f"    MFA setup failed: {str(e)}")

    # 8. Request password reset
    logger.info("\n[8] Requesting password reset...")
    try:
        reset_request = password_reset_service.request_password_reset(
            email=email,
            ip_address="192.168.1.100"
        )
        logger.info(f"    Password reset requested!")
        logger.info(f"    Request ID: {reset_request.id}")
        logger.info(f"    Token: {reset_request.token[:20]}...")
        logger.info(f"    Expires at: {reset_request.expires_at}")
    except Exception as e:
        logger.error(f"    Password reset request failed: {str(e)}")

    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("Example completed successfully!")
    logger.info("=" * 60)
    logger.info("\nWhat we demonstrated:")
    logger.info("  [+] User registration with secure password hashing")
    logger.info("  [+] Email/password authentication")
    logger.info("  [+] JWT token generation and verification")
    logger.info("  [+] Session management")
    logger.info("  [+] Password change workflow")
    logger.info("  [+] MFA (TOTP) setup and verification")
    logger.info("  [+] Password reset request")
    logger.info("\nNext steps:")
    logger.info("  - Explore other examples in the examples/ directory")
    logger.info("  - Read the documentation in README.md")
    logger.info("  - Try different adapters (SQLAlchemy, MongoDB, Redis)")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
