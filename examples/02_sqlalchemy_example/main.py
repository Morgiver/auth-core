"""
Example: Using auth-core with SQLAlchemy for PostgreSQL/MySQL/SQLite.

This example demonstrates:
- Setting up SQLAlchemy with auth-core
- Creating database tables
- Using SQLAlchemy repositories
- Complete authentication flow with database persistence
"""

from datetime import timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from auth_core.domain.services import AuthService, TokenService
from auth_core.adapters.repositories.sqlalchemy import (
    Base,
    SQLAlchemyCredentialRepository,
    SQLAlchemyTokenRepository,
)
from auth_core.adapters.hashers.argon2 import Argon2Hasher
from auth_core.adapters.token_generators.jwt import JWTGenerator
from auth_core.adapters.event_buses.memory import InMemoryEventBus


def main():
    """Run SQLAlchemy example."""
    print("=" * 70)
    print("Auth-Core with SQLAlchemy Example")
    print("=" * 70)

    # Step 1: Setup SQLAlchemy database
    print("\n[1] Setting up SQLAlchemy database...")

    # Use SQLite for demo (can be PostgreSQL, MySQL, etc.)
    engine = create_engine("sqlite:///auth_demo.db", echo=False)

    # Create all tables
    Base.metadata.create_all(engine)
    print("   Tables created successfully")

    # Create session factory
    Session = sessionmaker(bind=engine)
    db_session = Session()

    # Step 2: Initialize repositories
    print("\n[2] Initializing repositories...")
    credential_repo = SQLAlchemyCredentialRepository(db_session)
    token_repo = SQLAlchemyTokenRepository(db_session)
    print("   SQLAlchemy repositories initialized")

    # Step 3: Initialize services
    print("\n[3] Initializing services...")
    password_hasher = Argon2Hasher()
    token_generator = JWTGenerator(
        secret_key="demo-secret-key-change-in-production",
        algorithm="HS256",
        issuer="auth-core-demo",
    )
    event_bus = InMemoryEventBus()

    auth_service = AuthService(
        credential_repo=credential_repo,
        password_hasher=password_hasher,
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
    print("   Services initialized")

    # Step 4: Register a user
    print("\n[4] Registering user...")
    print("   User ID: user-alice-001")
    print("   Password: SecurePassword123")

    credential = auth_service.register(
        user_id="user-alice-001",
        password="SecurePassword123",
    )
    print(f"   Credential created: {credential.id}")
    print(f"   Status: {credential.status.value}")

    # Step 5: Authenticate user
    print("\n[5] Authenticating user...")
    authenticated = auth_service.authenticate(
        user_id="user-alice-001",
        password="SecurePassword123",
    )
    print(f"   Authentication successful!")
    print(f"   User ID: {authenticated.user_id}")
    print(f"   Last login: {authenticated.last_successful_login}")

    # Step 6: Create access token
    print("\n[6] Creating access token...")
    access_token = token_service.create_access_token(
        user_id="user-alice-001",
        
    )
    print(f"   Token created: {access_token.id}")
    print(f"   Token type: {access_token.token_type.value}")
    print(f"   Expires at: {access_token.expires_at}")
    print(f"   Token value (JWT): {access_token.token_value[:50]}...")

    # Step 7: Verify token
    print("\n[7] Verifying token...")
    verified = token_service.verify_token(access_token.token_value)
    print(f"   Token verified successfully!")
    print(f"   User ID from token: {verified.user_id}")
    

    # Step 8: Query database directly
    print("\n[8] Database verification...")

    # Count credentials
    cred_count = db_session.query(
        credential_repo.collection.__class__
    ).count() if hasattr(credential_repo, 'collection') else "N/A"

    # Alternative way to count
    from auth_core.adapters.repositories.sqlalchemy.models import CredentialModel, TokenModel
    cred_count = db_session.query(CredentialModel).count()
    token_count = db_session.query(TokenModel).count()

    print(f"   Credentials in database: {cred_count}")
    print(f"   Tokens in database: {token_count}")

    # Step 9: Test password change
    print("\n[9] Testing password change...")
    auth_service.change_password(
        user_id="user-alice-001",
        old_password="SecurePassword123",
        new_password="NewSecurePassword456",
    )
    print("   Password changed successfully")

    # Verify old password doesn't work
    try:
        auth_service.authenticate(
            user_id="user-alice-001",
            password="SecurePassword123",
        )
        print("   ERROR: Old password still works!")
    except Exception:
        print("   Old password correctly rejected")

    # Verify new password works
    auth_service.authenticate(
        user_id="user-alice-001",
        password="NewSecurePassword456",
    )
    print("   New password works correctly")

    # Step 10: Cleanup
    print("\n[10] Cleanup...")
    db_session.commit()
    db_session.close()
    print("   Database session closed")

    print("\n" + "=" * 70)
    print("Example completed successfully!")
    print("=" * 70)
    print("\nDatabase file: auth_demo.db")
    print("You can inspect it with: sqlite3 auth_demo.db")
    print("\nUseful SQL queries:")
    print("  SELECT * FROM auth_credentials;")
    print("  SELECT * FROM auth_tokens;")
    print("=" * 70)


if __name__ == "__main__":
    main()
