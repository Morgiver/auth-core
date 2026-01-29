# auth-core

**Framework-agnostic authentication and authorization package following Hexagonal Architecture and Domain-Driven Design principles.**

[![Tests](https://img.shields.io/badge/tests-136%20passed-brightgreen)]()
[![Coverage](https://img.shields.io/badge/coverage-81%25-green)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

## 🎯 Features

- **Email/Password Authentication** - Secure credential management with Argon2id hashing
- **JWT Tokens** - Access and refresh token generation and verification
- **Session Management** - Stateless (cookie) or stateful (Redis/DB) sessions
- **Multi-Factor Authentication (MFA)** - TOTP-based (Google Authenticator, Authy)
- **Password Reset** - Secure token-based password reset flow
- **OAuth Support** - Ready for Google, GitHub, Microsoft, Facebook, Apple
- **Account Locking** - Auto-lock after failed login attempts
- **Event-Driven** - Domain events for audit trails and inter-package communication

---

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│         Your Application            │
│   (FastAPI, Flask, CLI, Desktop)    │
└──────────────┬──────────────────────┘
               │
        ┌──────▼──────┐
        │  Adapters   │  ← You provide implementations
        └──────┬──────┘    (or use built-in ones)
               │
        ┌──────▼──────┐
        │   Domain    │  ← Pure business logic
        │  Services   │    (NO framework dependencies)
        └──────┬──────┘
               │
        ┌──────▼──────┐
        │ Interfaces  │  ← Abstract contracts
        └─────────────┘
```

**Hexagonal Architecture** = Your app controls the adapters, not the other way around!

---

## 📦 Installation

### Basic Installation

```bash
pip install auth-core
```

### With Optional Adapters

```bash
# Argon2 password hashing (recommended)
pip install auth-core[argon2]

# JWT token generation
pip install auth-core[jwt]

# MFA (TOTP) support
pip install auth-core[mfa]

# All adapters
pip install auth-core[all]
```

### Optional Dependencies by Feature

| Feature | Install | Use Case |
|---------|---------|----------|
| **Argon2** | `auth-core[argon2]` | OWASP-recommended password hashing |
| **Bcrypt** | `auth-core[bcrypt]` | Legacy/migration password hashing |
| **JWT** | `auth-core[jwt]` | JSON Web Token generation |
| **Fernet** | `auth-core[fernet]` | Symmetric encryption for tokens |
| **MFA** | `auth-core[mfa]` | TOTP-based 2FA |
| **OAuth** | `auth-core[oauth]` | Social login (Google, GitHub, etc.) |
| **Redis** | `auth-core[redis]` | Redis session storage |
| **SQLAlchemy** | `auth-core[sqlalchemy]` | SQL database repositories |
| **MongoDB** | `auth-core[mongodb]` | MongoDB repositories |

---

## 🚀 Quick Start

### Basic Authentication Flow

```python
from auth_core import AuthService, TokenService
from auth_core.adapters.hashers.argon2 import Argon2Hasher
from auth_core.adapters.token_generators.jwt import JWTGenerator
from auth_core.adapters.repositories.memory import (
    InMemoryCredentialRepository,
    InMemoryTokenRepository,
)

# Setup dependencies
hasher = Argon2Hasher()
token_generator = JWTGenerator(secret_key="your-secret-key")
credential_repo = InMemoryCredentialRepository()
token_repo = InMemoryTokenRepository()

# Create services
auth_service = AuthService(
    credential_repo=credential_repo,
    password_hasher=hasher,
)

token_service = TokenService(
    token_repo=token_repo,
    token_generator=token_generator,
)

# Register a user
credential = auth_service.register(
    user_id="user-123",
    email="alice@example.com",
    password="SecurePassword123",
)

# Authenticate
authenticated = auth_service.authenticate(
    email="alice@example.com",
    password="SecurePassword123",
)

# Create tokens
access_token = token_service.create_access_token(user_id="user-123")
refresh_token = token_service.create_refresh_token(user_id="user-123")

print(f"Access token: {access_token.token_value}")
print(f"Expires at: {access_token.expires_at}")
```

---

## 📚 Core Concepts

### 1. Domain Models

Pure business entities with NO external dependencies:

```python
from auth_core.domain.models import Credential, CredentialStatus

credential = Credential(
    user_id="user-123",
    email="alice@example.com",
    password_hash="hashed_password",
    status=CredentialStatus.ACTIVE,
    created_at=datetime.utcnow(),
    updated_at=datetime.utcnow(),
)

# Business logic methods
credential.lock("Too many failed attempts")
credential.unlock()
credential.record_failed_login()
credential.record_successful_login()
credential.enable_mfa(MFAType.TOTP, secret="...", backup_codes=[...])
```

### 2. Domain Services

Orchestrate business logic:

```python
# AuthService - Authentication and credential management
auth_service.register(user_id, email, password)
auth_service.authenticate(email, password, mfa_code=None)
auth_service.change_password(user_id, old_password, new_password)
auth_service.lock_credentials(user_id, reason)
auth_service.unlock_credentials(user_id)

# TokenService - Token lifecycle management
token_service.create_access_token(user_id, **metadata)
token_service.create_refresh_token(user_id)
token_service.refresh_access_token(refresh_token_value)
token_service.verify_token(token_value)
token_service.revoke_token(token_id)
token_service.revoke_all_tokens(user_id, token_type=None)

# SessionService - Session management
session_service.create_session(user_id, ip_address, user_agent)
session_service.get_session(session_id)
session_service.refresh_session(session_id)
session_service.delete_session(session_id)
session_service.delete_all_sessions(user_id)
session_service.cleanup_expired_sessions()

# MFAService - Multi-factor authentication
secret, qr_uri, backup_codes = mfa_service.enable_mfa(user_id)
mfa_service.verify_mfa_setup(user_id, secret, code)
mfa_service.verify_mfa_code(user_id, code)
mfa_service.disable_mfa(user_id, password)
backup_codes = mfa_service.regenerate_backup_codes(user_id)

# PasswordResetService - Password reset flow
reset_request = password_reset_service.request_password_reset(email)
password_reset_service.reset_password(token, new_password)
```

### 3. Interfaces (Abstract Contracts)

Define what you need, provide your own implementation:

```python
from auth_core.interfaces.repository import ICredentialRepository
from auth_core.interfaces.hasher import IPasswordHasher
from auth_core.interfaces.token_generator import ITokenGenerator

# Implement your own adapter
class MyDatabaseCredentialRepository(ICredentialRepository):
    def save(self, credential: Credential) -> Credential:
        # Your database logic here
        pass

    def find_by_email(self, email: str) -> Optional[Credential]:
        # Your query logic here
        pass

    # ... implement all interface methods
```

### 4. Built-in Adapters

Or use the provided adapters:

```python
# Password Hashers
from auth_core.adapters.hashers.argon2 import Argon2Hasher
from auth_core.adapters.hashers.bcrypt import BcryptHasher

# Token Generators
from auth_core.adapters.token_generators.jwt import JWTGenerator
from auth_core.adapters.token_generators.fernet import FernetGenerator

# Repositories
from auth_core.adapters.repositories.memory import (
    InMemoryCredentialRepository,
    InMemoryTokenRepository,
    InMemorySessionRepository,
)

# MFA Providers
from auth_core.adapters.mfa_providers.totp import TOTPProvider

# Event Buses
from auth_core.adapters.event_buses.memory import InMemoryEventBus
```

### 5. Event-Driven Architecture

Subscribe to domain events:

```python
from auth_core.events.events import (
    UserLoggedInEvent,
    PasswordChangedEvent,
    CredentialLockedEvent,
)

def on_user_logged_in(event: UserLoggedInEvent):
    print(f"User {event.user_id} logged in at {event.logged_in_at}")

def on_password_changed(event: PasswordChangedEvent):
    # Send email notification
    send_email(event.user_id, "Your password was changed")

def on_credential_locked(event: CredentialLockedEvent):
    # Alert security team
    alert_security(event.user_id, event.reason)

# Subscribe to events
event_bus.subscribe(UserLoggedInEvent, on_user_logged_in)
event_bus.subscribe(PasswordChangedEvent, on_password_changed)
event_bus.subscribe(CredentialLockedEvent, on_credential_locked)
```

---

## 🔐 Security Features

### Password Hashing

- **Argon2id** (default) - OWASP recommended for 2026
- **Bcrypt** - For compatibility/migration
- Configurable time/memory costs
- Automatic rehashing when parameters change

```python
from auth_core.adapters.hashers.argon2 import Argon2Hasher

hasher = Argon2Hasher(
    time_cost=2,        # Number of iterations
    memory_cost=65536,  # 64 MB
    parallelism=1,
)

hashed = hasher.hash("SecurePassword123")
is_valid = hasher.verify("SecurePassword123", hashed)
needs_upgrade = hasher.needs_rehash(hashed)
```

### JWT Tokens

- Short-lived access tokens (default: 15 minutes)
- Long-lived refresh tokens (default: 30 days)
- Signed with HS256 or RS256
- Custom claims support

```python
from auth_core.adapters.token_generators.jwt import JWTGenerator
from datetime import timedelta

generator = JWTGenerator(
    secret_key="your-secret-key",
    algorithm="HS256",
    issuer="your-app",
    audience="your-api",
)

token = generator.generate(
    subject="user-123",
    expires_in=timedelta(minutes=15),
    scope="api:read api:write",
    role="admin",
)

claims = generator.verify(token)
print(claims["sub"])   # "user-123"
print(claims["scope"]) # "api:read api:write"
```

### Account Security

- **Auto-lock** after N failed login attempts (configurable)
- **Password strength validation** (min length, complexity)
- **Failed login tracking** with timestamps
- **Session expiration** and cleanup

```python
from auth_core import AuthService

auth_service = AuthService(
    credential_repo=credential_repo,
    password_hasher=hasher,
    max_failed_attempts=5,      # Lock after 5 failures
    min_password_length=8,      # Minimum 8 characters
)
```

### MFA (Two-Factor Authentication)

- **TOTP** (Time-based One-Time Password)
- Compatible with Google Authenticator, Authy, etc.
- **Backup codes** for account recovery
- QR code generation for easy setup

```python
from auth_core import MFAService
from auth_core.adapters.mfa_providers.totp import TOTPProvider

mfa_service = MFAService(
    credential_repo=credential_repo,
    mfa_provider=TOTPProvider(password_hasher=hasher),
)

# Enable MFA
secret, qr_uri, backup_codes = mfa_service.enable_mfa(user_id="user-123")

# User scans QR code with authenticator app
print(f"Scan this QR code: {qr_uri}")

# Verify setup
code = input("Enter code from authenticator app: ")
mfa_service.verify_mfa_setup(user_id="user-123", secret=secret, code=code)

# Login with MFA
credential = auth_service.authenticate(
    email="alice@example.com",
    password="SecurePassword123",
    mfa_code="123456",  # From authenticator app
)
```

---

## 🎨 Usage Examples

### FastAPI Integration

```python
from fastapi import FastAPI, Depends, HTTPException
from auth_core import AuthService, TokenService
from auth_core.dto.requests import LoginRequest
from auth_core.dto.responses import TokenResponse

app = FastAPI()

# Setup dependencies (in real app, use dependency injection)
auth_service = AuthService(...)
token_service = TokenService(...)

@app.post("/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    try:
        # Authenticate user
        credential = auth_service.authenticate(
            email=request.email,
            password=request.password,
            mfa_code=request.mfa_code,
        )

        # Create tokens
        access_token = token_service.create_access_token(
            user_id=credential.user_id
        )
        refresh_token = token_service.create_refresh_token(
            user_id=credential.user_id
        )

        return TokenResponse(
            access_token=access_token.token_value,
            refresh_token=refresh_token.token_value,
            token_type="Bearer",
            expires_in=900,  # 15 minutes
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh(refresh_token: str):
    try:
        # Refresh access token
        new_access_token = token_service.refresh_access_token(refresh_token)

        return TokenResponse(
            access_token=new_access_token.token_value,
            token_type="Bearer",
            expires_in=900,
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
```

### Flask Integration

```python
from flask import Flask, request, jsonify
from auth_core import AuthService

app = Flask(__name__)
auth_service = AuthService(...)

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.json

    try:
        credential = auth_service.authenticate(
            email=data["email"],
            password=data["password"],
        )

        return jsonify({
            "user_id": credential.user_id,
            "email": credential.email,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 401
```

### CLI Application

```python
import click
from auth_core import AuthService

auth_service = AuthService(...)

@click.group()
def cli():
    pass

@cli.command()
@click.option("--email", prompt=True)
@click.option("--password", prompt=True, hide_input=True)
def register(email, password):
    """Register a new user."""
    try:
        user_id = str(uuid.uuid4())
        credential = auth_service.register(user_id, email, password)
        click.echo(f"User registered: {credential.email}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)

@cli.command()
@click.option("--email", prompt=True)
@click.option("--password", prompt=True, hide_input=True)
def login(email, password):
    """Login."""
    try:
        credential = auth_service.authenticate(email, password)
        click.echo(f"Logged in as: {credential.email}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)

if __name__ == "__main__":
    cli()
```

---

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/auth_core --cov-report=html

# Run only unit tests
pytest tests/unit -v

# Run only contract tests
pytest tests/contracts -v

# Run only E2E tests
pytest tests/e2e -v
```

**Test Results:**
- ✅ **136 tests** passing
- ✅ **81% coverage**
- ✅ Unit tests (domain logic)
- ✅ Contract tests (interface compliance)
- ✅ E2E tests (complete flows)

---

## 📖 Documentation

### Package Structure

```
auth-core/
├── src/auth_core/
│   ├── domain/              # Core business logic
│   │   ├── models.py        # Entities (Credential, Session, Token)
│   │   ├── services.py      # Business services
│   │   └── exceptions.py    # Domain exceptions
│   ├── interfaces/          # Abstract contracts
│   │   ├── repository.py
│   │   ├── hasher.py
│   │   ├── token_generator.py
│   │   └── ...
│   ├── adapters/            # Concrete implementations
│   │   ├── hashers/
│   │   ├── token_generators/
│   │   ├── repositories/
│   │   └── ...
│   ├── dto/                 # Data Transfer Objects
│   ├── events/              # Domain events
│   └── utils/               # Utilities
└── tests/                   # Test suite
    ├── unit/
    ├── contracts/
    └── e2e/
```

### Key Principles

1. **Dependency Inversion** - Depend on abstractions, not concretions
2. **Single Responsibility** - Each module has one reason to change
3. **Open/Closed** - Open for extension, closed for modification
4. **Framework Agnostic** - Works with FastAPI, Flask, CLI, Desktop, etc.
5. **Test-Driven** - 136 tests ensure reliability

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Write tests for your changes
4. Ensure all tests pass
5. Submit a pull request

---

## 📄 License

MIT License - see LICENSE file for details

---

## 🙏 Acknowledgments

- Inspired by **Hexagonal Architecture** (Alistair Cockburn)
- Follows **Domain-Driven Design** principles (Eric Evans)
- Security best practices from **OWASP**

---

## 📞 Support

- 📧 Email: your.email@example.com
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/auth-core/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/yourusername/auth-core/discussions)

---

**Built with ❤️ following clean architecture principles**
