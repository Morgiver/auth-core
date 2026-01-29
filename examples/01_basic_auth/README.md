# Basic Authentication Example

This example demonstrates basic authentication using auth-core with in-memory storage.

## Features

- User registration
- Email/password login
- Token generation (access + refresh)
- Password change
- Session management
- MFA (TOTP) setup and verification

## Requirements

```bash
pip install auth-core[argon2,jwt,mfa]
```

## Usage

```bash
python main.py
```

## What it demonstrates

1. **Registration**: Create credentials for a user
2. **Login**: Authenticate with email/password
3. **Tokens**: Generate JWT access and refresh tokens
4. **Sessions**: Create and manage user sessions
5. **Password Change**: Update user password
6. **MFA**: Enable and verify TOTP-based MFA
