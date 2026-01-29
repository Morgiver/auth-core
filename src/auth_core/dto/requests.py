"""
Request DTOs for auth-core package.

These DTOs define the input data structures with validation.
"""

from typing import Optional

from pydantic import BaseModel, Field

from auth_core.domain.models import MFAType


class LoginRequest(BaseModel):
    """Request to log in a user."""

    user_id: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    mfa_code: Optional[str] = Field(None, min_length=6, max_length=6)


class RegisterRequest(BaseModel):
    """Request to register new credentials."""

    user_id: str = Field(..., min_length=1)
    password: str = Field(..., min_length=8)


class RefreshTokenRequest(BaseModel):
    """Request to refresh an access token."""

    refresh_token: str = Field(..., min_length=1)


class PasswordResetRequest(BaseModel):
    """Request to reset password."""

    user_id: str = Field(..., min_length=1)


class PasswordResetConfirmRequest(BaseModel):
    """Request to confirm password reset with token."""

    token: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)


class ChangePasswordRequest(BaseModel):
    """Request to change password."""

    old_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)


class EnableMFARequest(BaseModel):
    """Request to enable MFA."""

    mfa_type: MFAType = MFAType.TOTP


class VerifyMFARequest(BaseModel):
    """Request to verify MFA setup."""

    secret: str = Field(..., min_length=1)
    code: str = Field(..., min_length=6, max_length=6)


class DisableMFARequest(BaseModel):
    """Request to disable MFA."""

    password: str = Field(..., min_length=1)


class OAuthLoginRequest(BaseModel):
    """Request to log in with OAuth."""

    provider: str = Field(..., min_length=1)
    code: str = Field(..., min_length=1)
    redirect_uri: str = Field(..., min_length=1)


class OAuthAuthorizationRequest(BaseModel):
    """Request to get OAuth authorization URL."""

    provider: str = Field(..., min_length=1)
    redirect_uri: str = Field(..., min_length=1)
    state: Optional[str] = None
