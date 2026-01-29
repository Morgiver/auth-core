"""
Response DTOs for auth-core package.

These DTOs define the output data structures.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class AuthResponse(BaseModel):
    """Response for authentication."""

    authenticated: bool
    user_id: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    mfa_required: bool = False
    expires_in: Optional[int] = None


class TokenResponse(BaseModel):
    """Response for token operations."""

    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    expires_in: int


class SessionResponse(BaseModel):
    """Response for session operations."""

    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    last_activity_at: datetime


class MFASetupResponse(BaseModel):
    """Response for MFA setup."""

    secret: str
    qr_uri: str
    backup_codes: List[str]


class PasswordResetResponse(BaseModel):
    """Response for password reset request."""

    message: str
    email: str


class OAuthAuthorizationResponse(BaseModel):
    """Response for OAuth authorization URL request."""

    authorization_url: str
    state: str
