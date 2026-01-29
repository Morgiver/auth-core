"""
SQLAlchemy ORM models for auth-core.

These models map domain entities to database tables.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import declarative_base, relationship

from auth_core.domain.models import (
    CredentialStatus,
    MFAType,
    OAuthProvider,
    TokenType,
)

Base = declarative_base()


class CredentialModel(Base):
    """SQLAlchemy model for Credential entity."""

    __tablename__ = "auth_credentials"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    status = Column(Enum(CredentialStatus), nullable=False, default=CredentialStatus.ACTIVE)

    # MFA fields
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_type = Column(Enum(MFAType), nullable=True)
    mfa_secret = Column(String(255), nullable=True)
    backup_codes = Column(JSON, default=list, nullable=False)

    # Login tracking
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    last_failed_login = Column(DateTime, nullable=True)
    last_successful_login = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    password_changed_at = Column(DateTime, nullable=True)

    # Metadata
    metadata_ = Column("metadata", JSON, default=dict, nullable=False)

    def __repr__(self) -> str:
        return f"<CredentialModel(id={self.id}, user_id={self.user_id})>"


class SessionModel(Base):
    """SQLAlchemy model for Session entity."""

    __tablename__ = "auth_sessions"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), nullable=False, index=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_activity_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    revoked = Column(Boolean, default=False, nullable=False)
    metadata_ = Column("metadata", JSON, default=dict, nullable=False)

    def __repr__(self) -> str:
        return f"<SessionModel(id={self.id}, user_id={self.user_id})>"


class TokenModel(Base):
    """SQLAlchemy model for Token entity."""

    __tablename__ = "auth_tokens"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), nullable=False, index=True)
    token_type = Column(Enum(TokenType), nullable=False)
    token_value = Column(Text, nullable=False, unique=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

    revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime, nullable=True)

    metadata_ = Column("metadata", JSON, default=dict, nullable=False)

    def __repr__(self) -> str:
        return f"<TokenModel(id={self.id}, type={self.token_type})>"


class PasswordResetRequestModel(Base):
    """SQLAlchemy model for PasswordResetRequest entity."""

    __tablename__ = "auth_password_resets"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), nullable=False, index=True)
    token = Column(String(255), nullable=False, unique=True, index=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

    used = Column(Boolean, default=False, nullable=False)
    used_at = Column(DateTime, nullable=True)

    ip_address = Column(String(45), nullable=True)
    metadata_ = Column("metadata", JSON, default=dict, nullable=False)

    def __repr__(self) -> str:
        return f"<PasswordResetRequestModel(id={self.id}, user_id={self.user_id})>"


class OAuthAccountModel(Base):
    """SQLAlchemy model for OAuthAccount entity."""

    __tablename__ = "auth_oauth_accounts"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), nullable=False, index=True)
    provider = Column(Enum(OAuthProvider), nullable=False)
    provider_user_id = Column(String(255), nullable=False)
    provider_email = Column(String(255), nullable=True)

    access_token = Column(Text, nullable=True)
    refresh_token = Column(Text, nullable=True)
    token_expires_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    metadata_ = Column("metadata", JSON, default=dict, nullable=False)

    def __repr__(self) -> str:
        return f"<OAuthAccountModel(id={self.id}, provider={self.provider})>"
