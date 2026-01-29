"""
Unit tests for Session domain model.
"""

import pytest
from datetime import datetime, timedelta

from auth_core.domain.models import Session


class TestSessionCreation:
    """Test session creation and initialization."""

    def test_create_session_with_required_fields(self):
        """Test creating session with required fields."""
        now = datetime.utcnow()
        expires = now + timedelta(hours=24)

        session = Session(
            user_id="user-123",
            created_at=now,
            expires_at=expires,
            last_activity_at=now,
        )

        assert session.user_id == "user-123"
        assert session.created_at == now
        assert session.expires_at == expires
        assert session.last_activity_at == now

    def test_session_with_optional_fields(self):
        """Test session with optional metadata."""
        now = datetime.utcnow()
        session = Session(
            user_id="user-123",
            created_at=now,
            expires_at=now + timedelta(hours=1),
            last_activity_at=now,
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            metadata={"device": "mobile"},
        )

        assert session.ip_address == "192.168.1.1"
        assert session.user_agent == "Mozilla/5.0"
        assert session.metadata["device"] == "mobile"


class TestSessionExpiration:
    """Test session expiration logic."""

    def test_is_expired_returns_false_for_valid_session(self, valid_session):
        """Test that valid session is not expired."""
        assert valid_session.is_expired() is False

    def test_is_expired_returns_true_for_expired_session(self, expired_session):
        """Test that expired session is detected."""
        assert expired_session.is_expired() is True

    def test_refresh_session(self, valid_session):
        """Test refreshing a session."""
        original_expiry = valid_session.expires_at
        new_expiry = datetime.utcnow() + timedelta(hours=48)

        valid_session.refresh(new_expiry)

        assert valid_session.expires_at == new_expiry
        assert valid_session.expires_at > original_expiry
        assert valid_session.last_activity_at is not None


class TestSessionDefaults:
    """Test session default values."""

    def test_session_id_defaults_to_none(self):
        """Test that session ID defaults to None."""
        now = datetime.utcnow()
        session = Session(
            user_id="user-123",
            created_at=now,
            expires_at=now + timedelta(hours=1),
            last_activity_at=now,
        )

        assert session.id is None

    def test_session_metadata_defaults_to_empty_dict(self):
        """Test that metadata defaults to empty dict."""
        now = datetime.utcnow()
        session = Session(
            user_id="user-123",
            created_at=now,
            expires_at=now + timedelta(hours=1),
            last_activity_at=now,
        )

        assert session.metadata == {}
