"""
Unit tests for SessionService.
"""

import pytest
from datetime import datetime, timedelta

from auth_core.domain.exceptions import InvalidSessionError, ExpiredSessionError


class TestSessionServiceCreation:
    """Test session creation."""

    def test_create_session(self, session_service):
        """Test creating a new session."""
        session = session_service.create_session(
            user_id="user-123",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
        )

        assert session.user_id == "user-123"
        assert session.ip_address == "192.168.1.1"
        assert session.user_agent == "Mozilla/5.0"
        assert session.id is not None
        assert session.expires_at is not None

    def test_session_has_correct_lifetime(self, session_service):
        """Test that session has correct lifetime."""
        session = session_service.create_session(user_id="user-123")

        # Session should expire in 24 hours (default)
        lifetime = session.expires_at - session.created_at
        assert lifetime == timedelta(hours=24)


class TestSessionServiceRetrieval:
    """Test session retrieval."""

    def test_get_session_returns_valid_session(self, session_service):
        """Test retrieving a valid session."""
        # Create session
        created_session = session_service.create_session(user_id="user-123")

        # Retrieve it
        retrieved_session = session_service.get_session(created_session.id)

        assert retrieved_session.id == created_session.id
        assert retrieved_session.user_id == "user-123"

    def test_get_nonexistent_session_raises_error(self, session_service):
        """Test that getting nonexistent session raises error."""
        with pytest.raises(InvalidSessionError):
            session_service.get_session("nonexistent-session-id")

    def test_get_expired_session_raises_error(self, session_service, session_repo):
        """Test that getting expired session raises error."""
        # Create session that expires immediately
        now = datetime.utcnow()
        from auth_core.domain.models import Session
        expired_session = Session(
            user_id="user-123",
            created_at=now - timedelta(hours=25),
            expires_at=now - timedelta(hours=1),
            last_activity_at=now - timedelta(hours=1),
        )
        saved_session = session_repo.save(expired_session)

        # Try to get it
        with pytest.raises(ExpiredSessionError):
            session_service.get_session(saved_session.id)


class TestSessionServiceRefresh:
    """Test session refresh."""

    def test_refresh_session(self, session_service, session_repo):
        """Test refreshing a session."""
        import time
        # Create session
        session = session_service.create_session(user_id="user-123")
        original_expiry = session.expires_at
        original_activity = session.last_activity_at

        # Wait a tiny bit to ensure time difference
        time.sleep(0.01)

        # Refresh it
        refreshed_session = session_service.refresh_session(session.id)

        assert refreshed_session.expires_at > original_expiry
        assert refreshed_session.last_activity_at >= original_activity

    def test_refresh_nonexistent_session_raises_error(self, session_service):
        """Test that refreshing nonexistent session raises error."""
        with pytest.raises(InvalidSessionError):
            session_service.refresh_session("nonexistent-session-id")


class TestSessionServiceDeletion:
    """Test session deletion."""

    def test_delete_session(self, session_service, session_repo):
        """Test deleting a session."""
        # Create session
        session = session_service.create_session(user_id="user-123")

        # Delete it
        session_service.delete_session(session.id)

        # Verify deleted
        deleted_session = session_repo.find_by_id(session.id)
        assert deleted_session is None

    def test_delete_all_sessions_for_user(self, session_service, session_repo):
        """Test deleting all sessions for a user."""
        # Create multiple sessions
        session1 = session_service.create_session(user_id="user-123")
        session2 = session_service.create_session(user_id="user-123")

        # Delete all for user
        session_service.delete_all_sessions("user-123")

        # Verify all deleted
        assert session_repo.find_by_id(session1.id) is None
        assert session_repo.find_by_id(session2.id) is None


class TestSessionServiceCleanup:
    """Test session cleanup."""

    def test_cleanup_expired_sessions(self, session_service, session_repo):
        """Test cleaning up expired sessions."""
        # Create valid and expired sessions
        now = datetime.utcnow()

        valid_session = session_service.create_session(user_id="user-123")

        from auth_core.domain.models import Session
        expired_session = Session(
            user_id="user-456",
            created_at=now - timedelta(hours=25),
            expires_at=now - timedelta(hours=1),
            last_activity_at=now - timedelta(hours=1),
        )
        session_repo.save(expired_session)

        # Cleanup
        count = session_service.cleanup_expired_sessions()

        # Verify only expired removed
        assert count == 1
        assert session_repo.find_by_id(valid_session.id) is not None
        assert session_repo.find_by_id(expired_session.id) is None
