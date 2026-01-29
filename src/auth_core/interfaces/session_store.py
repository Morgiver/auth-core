"""
Session store interface for auth-core package.

Defines the contract for session storage (cookie-based, Redis, database, etc.).
"""

from abc import ABC, abstractmethod
from typing import Optional

from auth_core.domain.models import Session


class ISessionStore(ABC):
    """Abstract interface for session storage."""

    @abstractmethod
    def create(self, session: Session) -> str:
        """
        Create a new session and return its identifier.

        Args:
            session: The session to create

        Returns:
            The session identifier (e.g., session ID or encrypted cookie value)
        """
        pass

    @abstractmethod
    def get(self, identifier: str) -> Optional[Session]:
        """
        Retrieve a session by its identifier.

        Args:
            identifier: The session identifier

        Returns:
            The session if found and valid, None otherwise
        """
        pass

    @abstractmethod
    def update(self, identifier: str, session: Session) -> None:
        """
        Update an existing session.

        Args:
            identifier: The session identifier
            session: The updated session

        Raises:
            InvalidSessionError: If session not found
        """
        pass

    @abstractmethod
    def delete(self, identifier: str) -> None:
        """
        Delete a session.

        Args:
            identifier: The session identifier
        """
        pass

    @abstractmethod
    def delete_all_for_user(self, user_id: str) -> None:
        """
        Delete all sessions for a user.

        Args:
            user_id: The user ID
        """
        pass

    @abstractmethod
    def cleanup_expired(self) -> int:
        """
        Clean up expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        pass
