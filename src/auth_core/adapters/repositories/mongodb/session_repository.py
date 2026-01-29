"""MongoDB implementation of ISessionRepository."""

import logging
from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from pymongo.database import Database
from pymongo.collection import Collection

from auth_core.domain.models import Session
from auth_core.interfaces.repository import ISessionRepository

logger = logging.getLogger(__name__)


class MongoDBSessionRepository(ISessionRepository):
    """MongoDB implementation of session repository."""

    def __init__(self, database: Database, collection_name: str = "sessions") -> None:
        """
        Initialize repository with MongoDB database.

        Args:
            database: MongoDB database instance
            collection_name: Name of collection to use
        """
        self.collection: Collection = database[collection_name]
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        """Create necessary indexes."""
        self.collection.create_index("user_id")
        self.collection.create_index("expires_at")
        self.collection.create_index("created_at")

    def save(self, session: Session) -> Session:
        """Save or update a session."""
        # Generate ID if needed
        if not session.id:
            session.id = str(uuid4())

        doc = self._entity_to_document(session)

        # Upsert
        self.collection.replace_one(
            {"_id": session.id}, doc, upsert=True
        )

        logger.debug(f"Saved session: {session.id}")
        return session

    def find_by_id(self, session_id: str) -> Optional[Session]:
        """Find session by ID."""
        doc = self.collection.find_one({"_id": session_id})
        return self._document_to_entity(doc) if doc else None

    def find_by_user_id(self, user_id: str) -> List[Session]:
        """Find all sessions for a user."""
        docs = self.collection.find({"user_id": user_id})
        return [self._document_to_entity(doc) for doc in docs]

    def delete(self, session_id: str) -> None:
        """Delete a session."""
        result = self.collection.delete_one({"_id": session_id})
        if result.deleted_count > 0:
            logger.debug(f"Deleted session: {session_id}")

    def delete_by_user_id(self, user_id: str) -> None:
        """Delete all sessions for a user."""
        result = self.collection.delete_many({"user_id": user_id})
        logger.debug(f"Deleted {result.deleted_count} sessions for user: {user_id}")

    def delete_expired(self, before: datetime) -> int:
        """Delete all expired sessions."""
        result = self.collection.delete_many({"expires_at": {"$lt": before}})
        count = result.deleted_count
        logger.debug(f"Deleted {count} expired sessions")
        return count

    def _entity_to_document(self, entity: Session) -> dict:
        """Convert domain entity to MongoDB document."""
        return {
            "_id": entity.id,
            "user_id": entity.user_id,
            "created_at": entity.created_at,
            "expires_at": entity.expires_at,
            "last_activity_at": entity.last_activity_at,
            "ip_address": entity.ip_address,
            "user_agent": entity.user_agent,
            "revoked": entity.revoked,
            "metadata": entity.metadata,
        }

    def _document_to_entity(self, doc: dict) -> Session:
        """Convert MongoDB document to domain entity."""
        return Session(
            id=doc["_id"],
            user_id=doc["user_id"],
            created_at=doc["created_at"],
            expires_at=doc["expires_at"],
            last_activity_at=doc["last_activity_at"],
            ip_address=doc.get("ip_address"),
            user_agent=doc.get("user_agent"),
            revoked=doc.get("revoked", False),
            metadata=doc.get("metadata", {}),
        )
