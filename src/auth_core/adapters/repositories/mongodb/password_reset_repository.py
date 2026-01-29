"""MongoDB implementation of IPasswordResetRepository."""

import logging
from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from pymongo.database import Database
from pymongo.collection import Collection

from auth_core.domain.models import PasswordResetRequest
from auth_core.interfaces.repository import IPasswordResetRepository

logger = logging.getLogger(__name__)


class MongoDBPasswordResetRepository(IPasswordResetRepository):
    """MongoDB implementation of password reset repository."""

    def __init__(
        self, database: Database, collection_name: str = "password_resets"
    ) -> None:
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
        self.collection.create_index("token", unique=True)
        self.collection.create_index("expires_at")
        self.collection.create_index("created_at")

    def save(self, reset_request: PasswordResetRequest) -> PasswordResetRequest:
        """Save or update a password reset request."""
        # Generate ID if needed
        if not reset_request.id:
            reset_request.id = str(uuid4())

        doc = self._entity_to_document(reset_request)

        # Upsert
        self.collection.replace_one(
            {"_id": reset_request.id}, doc, upsert=True
        )

        logger.debug(f"Saved password reset request: {reset_request.id}")
        return reset_request

    def find_by_id(self, request_id: str) -> Optional[PasswordResetRequest]:
        """Find password reset request by ID."""
        doc = self.collection.find_one({"_id": request_id})
        return self._document_to_entity(doc) if doc else None

    def find_by_token(self, token: str) -> Optional[PasswordResetRequest]:
        """Find password reset request by token."""
        doc = self.collection.find_one({"token": token})
        return self._document_to_entity(doc) if doc else None

    def find_by_user_id(self, user_id: str) -> List[PasswordResetRequest]:
        """Find all password reset requests for a user."""
        docs = self.collection.find({"user_id": user_id})
        return [self._document_to_entity(doc) for doc in docs]

    def delete(self, request_id: str) -> None:
        """Delete a password reset request."""
        result = self.collection.delete_one({"_id": request_id})
        if result.deleted_count > 0:
            logger.debug(f"Deleted password reset request: {request_id}")

    def delete_by_user_id(self, user_id: str) -> None:
        """Delete all password reset requests for a user."""
        result = self.collection.delete_many({"user_id": user_id})
        logger.debug(
            f"Deleted {result.deleted_count} password reset requests for user: {user_id}"
        )

    def delete_expired(self, before: datetime) -> int:
        """Delete all expired password reset requests."""
        result = self.collection.delete_many({"expires_at": {"$lt": before}})
        count = result.deleted_count
        logger.debug(f"Deleted {count} expired password reset requests")
        return count

    def _entity_to_document(self, entity: PasswordResetRequest) -> dict:
        """Convert domain entity to MongoDB document."""
        return {
            "_id": entity.id,
            "user_id": entity.user_id,
            "token": entity.token,
            "created_at": entity.created_at,
            "expires_at": entity.expires_at,
            "used": entity.used,
            "used_at": entity.used_at,
            "ip_address": entity.ip_address,
            "metadata": entity.metadata,
        }

    def _document_to_entity(self, doc: dict) -> PasswordResetRequest:
        """Convert MongoDB document to domain entity."""
        return PasswordResetRequest(
            id=doc["_id"],
            user_id=doc["user_id"],
            token=doc["token"],
            created_at=doc["created_at"],
            expires_at=doc["expires_at"],
            used=doc.get("used", False),
            used_at=doc.get("used_at"),
            ip_address=doc.get("ip_address"),
            metadata=doc.get("metadata", {}),
        )
