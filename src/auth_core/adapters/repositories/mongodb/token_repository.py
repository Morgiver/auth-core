"""MongoDB implementation of ITokenRepository."""

import logging
from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from pymongo.database import Database
from pymongo.collection import Collection

from auth_core.domain.models import Token, TokenType
from auth_core.interfaces.repository import ITokenRepository

logger = logging.getLogger(__name__)


class MongoDBTokenRepository(ITokenRepository):
    """MongoDB implementation of token repository."""

    def __init__(self, database: Database, collection_name: str = "tokens") -> None:
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
        self.collection.create_index("token_value", unique=True)
        self.collection.create_index("token_type")
        self.collection.create_index("expires_at")
        self.collection.create_index("created_at")

    def save(self, token: Token) -> Token:
        """Save or update a token."""
        # Generate ID if needed
        if not token.id:
            token.id = str(uuid4())

        doc = self._entity_to_document(token)

        # Upsert
        self.collection.replace_one(
            {"_id": token.id}, doc, upsert=True
        )

        logger.debug(f"Saved token: {token.id}")
        return token

    def find_by_id(self, token_id: str) -> Optional[Token]:
        """Find token by ID."""
        doc = self.collection.find_one({"_id": token_id})
        return self._document_to_entity(doc) if doc else None

    def find_by_value(self, token_value: str) -> Optional[Token]:
        """Find token by value."""
        doc = self.collection.find_one({"token_value": token_value})
        return self._document_to_entity(doc) if doc else None

    def find_by_user_id(
        self, user_id: str, token_type: Optional[TokenType] = None
    ) -> List[Token]:
        """Find all tokens for a user, optionally filtered by type."""
        query = {"user_id": user_id}
        if token_type:
            query["token_type"] = token_type.value

        docs = self.collection.find(query)
        return [self._document_to_entity(doc) for doc in docs]

    def delete(self, token_id: str) -> None:
        """Delete a token."""
        result = self.collection.delete_one({"_id": token_id})
        if result.deleted_count > 0:
            logger.debug(f"Deleted token: {token_id}")

    def delete_by_user_id(self, user_id: str) -> None:
        """Delete all tokens for a user."""
        result = self.collection.delete_many({"user_id": user_id})
        logger.debug(f"Deleted {result.deleted_count} tokens for user: {user_id}")

    def delete_expired(self, before: datetime) -> int:
        """Delete all expired tokens."""
        result = self.collection.delete_many({"expires_at": {"$lt": before}})
        count = result.deleted_count
        logger.debug(f"Deleted {count} expired tokens")
        return count

    def _entity_to_document(self, entity: Token) -> dict:
        """Convert domain entity to MongoDB document."""
        return {
            "_id": entity.id,
            "user_id": entity.user_id,
            "token_type": entity.token_type.value,
            "token_value": entity.token_value,
            "created_at": entity.created_at,
            "expires_at": entity.expires_at,
            "revoked": entity.revoked,
            "revoked_at": entity.revoked_at,
            "metadata": entity.metadata,
        }

    def _document_to_entity(self, doc: dict) -> Token:
        """Convert MongoDB document to domain entity."""
        return Token(
            id=doc["_id"],
            user_id=doc["user_id"],
            token_type=TokenType(doc["token_type"]),
            token_value=doc["token_value"],
            created_at=doc["created_at"],
            expires_at=doc.get("expires_at"),
            revoked=doc.get("revoked", False),
            revoked_at=doc.get("revoked_at"),
            metadata=doc.get("metadata", {}),
        )
