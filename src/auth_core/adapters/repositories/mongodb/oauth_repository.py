"""MongoDB implementation of IOAuthRepository."""

import logging
from typing import List, Optional
from uuid import uuid4

from pymongo.database import Database
from pymongo.collection import Collection

from auth_core.domain.models import OAuthAccount, OAuthProvider
from auth_core.interfaces.repository import IOAuthRepository

logger = logging.getLogger(__name__)


class MongoDBOAuthRepository(IOAuthRepository):
    """MongoDB implementation of OAuth repository."""

    def __init__(
        self, database: Database, collection_name: str = "oauth_accounts"
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
        self.collection.create_index([("provider", 1), ("provider_user_id", 1)], unique=True)
        self.collection.create_index("created_at")

    def save(self, oauth_account: OAuthAccount) -> OAuthAccount:
        """Save or update an OAuth account."""
        # Generate ID if needed
        if not oauth_account.id:
            oauth_account.id = str(uuid4())

        doc = self._entity_to_document(oauth_account)

        # Upsert
        self.collection.replace_one(
            {"_id": oauth_account.id}, doc, upsert=True
        )

        logger.debug(f"Saved OAuth account: {oauth_account.id}")
        return oauth_account

    def find_by_id(self, account_id: str) -> Optional[OAuthAccount]:
        """Find OAuth account by ID."""
        doc = self.collection.find_one({"_id": account_id})
        return self._document_to_entity(doc) if doc else None

    def find_by_user_id(
        self, user_id: str, provider: Optional[OAuthProvider] = None
    ) -> List[OAuthAccount]:
        """Find all OAuth accounts for a user, optionally filtered by provider."""
        query = {"user_id": user_id}
        if provider:
            query["provider"] = provider.value

        docs = self.collection.find(query)
        return [self._document_to_entity(doc) for doc in docs]

    def find_by_provider_user_id(
        self, provider: OAuthProvider, provider_user_id: str
    ) -> Optional[OAuthAccount]:
        """Find OAuth account by provider and provider user ID."""
        doc = self.collection.find_one({
            "provider": provider.value,
            "provider_user_id": provider_user_id
        })
        return self._document_to_entity(doc) if doc else None

    def delete(self, account_id: str) -> None:
        """Delete an OAuth account."""
        result = self.collection.delete_one({"_id": account_id})
        if result.deleted_count > 0:
            logger.debug(f"Deleted OAuth account: {account_id}")

    def delete_by_user_id(
        self, user_id: str, provider: Optional[OAuthProvider] = None
    ) -> None:
        """Delete all OAuth accounts for a user, optionally filtered by provider."""
        query = {"user_id": user_id}
        if provider:
            query["provider"] = provider.value

        result = self.collection.delete_many(query)
        logger.debug(f"Deleted {result.deleted_count} OAuth accounts for user: {user_id}")

    def _entity_to_document(self, entity: OAuthAccount) -> dict:
        """Convert domain entity to MongoDB document."""
        return {
            "_id": entity.id,
            "user_id": entity.user_id,
            "provider": entity.provider.value,
            "provider_user_id": entity.provider_user_id,
            "provider_email": entity.provider_email,
            "access_token": entity.access_token,
            "refresh_token": entity.refresh_token,
            "token_expires_at": entity.token_expires_at,
            "created_at": entity.created_at,
            "updated_at": entity.updated_at,
            "metadata": entity.metadata,
        }

    def _document_to_entity(self, doc: dict) -> OAuthAccount:
        """Convert MongoDB document to domain entity."""
        return OAuthAccount(
            id=doc["_id"],
            user_id=doc["user_id"],
            provider=OAuthProvider(doc["provider"]),
            provider_user_id=doc["provider_user_id"],
            provider_email=doc.get("provider_email"),
            access_token=doc.get("access_token"),
            refresh_token=doc.get("refresh_token"),
            token_expires_at=doc.get("token_expires_at"),
            created_at=doc["created_at"],
            updated_at=doc["updated_at"],
            metadata=doc.get("metadata", {}),
        )
