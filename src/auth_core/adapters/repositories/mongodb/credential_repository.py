"""MongoDB implementation of ICredentialRepository."""

import logging
from typing import Optional
from uuid import uuid4

from pymongo.database import Database
from pymongo.collection import Collection
from pymongo.errors import DuplicateKeyError

from auth_core.domain.exceptions import DuplicateCredentialError
from auth_core.domain.models import Credential, CredentialStatus, MFAType
from auth_core.interfaces.repository import ICredentialRepository

logger = logging.getLogger(__name__)


class MongoDBCredentialRepository(ICredentialRepository):
    """MongoDB implementation of credential repository."""

    def __init__(self, database: Database, collection_name: str = "credentials") -> None:
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
        self.collection.create_index("user_id", unique=True)
        self.collection.create_index("created_at")

    def save(self, credential: Credential) -> Credential:
        """Save or update a credential."""
        try:
            # Generate ID if needed
            if not credential.id:
                credential.id = str(uuid4())

            doc = self._entity_to_document(credential)

            # Upsert
            self.collection.replace_one(
                {"_id": credential.id}, doc, upsert=True
            )

            logger.debug(f"Saved credential: {credential.id}")
            return credential

        except DuplicateKeyError:
            logger.error(f"Duplicate credential for user: {credential.user_id}")
            raise DuplicateCredentialError(
                f"Credential for user {credential.user_id} already exists"
            )

    def find_by_id(self, credential_id: str) -> Optional[Credential]:
        """Find credential by ID."""
        doc = self.collection.find_one({"_id": credential_id})
        return self._document_to_entity(doc) if doc else None

    def find_by_user_id(self, user_id: str) -> Optional[Credential]:
        """Find credential by user ID."""
        doc = self.collection.find_one({"user_id": user_id})
        return self._document_to_entity(doc) if doc else None

    def delete(self, credential_id: str) -> None:
        """Delete a credential."""
        result = self.collection.delete_one({"_id": credential_id})
        if result.deleted_count > 0:
            logger.debug(f"Deleted credential: {credential_id}")

    def delete_by_user_id(self, user_id: str) -> None:
        """Delete all credentials for a user."""
        result = self.collection.delete_many({"user_id": user_id})
        logger.debug(f"Deleted {result.deleted_count} credentials for user: {user_id}")

    def _entity_to_document(self, entity: Credential) -> dict:
        """Convert domain entity to MongoDB document."""
        return {
            "_id": entity.id,
            "user_id": entity.user_id,
            "password_hash": entity.password_hash,
            "status": entity.status.value,
            "mfa_enabled": entity.mfa_enabled,
            "mfa_type": entity.mfa_type.value if entity.mfa_type else None,
            "mfa_secret": entity.mfa_secret,
            "backup_codes": entity.backup_codes,
            "failed_login_attempts": entity.failed_login_attempts,
            "last_failed_login": entity.last_failed_login,
            "last_successful_login": entity.last_successful_login,
            "created_at": entity.created_at,
            "updated_at": entity.updated_at,
            "password_changed_at": entity.password_changed_at,
            "metadata": entity.metadata,
        }

    def _document_to_entity(self, doc: dict) -> Credential:
        """Convert MongoDB document to domain entity."""
        return Credential(
            id=doc["_id"],
            user_id=doc["user_id"],
            password_hash=doc["password_hash"],
            status=CredentialStatus(doc["status"]),
            mfa_enabled=doc.get("mfa_enabled", False),
            mfa_type=MFAType(doc["mfa_type"]) if doc.get("mfa_type") else None,
            mfa_secret=doc.get("mfa_secret"),
            backup_codes=doc.get("backup_codes", []),
            failed_login_attempts=doc.get("failed_login_attempts", 0),
            last_failed_login=doc.get("last_failed_login"),
            last_successful_login=doc.get("last_successful_login"),
            created_at=doc["created_at"],
            updated_at=doc["updated_at"],
            password_changed_at=doc.get("password_changed_at"),
            metadata=doc.get("metadata", {}),
        )
