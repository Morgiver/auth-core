"""SQLAlchemy implementation of ICredentialRepository."""

import logging
from typing import Optional
from uuid import uuid4

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from auth_core.domain.exceptions import DuplicateCredentialError
from auth_core.domain.models import Credential, CredentialStatus
from auth_core.interfaces.repository import ICredentialRepository
from .models import CredentialModel

logger = logging.getLogger(__name__)


class SQLAlchemyCredentialRepository(ICredentialRepository):
    """SQLAlchemy implementation of credential repository."""

    def __init__(self, session: Session) -> None:
        """
        Initialize repository with SQLAlchemy session.

        Args:
            session: SQLAlchemy session
        """
        self.session = session

    def save(self, credential: Credential) -> Credential:
        """Save or update a credential."""
        try:
            # Generate ID if needed
            if not credential.id:
                credential.id = str(uuid4())

            # Check if exists
            existing = self.session.query(CredentialModel).filter_by(id=credential.id).first()

            if existing:
                # Update existing
                self._update_model_from_entity(existing, credential)
            else:
                # Create new
                model = self._entity_to_model(credential)
                self.session.add(model)

            self.session.commit()
            logger.debug(f"Saved credential: {credential.id}")
            return credential

        except IntegrityError as e:
            self.session.rollback()
            logger.error(f"Duplicate credential error: {e}")
            raise DuplicateCredentialError(
                f"Credential for user {credential.user_id} already exists"
            )

    def find_by_id(self, credential_id: str) -> Optional[Credential]:
        """Find credential by ID."""
        model = self.session.query(CredentialModel).filter_by(id=credential_id).first()
        return self._model_to_entity(model) if model else None

    def find_by_user_id(self, user_id: str) -> Optional[Credential]:
        """Find credential by user ID."""
        model = self.session.query(CredentialModel).filter_by(user_id=user_id).first()
        return self._model_to_entity(model) if model else None

    def delete(self, credential_id: str) -> None:
        """Delete a credential."""
        model = self.session.query(CredentialModel).filter_by(id=credential_id).first()
        if model:
            self.session.delete(model)
            self.session.commit()
            logger.debug(f"Deleted credential: {credential_id}")

    def delete_by_user_id(self, user_id: str) -> None:
        """Delete all credentials for a user."""
        self.session.query(CredentialModel).filter_by(user_id=user_id).delete()
        self.session.commit()
        logger.debug(f"Deleted credentials for user: {user_id}")

    def _entity_to_model(self, entity: Credential) -> CredentialModel:
        """Convert domain entity to SQLAlchemy model."""
        return CredentialModel(
            id=entity.id,
            user_id=entity.user_id,
            password_hash=entity.password_hash,
            status=entity.status,
            mfa_enabled=entity.mfa_enabled,
            mfa_type=entity.mfa_type,
            mfa_secret=entity.mfa_secret,
            backup_codes=entity.backup_codes,
            failed_login_attempts=entity.failed_login_attempts,
            last_failed_login=entity.last_failed_login,
            last_successful_login=entity.last_successful_login,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
            password_changed_at=entity.password_changed_at,
            metadata_=entity.metadata,
        )

    def _model_to_entity(self, model: CredentialModel) -> Credential:
        """Convert SQLAlchemy model to domain entity."""
        return Credential(
            id=model.id,
            user_id=model.user_id,
            password_hash=model.password_hash,
            status=model.status,
            mfa_enabled=model.mfa_enabled,
            mfa_type=model.mfa_type,
            mfa_secret=model.mfa_secret,
            backup_codes=model.backup_codes or [],
            failed_login_attempts=model.failed_login_attempts,
            last_failed_login=model.last_failed_login,
            last_successful_login=model.last_successful_login,
            created_at=model.created_at,
            updated_at=model.updated_at,
            password_changed_at=model.password_changed_at,
            metadata=model.metadata_ or {},
        )

    def _update_model_from_entity(
        self, model: CredentialModel, entity: Credential
    ) -> None:
        """Update SQLAlchemy model from domain entity."""
        model.user_id = entity.user_id
        model.password_hash = entity.password_hash
        model.status = entity.status
        model.mfa_enabled = entity.mfa_enabled
        model.mfa_type = entity.mfa_type
        model.mfa_secret = entity.mfa_secret
        model.backup_codes = entity.backup_codes
        model.failed_login_attempts = entity.failed_login_attempts
        model.last_failed_login = entity.last_failed_login
        model.last_successful_login = entity.last_successful_login
        model.updated_at = entity.updated_at
        model.password_changed_at = entity.password_changed_at
        model.metadata_ = entity.metadata
