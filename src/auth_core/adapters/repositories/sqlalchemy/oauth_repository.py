"""SQLAlchemy implementation of IOAuthRepository."""

import logging
from typing import List, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from auth_core.domain.models import OAuthAccount, OAuthProvider
from auth_core.interfaces.repository import IOAuthRepository
from .models import OAuthAccountModel

logger = logging.getLogger(__name__)


class SQLAlchemyOAuthRepository(IOAuthRepository):
    """SQLAlchemy implementation of OAuth repository."""

    def __init__(self, session: Session) -> None:
        """
        Initialize repository with SQLAlchemy session.

        Args:
            session: SQLAlchemy session
        """
        self.session = session

    def save(self, oauth_account: OAuthAccount) -> OAuthAccount:
        """Save or update an OAuth account."""
        # Generate ID if needed
        if not oauth_account.id:
            oauth_account.id = str(uuid4())

        # Check if exists
        existing = (
            self.session.query(OAuthAccountModel)
            .filter_by(id=oauth_account.id)
            .first()
        )

        if existing:
            # Update existing
            self._update_model_from_entity(existing, oauth_account)
        else:
            # Create new
            model = self._entity_to_model(oauth_account)
            self.session.add(model)

        self.session.commit()
        logger.debug(f"Saved OAuth account: {oauth_account.id}")
        return oauth_account

    def find_by_id(self, account_id: str) -> Optional[OAuthAccount]:
        """Find OAuth account by ID."""
        model = (
            self.session.query(OAuthAccountModel).filter_by(id=account_id).first()
        )
        return self._model_to_entity(model) if model else None

    def find_by_user_id(
        self, user_id: str, provider: Optional[OAuthProvider] = None
    ) -> List[OAuthAccount]:
        """Find all OAuth accounts for a user, optionally filtered by provider."""
        query = self.session.query(OAuthAccountModel).filter_by(user_id=user_id)

        if provider:
            query = query.filter_by(provider=provider)

        models = query.all()
        return [self._model_to_entity(m) for m in models]

    def find_by_provider_user_id(
        self, provider: OAuthProvider, provider_user_id: str
    ) -> Optional[OAuthAccount]:
        """Find OAuth account by provider and provider user ID."""
        model = (
            self.session.query(OAuthAccountModel)
            .filter_by(provider=provider, provider_user_id=provider_user_id)
            .first()
        )
        return self._model_to_entity(model) if model else None

    def delete(self, account_id: str) -> None:
        """Delete an OAuth account."""
        model = (
            self.session.query(OAuthAccountModel).filter_by(id=account_id).first()
        )
        if model:
            self.session.delete(model)
            self.session.commit()
            logger.debug(f"Deleted OAuth account: {account_id}")

    def delete_by_user_id(self, user_id: str, provider: Optional[OAuthProvider] = None) -> None:
        """Delete all OAuth accounts for a user, optionally filtered by provider."""
        query = self.session.query(OAuthAccountModel).filter_by(user_id=user_id)

        if provider:
            query = query.filter_by(provider=provider)

        query.delete()
        self.session.commit()
        logger.debug(f"Deleted OAuth accounts for user: {user_id}")

    def _entity_to_model(self, entity: OAuthAccount) -> OAuthAccountModel:
        """Convert domain entity to SQLAlchemy model."""
        return OAuthAccountModel(
            id=entity.id,
            user_id=entity.user_id,
            provider=entity.provider,
            provider_user_id=entity.provider_user_id,
            provider_email=entity.provider_email,
            access_token=entity.access_token,
            refresh_token=entity.refresh_token,
            token_expires_at=entity.token_expires_at,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
            metadata_=entity.metadata,
        )

    def _model_to_entity(self, model: OAuthAccountModel) -> OAuthAccount:
        """Convert SQLAlchemy model to domain entity."""
        return OAuthAccount(
            id=model.id,
            user_id=model.user_id,
            provider=model.provider,
            provider_user_id=model.provider_user_id,
            provider_email=model.provider_email,
            access_token=model.access_token,
            refresh_token=model.refresh_token,
            token_expires_at=model.token_expires_at,
            created_at=model.created_at,
            updated_at=model.updated_at,
            metadata=model.metadata_ or {},
        )

    def _update_model_from_entity(
        self, model: OAuthAccountModel, entity: OAuthAccount
    ) -> None:
        """Update SQLAlchemy model from domain entity."""
        model.user_id = entity.user_id
        model.provider = entity.provider
        model.provider_user_id = entity.provider_user_id
        model.provider_email = entity.provider_email
        model.access_token = entity.access_token
        model.refresh_token = entity.refresh_token
        model.token_expires_at = entity.token_expires_at
        model.updated_at = entity.updated_at
        model.metadata_ = entity.metadata
