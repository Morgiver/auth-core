"""SQLAlchemy implementation of ITokenRepository."""

import logging
from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from auth_core.domain.models import Token, TokenType
from auth_core.interfaces.repository import ITokenRepository
from .models import TokenModel

logger = logging.getLogger(__name__)


class SQLAlchemyTokenRepository(ITokenRepository):
    """SQLAlchemy implementation of token repository."""

    def __init__(self, session: Session) -> None:
        """
        Initialize repository with SQLAlchemy session.

        Args:
            session: SQLAlchemy session
        """
        self.session = session

    def save(self, token: Token) -> Token:
        """Save or update a token."""
        # Generate ID if needed
        if not token.id:
            token.id = str(uuid4())

        # Check if exists
        existing = self.session.query(TokenModel).filter_by(id=token.id).first()

        if existing:
            # Update existing
            self._update_model_from_entity(existing, token)
        else:
            # Create new
            model = self._entity_to_model(token)
            self.session.add(model)

        self.session.commit()
        logger.debug(f"Saved token: {token.id}")
        return token

    def find_by_id(self, token_id: str) -> Optional[Token]:
        """Find token by ID."""
        model = self.session.query(TokenModel).filter_by(id=token_id).first()
        return self._model_to_entity(model) if model else None

    def find_by_value(self, token_value: str) -> Optional[Token]:
        """Find token by value."""
        model = self.session.query(TokenModel).filter_by(token_value=token_value).first()
        return self._model_to_entity(model) if model else None

    def find_by_user_id(
        self, user_id: str, token_type: Optional[TokenType] = None
    ) -> List[Token]:
        """Find all tokens for a user, optionally filtered by type."""
        query = self.session.query(TokenModel).filter_by(user_id=user_id)

        if token_type:
            query = query.filter_by(token_type=token_type)

        models = query.all()
        return [self._model_to_entity(m) for m in models]

    def delete(self, token_id: str) -> None:
        """Delete a token."""
        model = self.session.query(TokenModel).filter_by(id=token_id).first()
        if model:
            self.session.delete(model)
            self.session.commit()
            logger.debug(f"Deleted token: {token_id}")

    def delete_by_user_id(self, user_id: str) -> None:
        """Delete all tokens for a user."""
        self.session.query(TokenModel).filter_by(user_id=user_id).delete()
        self.session.commit()
        logger.debug(f"Deleted all tokens for user: {user_id}")

    def delete_expired(self, before: datetime) -> int:
        """Delete all expired tokens."""
        count = (
            self.session.query(TokenModel)
            .filter(TokenModel.expires_at < before)
            .delete()
        )
        self.session.commit()
        logger.debug(f"Deleted {count} expired tokens")
        return count

    def _entity_to_model(self, entity: Token) -> TokenModel:
        """Convert domain entity to SQLAlchemy model."""
        return TokenModel(
            id=entity.id,
            user_id=entity.user_id,
            token_type=entity.token_type,
            token_value=entity.token_value,
            created_at=entity.created_at,
            expires_at=entity.expires_at,
            revoked=entity.revoked,
            revoked_at=entity.revoked_at,
            metadata_=entity.metadata,
        )

    def _model_to_entity(self, model: TokenModel) -> Token:
        """Convert SQLAlchemy model to domain entity."""
        return Token(
            id=model.id,
            user_id=model.user_id,
            token_type=model.token_type,
            token_value=model.token_value,
            created_at=model.created_at,
            expires_at=model.expires_at,
            revoked=model.revoked,
            revoked_at=model.revoked_at,
            metadata=model.metadata_ or {},
        )

    def _update_model_from_entity(self, model: TokenModel, entity: Token) -> None:
        """Update SQLAlchemy model from domain entity."""
        model.user_id = entity.user_id
        model.token_type = entity.token_type
        model.token_value = entity.token_value
        model.expires_at = entity.expires_at
        model.revoked = entity.revoked
        model.revoked_at = entity.revoked_at
        model.metadata_ = entity.metadata
