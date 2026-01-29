"""SQLAlchemy implementation of IPasswordResetRepository."""

import logging
from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from auth_core.domain.models import PasswordResetRequest
from auth_core.interfaces.repository import IPasswordResetRepository
from .models import PasswordResetRequestModel

logger = logging.getLogger(__name__)


class SQLAlchemyPasswordResetRepository(IPasswordResetRepository):
    """SQLAlchemy implementation of password reset repository."""

    def __init__(self, session: Session) -> None:
        """
        Initialize repository with SQLAlchemy session.

        Args:
            session: SQLAlchemy session
        """
        self.session = session

    def save(self, reset_request: PasswordResetRequest) -> PasswordResetRequest:
        """Save or update a password reset request."""
        # Generate ID if needed
        if not reset_request.id:
            reset_request.id = str(uuid4())

        # Check if exists
        existing = (
            self.session.query(PasswordResetRequestModel)
            .filter_by(id=reset_request.id)
            .first()
        )

        if existing:
            # Update existing
            self._update_model_from_entity(existing, reset_request)
        else:
            # Create new
            model = self._entity_to_model(reset_request)
            self.session.add(model)

        self.session.commit()
        logger.debug(f"Saved password reset request: {reset_request.id}")
        return reset_request

    def find_by_id(self, request_id: str) -> Optional[PasswordResetRequest]:
        """Find password reset request by ID."""
        model = (
            self.session.query(PasswordResetRequestModel)
            .filter_by(id=request_id)
            .first()
        )
        return self._model_to_entity(model) if model else None

    def find_by_token(self, token: str) -> Optional[PasswordResetRequest]:
        """Find password reset request by token."""
        model = (
            self.session.query(PasswordResetRequestModel).filter_by(token=token).first()
        )
        return self._model_to_entity(model) if model else None

    def find_by_user_id(self, user_id: str) -> List[PasswordResetRequest]:
        """Find all password reset requests for a user."""
        models = (
            self.session.query(PasswordResetRequestModel)
            .filter_by(user_id=user_id)
            .all()
        )
        return [self._model_to_entity(m) for m in models]

    def delete(self, request_id: str) -> None:
        """Delete a password reset request."""
        model = (
            self.session.query(PasswordResetRequestModel)
            .filter_by(id=request_id)
            .first()
        )
        if model:
            self.session.delete(model)
            self.session.commit()
            logger.debug(f"Deleted password reset request: {request_id}")

    def delete_by_user_id(self, user_id: str) -> None:
        """Delete all password reset requests for a user."""
        self.session.query(PasswordResetRequestModel).filter_by(
            user_id=user_id
        ).delete()
        self.session.commit()
        logger.debug(f"Deleted all password reset requests for user: {user_id}")

    def delete_expired(self, before: datetime) -> int:
        """Delete all expired password reset requests."""
        count = (
            self.session.query(PasswordResetRequestModel)
            .filter(PasswordResetRequestModel.expires_at < before)
            .delete()
        )
        self.session.commit()
        logger.debug(f"Deleted {count} expired password reset requests")
        return count

    def _entity_to_model(
        self, entity: PasswordResetRequest
    ) -> PasswordResetRequestModel:
        """Convert domain entity to SQLAlchemy model."""
        return PasswordResetRequestModel(
            id=entity.id,
            user_id=entity.user_id,
            token=entity.token,
            created_at=entity.created_at,
            expires_at=entity.expires_at,
            used=entity.used,
            used_at=entity.used_at,
            ip_address=entity.ip_address,
            metadata_=entity.metadata,
        )

    def _model_to_entity(self, model: PasswordResetRequestModel) -> PasswordResetRequest:
        """Convert SQLAlchemy model to domain entity."""
        return PasswordResetRequest(
            id=model.id,
            user_id=model.user_id,
            token=model.token,
            created_at=model.created_at,
            expires_at=model.expires_at,
            used=model.used,
            used_at=model.used_at,
            ip_address=model.ip_address,
            metadata=model.metadata_ or {},
        )

    def _update_model_from_entity(
        self, model: PasswordResetRequestModel, entity: PasswordResetRequest
    ) -> None:
        """Update SQLAlchemy model from domain entity."""
        model.user_id = entity.user_id
        model.token = entity.token
        model.expires_at = entity.expires_at
        model.used = entity.used
        model.used_at = entity.used_at
        model.ip_address = entity.ip_address
        model.metadata_ = entity.metadata
