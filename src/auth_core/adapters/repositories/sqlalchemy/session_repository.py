"""SQLAlchemy implementation of ISessionRepository."""

import logging
from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from sqlalchemy.orm import Session as DBSession

from auth_core.domain.models import Session
from auth_core.interfaces.repository import ISessionRepository
from .models import SessionModel

logger = logging.getLogger(__name__)


class SQLAlchemySessionRepository(ISessionRepository):
    """SQLAlchemy implementation of session repository."""

    def __init__(self, db_session: DBSession) -> None:
        """
        Initialize repository with SQLAlchemy session.

        Args:
            db_session: SQLAlchemy session
        """
        self.db_session = db_session

    def save(self, session: Session) -> Session:
        """Save or update a session."""
        # Generate ID if needed
        if not session.id:
            session.id = str(uuid4())

        # Check if exists
        existing = self.db_session.query(SessionModel).filter_by(id=session.id).first()

        if existing:
            # Update existing
            self._update_model_from_entity(existing, session)
        else:
            # Create new
            model = self._entity_to_model(session)
            self.db_session.add(model)

        self.db_session.commit()
        logger.debug(f"Saved session: {session.id}")
        return session

    def find_by_id(self, session_id: str) -> Optional[Session]:
        """Find session by ID."""
        model = self.db_session.query(SessionModel).filter_by(id=session_id).first()
        return self._model_to_entity(model) if model else None

    def find_by_user_id(self, user_id: str) -> List[Session]:
        """Find all sessions for a user."""
        models = self.db_session.query(SessionModel).filter_by(user_id=user_id).all()
        return [self._model_to_entity(m) for m in models]

    def delete(self, session_id: str) -> None:
        """Delete a session."""
        model = self.db_session.query(SessionModel).filter_by(id=session_id).first()
        if model:
            self.db_session.delete(model)
            self.db_session.commit()
            logger.debug(f"Deleted session: {session_id}")

    def delete_by_user_id(self, user_id: str) -> None:
        """Delete all sessions for a user."""
        self.db_session.query(SessionModel).filter_by(user_id=user_id).delete()
        self.db_session.commit()
        logger.debug(f"Deleted all sessions for user: {user_id}")

    def delete_expired(self, before: datetime) -> int:
        """Delete all expired sessions."""
        count = (
            self.db_session.query(SessionModel)
            .filter(SessionModel.expires_at < before)
            .delete()
        )
        self.db_session.commit()
        logger.debug(f"Deleted {count} expired sessions")
        return count

    def _entity_to_model(self, entity: Session) -> SessionModel:
        """Convert domain entity to SQLAlchemy model."""
        return SessionModel(
            id=entity.id,
            user_id=entity.user_id,
            created_at=entity.created_at,
            expires_at=entity.expires_at,
            last_activity_at=entity.last_activity_at,
            ip_address=entity.ip_address,
            user_agent=entity.user_agent,
            revoked=entity.revoked,
            metadata_=entity.metadata,
        )

    def _model_to_entity(self, model: SessionModel) -> Session:
        """Convert SQLAlchemy model to domain entity."""
        return Session(
            id=model.id,
            user_id=model.user_id,
            created_at=model.created_at,
            expires_at=model.expires_at,
            last_activity_at=model.last_activity_at,
            ip_address=model.ip_address,
            user_agent=model.user_agent,
            revoked=model.revoked,
            metadata=model.metadata_ or {},
        )

    def _update_model_from_entity(self, model: SessionModel, entity: Session) -> None:
        """Update SQLAlchemy model from domain entity."""
        model.user_id = entity.user_id
        model.expires_at = entity.expires_at
        model.last_activity_at = entity.last_activity_at
        model.ip_address = entity.ip_address
        model.user_agent = entity.user_agent
        model.revoked = entity.revoked
        model.metadata_ = entity.metadata
