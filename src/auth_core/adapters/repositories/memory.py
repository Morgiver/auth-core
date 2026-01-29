"""
In-memory repository implementations.

These implementations store data in memory (dictionaries) and are useful for:
- Testing
- Development
- Prototyping
- Simple applications that don't need persistence
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from auth_core.domain.exceptions import DuplicateCredentialError
from auth_core.domain.models import (
    Credential,
    OAuthAccount,
    OAuthProvider,
    PasswordResetRequest,
    Session,
    Token,
    TokenType,
)
from auth_core.interfaces.repository import (
    ICredentialRepository,
    IOAuthRepository,
    IPasswordResetRepository,
    ISessionRepository,
    ITokenRepository,
)

logger = logging.getLogger(__name__)


class InMemoryCredentialRepository(ICredentialRepository):
    """In-memory implementation of credential repository."""

    def __init__(self) -> None:
        self._credentials: Dict[str, Credential] = {}
        self._user_index: Dict[str, str] = {}  # user_id -> credential_id

    def save(self, credential: Credential) -> Credential:
        """Save or update a credential."""
        # Check for duplicate user_id (if creating new)
        if not credential.id:
            if credential.user_id in self._user_index:
                raise DuplicateCredentialError(
                    f"Credential for user {credential.user_id} already exists"
                )

        # Generate ID if needed
        if not credential.id:
            credential.id = str(uuid.uuid4())

        # Save credential
        self._credentials[credential.id] = credential
        self._user_index[credential.user_id] = credential.id

        logger.debug(f"Saved credential: {credential.id}")
        return credential

    def find_by_id(self, credential_id: str) -> Optional[Credential]:
        """Find credential by ID."""
        return self._credentials.get(credential_id)

    def find_by_user_id(self, user_id: str) -> Optional[Credential]:
        """Find credential by user ID."""
        credential_id = self._user_index.get(user_id)
        if credential_id:
            return self._credentials.get(credential_id)
        return None

    def delete(self, credential_id: str) -> None:
        """Delete a credential."""
        credential = self._credentials.get(credential_id)
        if credential:
            del self._credentials[credential_id]
            self._user_index.pop(credential.user_id, None)
            logger.debug(f"Deleted credential: {credential_id}")

    def delete_by_user_id(self, user_id: str) -> None:
        """Delete all credentials for a user."""
        credential_id = self._user_index.get(user_id)
        if credential_id:
            self.delete(credential_id)


class InMemorySessionRepository(ISessionRepository):
    """In-memory implementation of session repository."""

    def __init__(self) -> None:
        self._sessions: Dict[str, Session] = {}
        self._user_index: Dict[str, List[str]] = {}  # user_id -> [session_ids]

    def save(self, session: Session) -> Session:
        """Save or update a session."""
        # Generate ID if needed
        if not session.id:
            session.id = str(uuid.uuid4())

        # Save session
        self._sessions[session.id] = session

        # Update user index
        if session.user_id not in self._user_index:
            self._user_index[session.user_id] = []
        if session.id not in self._user_index[session.user_id]:
            self._user_index[session.user_id].append(session.id)

        logger.debug(f"Saved session: {session.id}")
        return session

    def find_by_id(self, session_id: str) -> Optional[Session]:
        """Find session by ID."""
        return self._sessions.get(session_id)

    def find_by_user_id(self, user_id: str) -> List[Session]:
        """Find all sessions for a user."""
        session_ids = self._user_index.get(user_id, [])
        return [self._sessions[sid] for sid in session_ids if sid in self._sessions]

    def delete(self, session_id: str) -> None:
        """Delete a session."""
        session = self._sessions.get(session_id)
        if session:
            del self._sessions[session_id]
            if session.user_id in self._user_index:
                self._user_index[session.user_id].remove(session_id)
            logger.debug(f"Deleted session: {session_id}")

    def delete_by_user_id(self, user_id: str) -> None:
        """Delete all sessions for a user."""
        session_ids = self._user_index.get(user_id, []).copy()
        for session_id in session_ids:
            self.delete(session_id)

    def delete_expired(self) -> int:
        """Delete all expired sessions."""
        now = datetime.utcnow()
        expired_ids = [
            sid for sid, session in self._sessions.items() if session.is_expired()
        ]

        for session_id in expired_ids:
            self.delete(session_id)

        logger.debug(f"Deleted {len(expired_ids)} expired sessions")
        return len(expired_ids)


class InMemoryTokenRepository(ITokenRepository):
    """In-memory implementation of token repository."""

    def __init__(self) -> None:
        self._tokens: Dict[str, Token] = {}
        self._value_index: Dict[str, str] = {}  # token_value -> token_id
        self._user_index: Dict[str, List[str]] = {}  # user_id -> [token_ids]

    def save(self, token: Token) -> Token:
        """Save or update a token."""
        # Generate ID if needed
        if not token.id:
            token.id = str(uuid.uuid4())

        # Save token
        self._tokens[token.id] = token
        self._value_index[token.token_value] = token.id

        # Update user index
        if token.user_id not in self._user_index:
            self._user_index[token.user_id] = []
        if token.id not in self._user_index[token.user_id]:
            self._user_index[token.user_id].append(token.id)

        logger.debug(f"Saved token: {token.id}")
        return token

    def find_by_id(self, token_id: str) -> Optional[Token]:
        """Find token by ID."""
        return self._tokens.get(token_id)

    def find_by_value(self, token_value: str) -> Optional[Token]:
        """Find token by its value."""
        token_id = self._value_index.get(token_value)
        if token_id:
            return self._tokens.get(token_id)
        return None

    def find_by_user_id(
        self, user_id: str, token_type: Optional[TokenType] = None
    ) -> List[Token]:
        """Find all tokens for a user, optionally filtered by type."""
        token_ids = self._user_index.get(user_id, [])
        tokens = [self._tokens[tid] for tid in token_ids if tid in self._tokens]

        if token_type:
            tokens = [t for t in tokens if t.token_type == token_type]

        return tokens

    def delete(self, token_id: str) -> None:
        """Delete a token."""
        token = self._tokens.get(token_id)
        if token:
            del self._tokens[token_id]
            self._value_index.pop(token.token_value, None)
            if token.user_id in self._user_index:
                self._user_index[token.user_id].remove(token_id)
            logger.debug(f"Deleted token: {token_id}")

    def delete_by_user_id(
        self, user_id: str, token_type: Optional[TokenType] = None
    ) -> None:
        """Delete all tokens for a user, optionally filtered by type."""
        tokens = self.find_by_user_id(user_id, token_type)
        for token in tokens:
            if token.id:
                self.delete(token.id)

    def delete_expired(self) -> int:
        """Delete all expired tokens."""
        now = datetime.utcnow()
        expired_ids = [tid for tid, token in self._tokens.items() if token.is_expired()]

        for token_id in expired_ids:
            self.delete(token_id)

        logger.debug(f"Deleted {len(expired_ids)} expired tokens")
        return len(expired_ids)


class InMemoryOAuthRepository(IOAuthRepository):
    """In-memory implementation of OAuth repository."""

    def __init__(self) -> None:
        self._accounts: Dict[str, OAuthAccount] = {}
        self._user_index: Dict[str, List[str]] = {}  # user_id -> [oauth_ids]
        self._provider_index: Dict[tuple, str] = {}  # (provider, provider_user_id) -> oauth_id

    def save(self, oauth_account: OAuthAccount) -> OAuthAccount:
        """Save or update an OAuth account."""
        # Generate ID if needed
        if not oauth_account.id:
            oauth_account.id = str(uuid.uuid4())

        # Save account
        self._accounts[oauth_account.id] = oauth_account
        self._provider_index[
            (oauth_account.provider, oauth_account.provider_user_id)
        ] = oauth_account.id

        # Update user index
        if oauth_account.user_id not in self._user_index:
            self._user_index[oauth_account.user_id] = []
        if oauth_account.id not in self._user_index[oauth_account.user_id]:
            self._user_index[oauth_account.user_id].append(oauth_account.id)

        logger.debug(f"Saved OAuth account: {oauth_account.id}")
        return oauth_account

    def find_by_id(self, oauth_id: str) -> Optional[OAuthAccount]:
        """Find OAuth account by ID."""
        return self._accounts.get(oauth_id)

    def find_by_user_id(self, user_id: str) -> List[OAuthAccount]:
        """Find all OAuth accounts for a user."""
        oauth_ids = self._user_index.get(user_id, [])
        return [self._accounts[oid] for oid in oauth_ids if oid in self._accounts]

    def find_by_provider_and_user(
        self, provider: OAuthProvider, provider_user_id: str
    ) -> Optional[OAuthAccount]:
        """Find OAuth account by provider and provider user ID."""
        oauth_id = self._provider_index.get((provider, provider_user_id))
        if oauth_id:
            return self._accounts.get(oauth_id)
        return None

    def delete(self, oauth_id: str) -> None:
        """Delete an OAuth account."""
        account = self._accounts.get(oauth_id)
        if account:
            del self._accounts[oauth_id]
            self._provider_index.pop((account.provider, account.provider_user_id), None)
            if account.user_id in self._user_index:
                self._user_index[account.user_id].remove(oauth_id)
            logger.debug(f"Deleted OAuth account: {oauth_id}")

    def delete_by_user_id(self, user_id: str) -> None:
        """Delete all OAuth accounts for a user."""
        oauth_ids = self._user_index.get(user_id, []).copy()
        for oauth_id in oauth_ids:
            self.delete(oauth_id)


class InMemoryPasswordResetRepository(IPasswordResetRepository):
    """In-memory implementation of password reset repository."""

    def __init__(self) -> None:
        self._requests: Dict[str, PasswordResetRequest] = {}
        self._token_index: Dict[str, str] = {}  # token -> request_id
        self._user_index: Dict[str, List[str]] = {}  # user_id -> [request_ids]

    def save(self, request: PasswordResetRequest) -> PasswordResetRequest:
        """Save or update a password reset request."""
        # Generate ID if needed
        if not request.id:
            request.id = str(uuid.uuid4())

        # Save request
        self._requests[request.id] = request
        self._token_index[request.token] = request.id

        # Update user index
        if request.user_id not in self._user_index:
            self._user_index[request.user_id] = []
        if request.id not in self._user_index[request.user_id]:
            self._user_index[request.user_id].append(request.id)

        logger.debug(f"Saved password reset request: {request.id}")
        return request

    def find_by_id(self, request_id: str) -> Optional[PasswordResetRequest]:
        """Find password reset request by ID."""
        return self._requests.get(request_id)

    def find_by_token(self, token: str) -> Optional[PasswordResetRequest]:
        """Find password reset request by token."""
        request_id = self._token_index.get(token)
        if request_id:
            return self._requests.get(request_id)
        return None

    def find_by_user_id(self, user_id: str) -> List[PasswordResetRequest]:
        """Find all password reset requests for a user."""
        request_ids = self._user_index.get(user_id, [])
        return [self._requests[rid] for rid in request_ids if rid in self._requests]

    def delete(self, request_id: str) -> None:
        """Delete a password reset request."""
        request = self._requests.get(request_id)
        if request:
            del self._requests[request_id]
            self._token_index.pop(request.token, None)
            if request.user_id in self._user_index:
                self._user_index[request.user_id].remove(request_id)
            logger.debug(f"Deleted password reset request: {request_id}")

    def delete_by_user_id(self, user_id: str) -> None:
        """Delete all password reset requests for a user."""
        request_ids = self._user_index.get(user_id, []).copy()
        for request_id in request_ids:
            self.delete(request_id)

    def delete_expired(self) -> int:
        """Delete all expired reset requests."""
        now = datetime.utcnow()
        expired_ids = [
            rid for rid, request in self._requests.items() if request.is_expired()
        ]

        for request_id in expired_ids:
            self.delete(request_id)

        logger.debug(f"Deleted {len(expired_ids)} expired password reset requests")
        return len(expired_ids)
