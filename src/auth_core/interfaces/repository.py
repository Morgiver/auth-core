"""
Repository interfaces for auth-core package.

These are abstract contracts that define how to persist and retrieve domain entities.
Concrete implementations will be provided in the adapters layer.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from auth_core.domain.models import (
    Credential,
    OAuthAccount,
    OAuthProvider,
    PasswordResetRequest,
    Session,
    Token,
    TokenType,
)


class ICredentialRepository(ABC):
    """Abstract interface for credential persistence."""

    @abstractmethod
    def save(self, credential: Credential) -> Credential:
        """
        Save or update a credential.

        Args:
            credential: The credential to save

        Returns:
            The saved credential with ID populated

        Raises:
            DuplicateCredentialError: If credential with same email already exists
        """
        pass

    @abstractmethod
    def find_by_id(self, credential_id: str) -> Optional[Credential]:
        """
        Find credential by ID.

        Args:
            credential_id: The credential ID

        Returns:
            The credential if found, None otherwise
        """
        pass

    @abstractmethod
    def find_by_user_id(self, user_id: str) -> Optional[Credential]:
        """
        Find credential by user ID.

        Args:
            user_id: The user ID

        Returns:
            The credential if found, None otherwise
        """
        pass

    @abstractmethod
    def delete(self, credential_id: str) -> None:
        """
        Delete a credential.

        Args:
            credential_id: The credential ID to delete
        """
        pass

    @abstractmethod
    def delete_by_user_id(self, user_id: str) -> None:
        """
        Delete all credentials for a user.

        Args:
            user_id: The user ID
        """
        pass


class ISessionRepository(ABC):
    """Abstract interface for session persistence."""

    @abstractmethod
    def save(self, session: Session) -> Session:
        """
        Save or update a session.

        Args:
            session: The session to save

        Returns:
            The saved session with ID populated
        """
        pass

    @abstractmethod
    def find_by_id(self, session_id: str) -> Optional[Session]:
        """
        Find session by ID.

        Args:
            session_id: The session ID

        Returns:
            The session if found, None otherwise
        """
        pass

    @abstractmethod
    def find_by_user_id(self, user_id: str) -> List[Session]:
        """
        Find all sessions for a user.

        Args:
            user_id: The user ID

        Returns:
            List of sessions
        """
        pass

    @abstractmethod
    def delete(self, session_id: str) -> None:
        """
        Delete a session.

        Args:
            session_id: The session ID to delete
        """
        pass

    @abstractmethod
    def delete_by_user_id(self, user_id: str) -> None:
        """
        Delete all sessions for a user.

        Args:
            user_id: The user ID
        """
        pass

    @abstractmethod
    def delete_expired(self) -> int:
        """
        Delete all expired sessions.

        Returns:
            Number of sessions deleted
        """
        pass


class ITokenRepository(ABC):
    """Abstract interface for token persistence."""

    @abstractmethod
    def save(self, token: Token) -> Token:
        """
        Save or update a token.

        Args:
            token: The token to save

        Returns:
            The saved token with ID populated
        """
        pass

    @abstractmethod
    def find_by_id(self, token_id: str) -> Optional[Token]:
        """
        Find token by ID.

        Args:
            token_id: The token ID

        Returns:
            The token if found, None otherwise
        """
        pass

    @abstractmethod
    def find_by_value(self, token_value: str) -> Optional[Token]:
        """
        Find token by its value.

        Args:
            token_value: The token value

        Returns:
            The token if found, None otherwise
        """
        pass

    @abstractmethod
    def find_by_user_id(
        self, user_id: str, token_type: Optional[TokenType] = None
    ) -> List[Token]:
        """
        Find all tokens for a user, optionally filtered by type.

        Args:
            user_id: The user ID
            token_type: Optional token type filter

        Returns:
            List of tokens
        """
        pass

    @abstractmethod
    def delete(self, token_id: str) -> None:
        """
        Delete a token.

        Args:
            token_id: The token ID to delete
        """
        pass

    @abstractmethod
    def delete_by_user_id(
        self, user_id: str, token_type: Optional[TokenType] = None
    ) -> None:
        """
        Delete all tokens for a user, optionally filtered by type.

        Args:
            user_id: The user ID
            token_type: Optional token type filter
        """
        pass

    @abstractmethod
    def delete_expired(self) -> int:
        """
        Delete all expired tokens.

        Returns:
            Number of tokens deleted
        """
        pass


class IOAuthRepository(ABC):
    """Abstract interface for OAuth account persistence."""

    @abstractmethod
    def save(self, oauth_account: OAuthAccount) -> OAuthAccount:
        """
        Save or update an OAuth account.

        Args:
            oauth_account: The OAuth account to save

        Returns:
            The saved OAuth account with ID populated
        """
        pass

    @abstractmethod
    def find_by_id(self, oauth_id: str) -> Optional[OAuthAccount]:
        """
        Find OAuth account by ID.

        Args:
            oauth_id: The OAuth account ID

        Returns:
            The OAuth account if found, None otherwise
        """
        pass

    @abstractmethod
    def find_by_user_id(self, user_id: str) -> List[OAuthAccount]:
        """
        Find all OAuth accounts for a user.

        Args:
            user_id: The user ID

        Returns:
            List of OAuth accounts
        """
        pass

    @abstractmethod
    def find_by_provider_and_user(
        self, provider: OAuthProvider, provider_user_id: str
    ) -> Optional[OAuthAccount]:
        """
        Find OAuth account by provider and provider user ID.

        Args:
            provider: The OAuth provider
            provider_user_id: The user ID from the provider

        Returns:
            The OAuth account if found, None otherwise
        """
        pass

    @abstractmethod
    def delete(self, oauth_id: str) -> None:
        """
        Delete an OAuth account.

        Args:
            oauth_id: The OAuth account ID to delete
        """
        pass

    @abstractmethod
    def delete_by_user_id(self, user_id: str) -> None:
        """
        Delete all OAuth accounts for a user.

        Args:
            user_id: The user ID
        """
        pass


class IPasswordResetRepository(ABC):
    """Abstract interface for password reset request persistence."""

    @abstractmethod
    def save(self, request: PasswordResetRequest) -> PasswordResetRequest:
        """
        Save or update a password reset request.

        Args:
            request: The password reset request to save

        Returns:
            The saved request with ID populated
        """
        pass

    @abstractmethod
    def find_by_id(self, request_id: str) -> Optional[PasswordResetRequest]:
        """
        Find password reset request by ID.

        Args:
            request_id: The request ID

        Returns:
            The request if found, None otherwise
        """
        pass

    @abstractmethod
    def find_by_token(self, token: str) -> Optional[PasswordResetRequest]:
        """
        Find password reset request by token.

        Args:
            token: The reset token

        Returns:
            The request if found, None otherwise
        """
        pass

    @abstractmethod
    def find_by_user_id(self, user_id: str) -> List[PasswordResetRequest]:
        """
        Find all password reset requests for a user.

        Args:
            user_id: The user ID

        Returns:
            List of reset requests
        """
        pass

    @abstractmethod
    def delete(self, request_id: str) -> None:
        """
        Delete a password reset request.

        Args:
            request_id: The request ID to delete
        """
        pass

    @abstractmethod
    def delete_by_user_id(self, user_id: str) -> None:
        """
        Delete all password reset requests for a user.

        Args:
            user_id: The user ID
        """
        pass

    @abstractmethod
    def delete_expired(self) -> int:
        """
        Delete all expired reset requests.

        Returns:
            Number of requests deleted
        """
        pass
