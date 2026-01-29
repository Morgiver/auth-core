"""
OAuth provider interface for auth-core package.

Defines the contract for OAuth provider implementations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class OAuthUserInfo:
    """User information returned from OAuth provider."""

    provider_user_id: str
    email: Optional[str] = None
    username: Optional[str] = None
    name: Optional[str] = None
    avatar_url: Optional[str] = None
    raw_data: Optional[Dict] = None


@dataclass
class OAuthTokens:
    """OAuth tokens returned from provider."""

    access_token: str
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    token_type: str = "Bearer"


class IOAuthProvider(ABC):
    """Abstract interface for OAuth providers."""

    @abstractmethod
    def get_authorization_url(self, redirect_uri: str, state: str) -> str:
        """
        Get the authorization URL for the OAuth flow.

        Args:
            redirect_uri: The redirect URI after authorization
            state: CSRF protection state parameter

        Returns:
            The authorization URL
        """
        pass

    @abstractmethod
    def exchange_code_for_tokens(self, code: str, redirect_uri: str) -> OAuthTokens:
        """
        Exchange authorization code for access tokens.

        Args:
            code: The authorization code
            redirect_uri: The redirect URI (must match the one used in authorization)

        Returns:
            OAuth tokens

        Raises:
            OAuthProviderError: If token exchange fails
        """
        pass

    @abstractmethod
    def get_user_info(self, access_token: str) -> OAuthUserInfo:
        """
        Get user information from the OAuth provider.

        Args:
            access_token: The access token

        Returns:
            User information

        Raises:
            OAuthProviderError: If user info retrieval fails
        """
        pass

    @abstractmethod
    def refresh_token(self, refresh_token: str) -> OAuthTokens:
        """
        Refresh an access token.

        Args:
            refresh_token: The refresh token

        Returns:
            New OAuth tokens

        Raises:
            OAuthProviderError: If token refresh fails
        """
        pass
