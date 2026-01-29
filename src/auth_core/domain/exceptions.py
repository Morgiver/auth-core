"""
Domain exceptions for auth-core package.

All exceptions are framework-agnostic and represent business rule violations.
"""


class AuthDomainException(Exception):
    """Base exception for all auth domain errors."""

    pass


# Authentication exceptions
class AuthenticationError(AuthDomainException):
    """Raised when authentication fails."""

    pass


class InvalidCredentialsError(AuthenticationError):
    """Raised when email or password is incorrect."""

    pass


class CredentialLockedError(AuthenticationError):
    """Raised when credential account is locked."""

    pass


class CredentialExpiredError(AuthenticationError):
    """Raised when credential has expired."""

    pass


class CredentialDisabledError(AuthenticationError):
    """Raised when credential is disabled."""

    pass


class MFARequiredError(AuthenticationError):
    """Raised when MFA code is required but not provided."""

    pass


class InvalidMFACodeError(AuthenticationError):
    """Raised when MFA code is invalid."""

    pass


# Password exceptions
class PasswordError(AuthDomainException):
    """Base exception for password-related errors."""

    pass


class WeakPasswordError(PasswordError):
    """Raised when password doesn't meet strength requirements."""

    pass


class PasswordMismatchError(PasswordError):
    """Raised when old password doesn't match current password."""

    pass


class PasswordReuseError(PasswordError):
    """Raised when new password matches a recently used password."""

    pass


# Token exceptions
class TokenError(AuthDomainException):
    """Base exception for token-related errors."""

    pass


class InvalidTokenError(TokenError):
    """Raised when token is invalid or malformed."""

    pass


class ExpiredTokenError(TokenError):
    """Raised when token has expired."""

    pass


class RevokedTokenError(TokenError):
    """Raised when token has been revoked."""

    pass


# Session exceptions
class SessionError(AuthDomainException):
    """Base exception for session-related errors."""

    pass


class InvalidSessionError(SessionError):
    """Raised when session is invalid or not found."""

    pass


class ExpiredSessionError(SessionError):
    """Raised when session has expired."""

    pass


# OAuth exceptions
class OAuthError(AuthDomainException):
    """Base exception for OAuth-related errors."""

    pass


class OAuthProviderError(OAuthError):
    """Raised when OAuth provider returns an error."""

    pass


class OAuthAccountNotFoundError(OAuthError):
    """Raised when OAuth account is not found."""

    pass


class OAuthAccountAlreadyLinkedError(OAuthError):
    """Raised when OAuth account is already linked to another user."""

    pass


# Password reset exceptions
class PasswordResetError(AuthDomainException):
    """Base exception for password reset errors."""

    pass


class InvalidPasswordResetTokenError(PasswordResetError):
    """Raised when password reset token is invalid."""

    pass


class ExpiredPasswordResetTokenError(PasswordResetError):
    """Raised when password reset token has expired."""

    pass


class PasswordResetTokenAlreadyUsedError(PasswordResetError):
    """Raised when password reset token has already been used."""

    pass


# MFA exceptions
class MFAError(AuthDomainException):
    """Base exception for MFA-related errors."""

    pass


class MFAAlreadyEnabledError(MFAError):
    """Raised when MFA is already enabled."""

    pass


class MFANotEnabledError(MFAError):
    """Raised when MFA is not enabled."""

    pass


class InvalidMFASecretError(MFAError):
    """Raised when MFA secret is invalid."""

    pass


# Repository exceptions
class RepositoryError(AuthDomainException):
    """Base exception for repository errors."""

    pass


class DuplicateCredentialError(RepositoryError):
    """Raised when attempting to create duplicate credential."""

    pass


class CredentialNotFoundError(RepositoryError):
    """Raised when credential is not found."""

    pass


class SessionNotFoundError(RepositoryError):
    """Raised when session is not found."""

    pass


class TokenNotFoundError(RepositoryError):
    """Raised when token is not found."""

    pass


class OAuthAccountNotFoundInRepoError(RepositoryError):
    """Raised when OAuth account is not found in repository."""

    pass


class PasswordResetRequestNotFoundError(RepositoryError):
    """Raised when password reset request is not found."""

    pass
