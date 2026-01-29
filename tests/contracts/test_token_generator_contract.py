"""
Contract tests for ITokenGenerator.

All token generator implementations must pass these tests.
"""

import pytest
from datetime import timedelta

from auth_core.domain.exceptions import InvalidTokenError, ExpiredTokenError


class TokenGeneratorContractTests:
    """Base test class that ALL token generator implementations must pass."""

    @pytest.fixture
    def generator(self):
        """Subclasses must provide generator implementation."""
        raise NotImplementedError("Subclasses must provide generator fixture")

    def test_generate_token_returns_string(self, generator):
        """Test that generating token returns string."""
        token = generator.generate(subject="user-123")

        assert isinstance(token, str)
        assert len(token) > 0

    def test_generate_token_with_expiry(self, generator):
        """Test generating token with expiry."""
        token = generator.generate(
            subject="user-123",
            expires_in=timedelta(minutes=15),
        )

        assert isinstance(token, str)
        assert len(token) > 0

    def test_generate_token_with_custom_claims(self, generator):
        """Test generating token with custom claims."""
        token = generator.generate(
            subject="user-123",
            scope="api:read api:write",
            role="admin",
        )

        # Verify claims present
        claims = generator.verify(token)
        assert claims["scope"] == "api:read api:write"
        assert claims["role"] == "admin"

    def test_verify_valid_token(self, generator):
        """Test verifying valid token."""
        token = generator.generate(subject="user-123")

        claims = generator.verify(token)
        assert claims["sub"] == "user-123"
        assert "iat" in claims

    def test_verify_invalid_token_raises_error(self, generator):
        """Test that verifying invalid token raises error."""
        with pytest.raises(InvalidTokenError):
            generator.verify("invalid_token_string")

    def test_verify_expired_token_raises_error(self, generator):
        """Test that verifying expired token raises error."""
        # Generate token that expires immediately
        token = generator.generate(
            subject="user-123",
            expires_in=timedelta(seconds=-1),  # Already expired
        )

        with pytest.raises(ExpiredTokenError):
            generator.verify(token)

    def test_decode_without_verification(self, generator):
        """Test decoding token without verification."""
        token = generator.generate(subject="user-123", custom="value")

        claims = generator.decode_without_verification(token)
        assert claims["sub"] == "user-123"
        assert claims["custom"] == "value"

    def test_decode_expired_token_without_verification(self, generator):
        """Test decoding expired token without verification."""
        # Generate expired token
        token = generator.generate(
            subject="user-123",
            expires_in=timedelta(seconds=-1),
        )

        # Should work without verification
        claims = generator.decode_without_verification(token)
        assert claims["sub"] == "user-123"

    def test_generate_different_tokens_for_same_subject(self, generator):
        """Test that generating multiple tokens for same subject returns different values."""
        import time
        token1 = generator.generate(subject="user-123")
        # Wait a bit to ensure different iat timestamp
        time.sleep(1.1)  # Wait over 1 second to ensure different iat
        token2 = generator.generate(subject="user-123")

        # Tokens should be different (due to iat timestamp)
        assert token1 != token2

    def test_verify_returns_subject(self, generator):
        """Test that verify returns subject claim."""
        subject = "user-123"
        token = generator.generate(subject=subject)

        claims = generator.verify(token)
        assert claims["sub"] == subject


# ===== Concrete Test Classes =====

class TestJWTGenerator(TokenGeneratorContractTests):
    """Test JWTGenerator against contract."""

    @pytest.fixture
    def generator(self, jwt_generator):
        """Use the jwt_generator fixture from conftest."""
        return jwt_generator


class TestFernetGenerator(TokenGeneratorContractTests):
    """Test FernetGenerator against contract."""

    @pytest.fixture
    def generator(self, fernet_generator):
        """Use the fernet_generator fixture from conftest."""
        return fernet_generator
