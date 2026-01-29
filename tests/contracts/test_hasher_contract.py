"""
Contract tests for IPasswordHasher.

All password hasher implementations must pass these tests.
"""

import pytest


class PasswordHasherContractTests:
    """Base test class that ALL password hasher implementations must pass."""

    @pytest.fixture
    def hasher(self):
        """Subclasses must provide hasher implementation."""
        raise NotImplementedError("Subclasses must provide hasher fixture")

    def test_hash_returns_different_value_than_password(self, hasher):
        """Test that hashing returns different value than original password."""
        password = "SecurePassword123"
        hashed = hasher.hash(password)

        assert hashed != password
        assert len(hashed) > 0

    def test_hash_same_password_twice_returns_different_hashes(self, hasher):
        """Test that hashing same password twice returns different hashes (salt)."""
        password = "SecurePassword123"
        hash1 = hasher.hash(password)
        hash2 = hasher.hash(password)

        # Should be different due to different salts
        assert hash1 != hash2

    def test_verify_correct_password(self, hasher):
        """Test verifying correct password."""
        password = "SecurePassword123"
        hashed = hasher.hash(password)

        assert hasher.verify(password, hashed) is True

    def test_verify_incorrect_password(self, hasher):
        """Test verifying incorrect password."""
        password = "SecurePassword123"
        hashed = hasher.hash(password)

        assert hasher.verify("WrongPassword", hashed) is False

    def test_verify_empty_password(self, hasher):
        """Test verifying empty password."""
        password = "SecurePassword123"
        hashed = hasher.hash(password)

        assert hasher.verify("", hashed) is False

    def test_hash_empty_password(self, hasher):
        """Test hashing empty password."""
        hashed = hasher.hash("")
        assert hashed != ""
        assert len(hashed) > 0

    def test_hash_long_password(self, hasher):
        """Test hashing very long password."""
        # Use 70 chars to be safe with bcrypt's 72 byte limit
        password = "A" * 70
        hashed = hasher.hash(password)

        assert hashed != password
        assert hasher.verify(password, hashed) is True

    def test_hash_unicode_password(self, hasher):
        """Test hashing password with unicode characters."""
        password = "Pāsswørd123!@#$"
        hashed = hasher.hash(password)

        assert hasher.verify(password, hashed) is True

    def test_needs_rehash_returns_bool(self, hasher):
        """Test that needs_rehash returns boolean."""
        password = "SecurePassword123"
        hashed = hasher.hash(password)

        result = hasher.needs_rehash(hashed)
        assert isinstance(result, bool)


# ===== Concrete Test Classes =====

class TestArgon2Hasher(PasswordHasherContractTests):
    """Test Argon2Hasher against contract."""

    @pytest.fixture
    def hasher(self, argon2_hasher):
        """Use the argon2_hasher fixture from conftest."""
        return argon2_hasher


class TestBcryptHasher(PasswordHasherContractTests):
    """Test BcryptHasher against contract."""

    @pytest.fixture
    def hasher(self, bcrypt_hasher):
        """Use the bcrypt_hasher fixture from conftest."""
        return bcrypt_hasher
