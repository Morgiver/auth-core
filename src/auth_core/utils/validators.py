"""
Validation utilities for auth-core package.

Provides password strength validation and other validation logic.
"""

import logging
import re
from typing import List, Optional

logger = logging.getLogger(__name__)


class PasswordStrengthValidator:
    """
    Validates password strength based on configurable rules.
    """

    def __init__(
        self,
        min_length: int = 8,
        max_length: int = 128,
        require_uppercase: bool = False,
        require_lowercase: bool = False,
        require_digit: bool = False,
        require_special: bool = False,
        special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?",
    ):
        self.min_length = min_length
        self.max_length = max_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digit = require_digit
        self.require_special = require_special
        self.special_chars = special_chars

    def validate(self, password: str) -> tuple[bool, List[str]]:
        """
        Validate password strength.

        Args:
            password: The password to validate

        Returns:
            Tuple of (is_valid, errors)
        """
        errors = []

        # Check length
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters")

        if len(password) > self.max_length:
            errors.append(f"Password must not exceed {self.max_length} characters")

        # Check uppercase
        if self.require_uppercase and not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")

        # Check lowercase
        if self.require_lowercase and not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")

        # Check digit
        if self.require_digit and not re.search(r"\d", password):
            errors.append("Password must contain at least one digit")

        # Check special character
        if self.require_special and not any(c in self.special_chars for c in password):
            errors.append(
                f"Password must contain at least one special character ({self.special_chars})"
            )

        return len(errors) == 0, errors

    def validate_or_raise(self, password: str) -> None:
        """
        Validate password strength and raise exception if invalid.

        Args:
            password: The password to validate

        Raises:
            WeakPasswordError: If password doesn't meet requirements
        """
        from auth_core.domain.exceptions import WeakPasswordError

        is_valid, errors = self.validate(password)

        if not is_valid:
            raise WeakPasswordError("; ".join(errors))


def is_common_password(password: str, common_passwords: Optional[List[str]] = None) -> bool:
    """
    Check if password is in a list of common passwords.

    Args:
        password: The password to check
        common_passwords: Optional list of common passwords

    Returns:
        True if password is common, False otherwise
    """
    if common_passwords is None:
        # Default list of most common passwords
        common_passwords = [
            "password",
            "123456",
            "12345678",
            "qwerty",
            "abc123",
            "monkey",
            "1234567",
            "letmein",
            "trustno1",
            "dragon",
            "baseball",
            "111111",
            "iloveyou",
            "master",
            "sunshine",
            "ashley",
            "bailey",
            "passw0rd",
            "shadow",
            "123123",
        ]

    return password.lower() in common_passwords
