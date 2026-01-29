"""
Generator utilities for auth-core package.

Provides secure token and code generation.
"""

import secrets
import string
from typing import List


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.

    Args:
        length: The length of the token (default: 32 bytes)

    Returns:
        URL-safe base64-encoded token
    """
    return secrets.token_urlsafe(length)


def generate_numeric_code(length: int = 6) -> str:
    """
    Generate a numeric code.

    Args:
        length: The length of the code (default: 6 digits)

    Returns:
        Numeric code as string
    """
    return "".join(secrets.choice(string.digits) for _ in range(length))


def generate_alphanumeric_code(length: int = 8, uppercase: bool = True) -> str:
    """
    Generate an alphanumeric code.

    Args:
        length: The length of the code (default: 8 characters)
        uppercase: Whether to use uppercase letters (default: True)

    Returns:
        Alphanumeric code
    """
    chars = string.ascii_uppercase + string.digits if uppercase else string.ascii_lowercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def generate_backup_codes(count: int = 10, length: int = 8) -> List[str]:
    """
    Generate backup codes for MFA.

    Args:
        count: Number of backup codes to generate (default: 10)
        length: Length of each code (default: 8 characters)

    Returns:
        List of backup codes
    """
    return [generate_alphanumeric_code(length) for _ in range(count)]
