"""Password hashing for the web admin's local user store.

Plain PBKDF2-HMAC-SHA256 via the standard library instead of passlib+bcrypt:
passlib 1.7.x's bcrypt backend detection is broken against bcrypt>=4 (a
long-standing, unfixed upstream incompatibility), and pulling in an older
bcrypt just to work around it isn't worth it for a local admin-user store.
PBKDF2 with a high iteration count is a fine, dependency-free choice here.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

_ALGO = "pbkdf2_sha256"
_ITERATIONS = 260_000

MIN_PASSWORD_LENGTH = 8


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _ITERATIONS)
    return f"{_ALGO}${_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algo, iterations_s, salt, digest_hex = password_hash.split("$", 3)
        if algo != _ALGO:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations_s))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, AttributeError):
        return False


def generate_password(length: int = 20) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))
