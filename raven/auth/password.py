"""Argon2id password hashing.

Argon2id is the OWASP-recommended algorithm for password storage.
Falls back to a clear error if `argon2-cffi` is not installed.
"""

from __future__ import annotations

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, InvalidHash
except ImportError:  # pragma: no cover
    raise ImportError(
        "argon2-cffi is required. Install with: pip install argon2-cffi"
    )


# OWASP 2023 minimum: t=2, m=19456, p=1
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19_456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)


def hash_password(plain: str) -> str:
    """Hash a plaintext password with Argon2id."""
    return _hasher.hash(plain)


def verify_password(plain: str, stored_hash: str) -> bool:
    """Constant-time verification. Returns False on any error."""
    try:
        _hasher.verify(stored_hash, plain)
        return True
    except (VerifyMismatchError, InvalidHash, Exception):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True if the stored hash uses outdated parameters and should be re-hashed
    on the next successful login."""
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHash:
        return True
