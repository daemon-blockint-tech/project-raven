"""Fernet-backed secret helper for at-rest encryption of API keys.

When ``settings.secret_key`` is at least 32 chars we derive a Fernet key from
it; otherwise we generate an ephemeral key (in-memory only, lost on restart)
and log a warning. Encrypted values are stored as ``fernet:<token>`` so the
on-disk shape is recognisable.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import threading
from typing import Optional

log = logging.getLogger(__name__)

_PREFIX = "fernet:"


def _derive_key(secret: str) -> bytes:
    """Derive a 32-byte Fernet key from the application secret."""
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


class FernetVault:
    """Thread-safe encrypt/decrypt for short string secrets."""

    def __init__(self, secret: Optional[str] = None) -> None:
        from cryptography.fernet import Fernet  # lazy import — dep is heavy

        self._lock = threading.RLock()
        if secret and len(secret) >= 32:
            key = _derive_key(secret)
        else:
            log.warning(
                "FernetVault: weak/missing secret_key; using ephemeral key. "
                "Encrypted values will NOT survive a process restart."
            )
            key = Fernet.generate_key()
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        if not plaintext:
            return ""
        token = self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")
        return _PREFIX + token

    def decrypt(self, ciphertext: str) -> str:
        if not ciphertext:
            return ""
        if not ciphertext.startswith(_PREFIX):
            return ciphertext  # already plaintext (legacy)
        token = ciphertext[len(_PREFIX):]
        return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")


_singleton: Optional[FernetVault] = None
_lock = threading.Lock()


def vault() -> FernetVault:
    global _singleton
    if _singleton is not None:
        return _singleton
    with _lock:
        if _singleton is None:
            from raven.config import settings
            _singleton = FernetVault(secret=settings.secret_key)
        return _singleton


def reset_vault() -> None:
    """Tests only."""
    global _singleton
    _singleton = None
