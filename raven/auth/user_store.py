"""In-memory user store.

This is the Phase 1 implementation. Phase 3 (Data plane) replaces this with a
SQLAlchemy-backed `users` table + Alembic migration. The interface stays the
same so route handlers do not need to change.
"""

from __future__ import annotations

import threading
from typing import Dict, List, Optional

from raven.auth.models import Role, User
from raven.auth.password import hash_password, verify_password, needs_rehash


class UserStore:
    """Thread-safe in-memory user store."""

    def __init__(self) -> None:
        self._users: Dict[str, User] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create(self, username: str, password: str, roles: List[Role]) -> User:
        username = username.lower().strip()
        with self._lock:
            if username in self._users:
                raise ValueError(f"User already exists: {username!r}")
            user = User(
                username=username,
                password_hash=hash_password(password),
                roles=list(roles),
            )
            self._users[username] = user
            return user

    def get(self, username: str) -> Optional[User]:
        return self._users.get(username.lower().strip())

    def list_users(self) -> List[User]:
        return list(self._users.values())

    def delete(self, username: str) -> bool:
        with self._lock:
            return self._users.pop(username.lower().strip(), None) is not None

    def count(self) -> int:
        return len(self._users)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Return the user iff password matches and account is enabled.
        Rehashes the stored password transparently if the hash is outdated."""
        user = self.get(username)
        if user is None or user.disabled:
            # Run a dummy verify to keep timing similar (avoid user enum)
            verify_password(password, "$argon2id$v=19$m=19456,t=2,p=1$xxxxx$yyyyy")
            return None
        if not verify_password(password, user.password_hash):
            return None
        if needs_rehash(user.password_hash):
            with self._lock:
                user.password_hash = hash_password(password)
        return user


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_singleton: Optional[UserStore] = None


def user_store() -> UserStore:
    global _singleton
    if _singleton is None:
        _singleton = UserStore()
        _bootstrap_admin(_singleton)
    return _singleton


def reset_user_store() -> None:
    """Reset for tests."""
    global _singleton
    _singleton = None


def _bootstrap_admin(store: UserStore) -> None:
    """Auto-create the bootstrap admin if configured and store is empty."""
    from raven.config import settings

    if store.count() > 0:
        return
    if not settings.bootstrap_admin_password:
        return
    try:
        store.create(
            username=settings.bootstrap_admin_username,
            password=settings.bootstrap_admin_password,
            roles=[Role.ADMIN],
        )
    except ValueError:
        pass
