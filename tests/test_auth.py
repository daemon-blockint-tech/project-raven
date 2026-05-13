"""Tests for the auth layer — JWT, password hashing, RBAC dependencies, user store."""

from __future__ import annotations

import time

import pytest

from raven.auth.jwt_manager import JWTError, JWTManager
from raven.auth.models import Role, User
from raven.auth.password import hash_password, needs_rehash, verify_password
from raven.auth.user_store import UserStore


# ---------------------------------------------------------------------------
# Role
# ---------------------------------------------------------------------------

class TestRoleHierarchy:
    def test_admin_covers_operator_and_viewer(self):
        assert Role.ADMIN.covers(Role.VIEWER)
        assert Role.ADMIN.covers(Role.OPERATOR)
        assert Role.ADMIN.covers(Role.ADMIN)

    def test_operator_covers_viewer_only(self):
        assert Role.OPERATOR.covers(Role.VIEWER)
        assert Role.OPERATOR.covers(Role.OPERATOR)
        assert not Role.OPERATOR.covers(Role.ADMIN)

    def test_viewer_covers_only_self(self):
        assert Role.VIEWER.covers(Role.VIEWER)
        assert not Role.VIEWER.covers(Role.OPERATOR)
        assert not Role.VIEWER.covers(Role.ADMIN)


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

class TestPasswordHashing:
    def test_round_trip(self):
        h = hash_password("correct horse battery staple")
        assert h.startswith("$argon2id$")
        assert verify_password("correct horse battery staple", h) is True

    def test_wrong_password_rejected(self):
        h = hash_password("secret123secret")
        assert verify_password("wrong", h) is False

    def test_invalid_hash_returns_false(self):
        assert verify_password("anything", "not-a-hash") is False

    def test_unique_salt(self):
        a = hash_password("same")
        b = hash_password("same")
        assert a != b

    def test_needs_rehash_with_garbage(self):
        assert needs_rehash("garbage") is True


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

class TestJWTManager:
    @pytest.fixture
    def mgr(self):
        return JWTManager(secret="x" * 32, access_ttl_minutes=1, refresh_ttl_days=1)

    def test_short_secret_rejected(self):
        with pytest.raises(ValueError):
            JWTManager(secret="short")

    def test_access_round_trip(self, mgr):
        token = mgr.issue_access("alice", [Role.ADMIN])
        claims = mgr.decode_access(token)
        assert claims["sub"] == "alice"
        assert claims["roles"] == ["admin"]
        assert claims["typ"] == "access"

    def test_refresh_round_trip(self, mgr):
        token = mgr.issue_refresh("alice")
        claims = mgr.decode_refresh(token)
        assert claims["sub"] == "alice"
        assert claims["typ"] == "refresh"

    def test_access_token_cannot_pass_as_refresh(self, mgr):
        access = mgr.issue_access("alice", [Role.VIEWER])
        with pytest.raises(JWTError):
            mgr.decode_refresh(access)

    def test_refresh_token_cannot_pass_as_access(self, mgr):
        refresh = mgr.issue_refresh("alice")
        with pytest.raises(JWTError):
            mgr.decode_access(refresh)

    def test_revocation_blocks_decode(self, mgr):
        token = mgr.issue_refresh("alice")
        claims = mgr.decode_refresh(token)
        mgr.revoke(claims["jti"])
        with pytest.raises(JWTError):
            mgr.decode_refresh(token)

    def test_tampered_token_rejected(self, mgr):
        token = mgr.issue_access("alice", [Role.VIEWER])
        # Tamper with payload
        tampered = token[:-5] + "AAAAA"
        with pytest.raises(JWTError):
            mgr.decode_access(tampered)


# ---------------------------------------------------------------------------
# UserStore
# ---------------------------------------------------------------------------

class TestUserStore:
    @pytest.fixture
    def store(self):
        return UserStore()

    def test_create_and_get(self, store):
        store.create("alice", "very-strong-pw-1234", [Role.OPERATOR])
        u = store.get("alice")
        assert u is not None
        assert u.username == "alice"
        assert Role.OPERATOR in u.roles

    def test_username_normalised_to_lowercase(self, store):
        store.create("Alice", "very-strong-pw-1234", [Role.VIEWER])
        assert store.get("alice") is not None
        assert store.get("ALICE") is not None

    def test_duplicate_create_rejected(self, store):
        store.create("alice", "very-strong-pw-1234", [Role.VIEWER])
        with pytest.raises(ValueError):
            store.create("alice", "very-strong-pw-1234", [Role.ADMIN])

    def test_authenticate_success(self, store):
        store.create("bob", "very-strong-pw-1234", [Role.ADMIN])
        u = store.authenticate("bob", "very-strong-pw-1234")
        assert u is not None
        assert u.has_role(Role.ADMIN)

    def test_authenticate_wrong_password(self, store):
        store.create("bob", "very-strong-pw-1234", [Role.ADMIN])
        assert store.authenticate("bob", "wrong") is None

    def test_authenticate_unknown_user(self, store):
        assert store.authenticate("nobody", "anything") is None

    def test_authenticate_disabled_user(self, store):
        store.create("bob", "very-strong-pw-1234", [Role.VIEWER])
        store.get("bob").disabled = True
        assert store.authenticate("bob", "very-strong-pw-1234") is None

    def test_user_has_role_admin_covers_all(self, store):
        store.create("root", "very-strong-pw-1234", [Role.ADMIN])
        u = store.get("root")
        assert u.has_role(Role.VIEWER)
        assert u.has_role(Role.OPERATOR)
        assert u.has_role(Role.ADMIN)
