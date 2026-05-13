"""JWT issue/verify with access + refresh token pair.

Token types:
  - "access"  : short-lived (default 15 min), used as `Authorization: Bearer`
  - "refresh" : long-lived (default 7 days), used only at `/auth/refresh`

Refresh tokens carry a `jti` (UUID4) which can be added to a Redis blocklist
on `/auth/logout` to revoke the session before expiry.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

import jwt
from jwt.exceptions import InvalidTokenError

from raven.auth.models import Role


class JWTError(Exception):
    """Raised when a token is missing, expired, malformed, or revoked."""


class JWTManager:
    """Stateless JWT signer + verifier with an in-memory revocation set.

    The in-memory revocation set is fine for single-replica development.
    For multi-replica prod, swap `_revoked_jtis` for a Redis-backed set
    (see Phase 3 — Data plane).
    """

    def __init__(
        self,
        secret: str,
        algorithm: str = "HS256",
        issuer: str = "raven",
        audience: str = "raven-api",
        access_ttl_minutes: int = 15,
        refresh_ttl_days: int = 7,
    ) -> None:
        if not secret or len(secret) < 16:
            raise ValueError("JWT secret must be at least 16 chars")
        self.secret = secret
        self.algorithm = algorithm
        self.issuer = issuer
        self.audience = audience
        self.access_ttl = timedelta(minutes=access_ttl_minutes)
        self.refresh_ttl = timedelta(days=refresh_ttl_days)
        self._revoked_jtis: Set[str] = set()

    # ------------------------------------------------------------------
    # Issue
    # ------------------------------------------------------------------

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _base_claims(self, sub: str, token_type: str, ttl: timedelta) -> Dict[str, Any]:
        now = self._now()
        return {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": sub,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + ttl).timestamp()),
            "jti": str(uuid.uuid4()),
            "typ": token_type,
        }

    def issue_access(self, username: str, roles: List[Role]) -> str:
        claims = self._base_claims(username, "access", self.access_ttl)
        claims["roles"] = [r.value for r in roles]
        return jwt.encode(claims, self.secret, algorithm=self.algorithm)

    def issue_refresh(self, username: str) -> str:
        claims = self._base_claims(username, "refresh", self.refresh_ttl)
        return jwt.encode(claims, self.secret, algorithm=self.algorithm)

    def access_ttl_seconds(self) -> int:
        return int(self.access_ttl.total_seconds())

    # ------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------

    def decode(self, token: str, expected_type: str) -> Dict[str, Any]:
        try:
            claims = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "sub", "typ", "jti"]},
            )
        except InvalidTokenError as e:
            raise JWTError(f"Invalid token: {e}") from e

        if claims.get("typ") != expected_type:
            raise JWTError(
                f"Token type mismatch: expected {expected_type!r}, got {claims.get('typ')!r}"
            )
        if claims.get("jti") in self._revoked_jtis:
            raise JWTError("Token has been revoked")
        return claims

    def decode_access(self, token: str) -> Dict[str, Any]:
        return self.decode(token, "access")

    def decode_refresh(self, token: str) -> Dict[str, Any]:
        return self.decode(token, "refresh")

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    def revoke(self, jti: str) -> None:
        self._revoked_jtis.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked_jtis


# ---------------------------------------------------------------------------
# Module-level singleton (lazy, reads settings at first access)
# ---------------------------------------------------------------------------

_singleton: Optional[JWTManager] = None


def jwt_manager() -> JWTManager:
    """Return the process-wide JWTManager, built from Raven settings."""
    global _singleton
    if _singleton is None:
        from raven.config import settings
        _singleton = JWTManager(
            secret=settings.secret_key,
            algorithm=settings.jwt_algorithm,
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            access_ttl_minutes=settings.jwt_access_ttl_minutes,
            refresh_ttl_days=settings.jwt_refresh_ttl_days,
        )
    return _singleton


def reset_jwt_manager() -> None:
    """Reset the singleton (for tests)."""
    global _singleton
    _singleton = None
