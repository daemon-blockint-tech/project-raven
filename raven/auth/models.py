"""Auth domain models — User, Role, TokenPair."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List

from pydantic import BaseModel, Field


class Role(str, Enum):
    """Three-tier RBAC. Higher roles inherit lower-role permissions."""

    VIEWER = "viewer"  # read-only
    OPERATOR = "operator"  # can run hunts, mitigations, set targets
    ADMIN = "admin"  # can rotate AI providers, change system prompt, manage users

    @property
    def rank(self) -> int:
        return {"viewer": 0, "operator": 1, "admin": 2}[self.value]

    def covers(self, required: "Role") -> bool:
        return self.rank >= required.rank


# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------


@dataclass
class User:
    """Internal user record (also used as in-memory store row)."""

    username: str
    password_hash: str
    roles: List[Role] = field(default_factory=lambda: [Role.VIEWER])
    disabled: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)

    def has_role(self, required: Role) -> bool:
        return any(r.covers(required) for r in self.roles)


# ---------------------------------------------------------------------------
# Request / response payloads
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # access token TTL in seconds


class UserPublic(BaseModel):
    """Public user representation (no password hash)."""

    username: str
    roles: List[Role]
    disabled: bool
    created_at: datetime


class UserCreate(BaseModel):
    username: str = Field(
        ..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$"
    )
    password: str = Field(..., min_length=12, max_length=256)
    roles: List[Role] = Field(default_factory=lambda: [Role.VIEWER])
