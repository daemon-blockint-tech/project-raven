"""Project Raven authentication & authorization.

JWT bearer + refresh tokens with RBAC (viewer / operator / admin).
"""

from raven.auth.models import Role, TokenPair, User, UserCreate, UserPublic
from raven.auth.jwt_manager import JWTManager, jwt_manager
from raven.auth.dependencies import (
    current_user,
    require_role,
    require_admin,
    require_operator,
)

__all__ = [
    "Role",
    "TokenPair",
    "User",
    "UserCreate",
    "UserPublic",
    "JWTManager",
    "jwt_manager",
    "current_user",
    "require_role",
    "require_admin",
    "require_operator",
]
