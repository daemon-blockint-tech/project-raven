"""FastAPI dependencies for authentication and RBAC."""

from __future__ import annotations

from typing import List

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from raven.auth.jwt_manager import JWTError, jwt_manager
from raven.auth.models import Role, User
from raven.auth.user_store import user_store


_bearer = HTTPBearer(auto_error=False)


def current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> User:
    """Resolve the current user from the `Authorization: Bearer <jwt>` header.

    Raises 401 if missing/invalid, 403 if the account is disabled.
    Also stashes the user + jti on `request.state` for the audit middleware.
    """
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = jwt_manager().decode_access(creds.credentials)
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = claims["sub"]
    user = user_store().get(username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if user.disabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    # For audit log middleware
    request.state.user = user
    request.state.jti = claims.get("jti")
    return user


def require_role(required: Role):
    """Dependency factory enforcing a minimum role."""

    def _check(user: User = Depends(current_user)) -> User:
        if not user.has_role(required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {required.value}",
            )
        return user

    return _check


# Convenience shortcuts
require_viewer = require_role(Role.VIEWER)
require_operator = require_role(Role.OPERATOR)
require_admin = require_role(Role.ADMIN)
