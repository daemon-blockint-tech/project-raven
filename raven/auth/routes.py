"""Authentication endpoints: /auth/login, /auth/refresh, /auth/logout, /auth/me."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from raven.auth.dependencies import current_user
from raven.auth.jwt_manager import JWTError, jwt_manager
from raven.auth.models import (
    LoginRequest,
    RefreshRequest,
    TokenPair,
    User,
    UserPublic,
)
from raven.auth.user_store import user_store


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenPair)
async def login(payload: LoginRequest) -> TokenPair:
    """Exchange username + password for an access + refresh token pair."""
    user = user_store().authenticate(payload.username, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    mgr = jwt_manager()
    return TokenPair(
        access_token=mgr.issue_access(user.username, user.roles),
        refresh_token=mgr.issue_refresh(user.username),
        expires_in=mgr.access_ttl_seconds(),
    )


@router.post("/refresh", response_model=TokenPair)
async def refresh(payload: RefreshRequest) -> TokenPair:
    """Exchange a refresh token for a new access token (and a rotated refresh)."""
    mgr = jwt_manager()
    try:
        claims = mgr.decode_refresh(payload.refresh_token)
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    user = user_store().get(claims["sub"])
    if user is None or user.disabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive"
        )

    # Rotate refresh token (revoke old, issue new) — defence in depth against theft
    mgr.revoke(claims["jti"])
    return TokenPair(
        access_token=mgr.issue_access(user.username, user.roles),
        refresh_token=mgr.issue_refresh(user.username),
        expires_in=mgr.access_ttl_seconds(),
    )


@router.post("/logout")
async def logout(payload: RefreshRequest, user: User = Depends(current_user)):
    """Revoke the supplied refresh token. The access token expires naturally."""
    mgr = jwt_manager()
    try:
        claims = mgr.decode_refresh(payload.refresh_token)
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    if claims["sub"] != user.username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Refresh token does not belong to the current user",
        )
    mgr.revoke(claims["jti"])
    return {"revoked": True}


@router.get("/me", response_model=UserPublic)
async def me(user: User = Depends(current_user)) -> UserPublic:
    return UserPublic(
        username=user.username,
        roles=user.roles,
        disabled=user.disabled,
        created_at=user.created_at,
    )
