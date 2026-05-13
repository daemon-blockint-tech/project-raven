"""REST endpoints for the approval gate."""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from raven.approval.gate import approval_gate
from raven.approval.models import ApprovalMode, PendingApproval
from raven.approval.store import allowlist_store, pending_store
from raven.auth.dependencies import current_user, require_admin, require_operator
from raven.auth.models import User
from raven.observability.metrics import APPROVAL_REQUESTS


router = APIRouter(prefix="/approval", tags=["approval"])


class ModeUpdate(BaseModel):
    mode: ApprovalMode


class AllowlistEntry(BaseModel):
    pattern: str


class DecisionResolve(BaseModel):
    approve: bool


@router.get("/mode")
async def get_mode(user: User = Depends(current_user)):
    gate = approval_gate()
    return {"mode": gate.mode.value, "timeout_seconds": gate.timeout_seconds}


@router.patch("/mode")
async def set_mode(payload: ModeUpdate, user: User = Depends(require_admin)):
    approval_gate().set_mode(payload.mode)
    return {"mode": payload.mode.value, "set_by": user.username}


@router.get("/decisions", response_model=List[PendingApproval])
async def list_decisions(
    actor: Optional[str] = None,
    user: User = Depends(current_user),
):
    """List currently pending approval requests."""
    return pending_store().list(actor=actor)


@router.post("/decisions/{request_id}/approve")
async def approve_decision(
    request_id: str,
    user: User = Depends(require_operator),
):
    decision = approval_gate().resolve(request_id, approve=True, decided_by=user.username)
    APPROVAL_REQUESTS.labels(mode=decision.mode.value, verdict=decision.verdict.value).inc()
    return decision


@router.post("/decisions/{request_id}/deny")
async def deny_decision(
    request_id: str,
    user: User = Depends(require_operator),
):
    decision = approval_gate().resolve(request_id, approve=False, decided_by=user.username)
    APPROVAL_REQUESTS.labels(mode=decision.mode.value, verdict=decision.verdict.value).inc()
    return decision


@router.get("/allowlist")
async def list_allowlist(user: User = Depends(current_user)):
    return {"patterns": allowlist_store().list()}


@router.post("/allowlist")
async def add_allowlist(payload: AllowlistEntry, user: User = Depends(require_admin)):
    allowlist_store().add(payload.pattern)
    return {"added": payload.pattern, "by": user.username}


@router.delete("/allowlist/{pattern}")
async def remove_allowlist(pattern: str, user: User = Depends(require_admin)):
    removed = allowlist_store().remove(pattern)
    if not removed:
        raise HTTPException(status_code=404, detail=f"pattern not found: {pattern!r}")
    return {"removed": pattern}
