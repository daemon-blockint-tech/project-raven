"""FastAPI dependencies that route destructive actions through the gate."""

from __future__ import annotations

from typing import Callable

from fastapi import Depends, HTTPException, Request, status

from raven.approval.gate import approval_gate
from raven.approval.models import ApprovalDecision, ApprovalVerdict
from raven.auth.dependencies import current_user, require_admin
from raven.auth.models import User


def approval_required(command_field: str = "command") -> Callable:
    """Dependency factory that resolves the field ``command_field`` from the
    request JSON body and routes it through ``ApprovalGate.check()``.

    Behaviour:
      * BLOCKLIST_HIT          → 451 Unavailable For Legal Reasons (no override)
      * AUTO_DENIED            → 403
      * DENIED + pending       → 202 Accepted with request_id (await operator)
      * APPROVED/AUTO_APPROVED → returns ApprovalDecision so the route can log it
    """

    async def _check(
        request: Request,
        user: User = Depends(current_user),
    ) -> ApprovalDecision:
        try:
            body = await request.json()
        except Exception:
            body = {}
        command = str(body.get(command_field, ""))
        decision = approval_gate().check(command, actor=user.username)

        if decision.verdict == ApprovalVerdict.BLOCKLIST_HIT:
            raise HTTPException(
                status_code=451,
                detail={
                    "verdict": decision.verdict.value,
                    "reason": decision.reason,
                    "pattern": decision.matched_description,
                },
            )
        if decision.verdict in (ApprovalVerdict.AUTO_DENIED,):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "verdict": decision.verdict.value,
                    "reason": decision.reason,
                    "pattern": decision.matched_description,
                },
            )
        if (
            decision.verdict == ApprovalVerdict.DENIED
            and decision.request_id
            and decision.matched_pattern
        ):
            # Pending — surface 202 with the request_id so the caller can poll.
            raise HTTPException(
                status_code=status.HTTP_202_ACCEPTED,
                detail={
                    "verdict": "pending",
                    "request_id": decision.request_id,
                    "pattern": decision.matched_description,
                    "severity": decision.severity,
                    "reason": decision.reason,
                },
            )
        return decision

    return _check


# Re-export admin guard for the approval-management endpoints
require_approval_admin = require_admin
