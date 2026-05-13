"""Approval gate — Hermes Agent-inspired dangerous-command HITL with hardline blocklist.

Three modes: ``manual`` (always ask), ``smart`` (LLM-assisted triage), ``off`` (YOLO).
Below every mode sits an ``UNRECOVERABLE_BLOCKLIST`` that nothing can bypass.
"""

from raven.approval.models import (
    ApprovalDecision,
    ApprovalMode,
    ApprovalVerdict,
    BlocklistMatch,
    DangerousPattern,
    PendingApproval,
)
from raven.approval.gate import ApprovalGate, approval_gate
from raven.approval.dependencies import approval_required, require_approval_admin

__all__ = [
    "ApprovalDecision",
    "ApprovalMode",
    "ApprovalVerdict",
    "BlocklistMatch",
    "DangerousPattern",
    "PendingApproval",
    "ApprovalGate",
    "approval_gate",
    "approval_required",
    "require_approval_admin",
]
