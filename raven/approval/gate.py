"""ApprovalGate — central decision point.

Order of evaluation for every command:

    1. UNRECOVERABLE_BLOCKLIST   → always BLOCKLIST_HIT (no override possible)
    2. Permanent allowlist match → ALLOWED (admin-approved patterns)
    3. Dangerous pattern match?
         no  → ALLOWED
         yes → branch on ``ApprovalMode``:
                * MANUAL → enqueue PendingApproval, return verdict=DENIED until
                          someone resolves it; the route handler raises 202.
                * SMART  → run SmartApprover; auto-approve / auto-deny / escalate
                * OFF    → AUTO_APPROVED (YOLO; blocklist already ran)
"""

from __future__ import annotations

import os
import threading
import time
from typing import Optional

from raven.approval.models import (
    ApprovalDecision,
    ApprovalMode,
    ApprovalVerdict,
    PendingApproval,
)
from raven.approval.patterns import match_blocklist, match_dangerous
from raven.approval.store import allowlist_store, pending_store


class ApprovalGate:
    """Thread-safe singleton encapsulating mode + decision logic."""

    _instance: Optional["ApprovalGate"] = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "ApprovalGate":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Tests only."""
        with cls._lock:
            cls._instance = None

    def __init__(self) -> None:
        from raven.config import settings

        self._mode = ApprovalMode(settings.approval_mode)
        self._timeout = settings.approval_timeout_seconds
        self._yolo_env = settings.yolo_env_override
        self._smart_approver = None  # lazy

    # ------------------------------------------------------------------
    # Mode management
    # ------------------------------------------------------------------

    @property
    def mode(self) -> ApprovalMode:
        if self._yolo_env and os.environ.get("RAVEN_YOLO_MODE") in {"1", "true", "yes"}:
            return ApprovalMode.OFF
        return self._mode

    def set_mode(self, mode: ApprovalMode) -> None:
        self._mode = mode

    @property
    def timeout_seconds(self) -> int:
        return self._timeout

    # ------------------------------------------------------------------
    # Core decision
    # ------------------------------------------------------------------

    def check(self, command: str, actor: str = "unknown") -> ApprovalDecision:
        """Return an immediate decision. MANUAL mode returns a DENIED verdict
        with ``request_id`` set — caller raises 202 and surfaces the ID."""

        start = time.perf_counter()

        # 1) Blocklist — no override
        bl = match_blocklist(command)
        if bl is not None:
            return ApprovalDecision(
                command=command,
                verdict=ApprovalVerdict.BLOCKLIST_HIT,
                mode=self.mode,
                matched_pattern=bl.pattern,
                matched_description=bl.description,
                severity=bl.severity,
                reason="UNRECOVERABLE_BLOCKLIST — no override available",
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )

        # 2) Permanent allowlist
        allowed_by = allowlist_store().matches(command)
        if allowed_by is not None:
            return ApprovalDecision(
                command=command,
                verdict=ApprovalVerdict.ALLOWED,
                mode=self.mode,
                reason=f"allowlist: {allowed_by}",
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )

        # 3) Dangerous pattern?
        dp = match_dangerous(command)
        if dp is None:
            return ApprovalDecision(
                command=command,
                verdict=ApprovalVerdict.ALLOWED,
                mode=self.mode,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )

        # 4) Mode-specific handling
        mode = self.mode
        if mode == ApprovalMode.OFF:
            return ApprovalDecision(
                command=command,
                verdict=ApprovalVerdict.AUTO_APPROVED,
                mode=mode,
                matched_pattern=dp.pattern,
                matched_description=dp.description,
                severity=dp.severity,
                reason="YOLO mode — auto-approved; blocklist did not fire",
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )

        if mode == ApprovalMode.SMART:
            assessment = self._smart_assess(command, dp)
            if assessment.verdict == "approve":
                return ApprovalDecision(
                    command=command,
                    verdict=ApprovalVerdict.AUTO_APPROVED,
                    mode=mode,
                    matched_pattern=dp.pattern,
                    matched_description=dp.description,
                    severity=dp.severity,
                    reason=f"smart: {assessment.reasoning}",
                    duration_ms=(time.perf_counter() - start) * 1000.0,
                )
            if assessment.verdict == "deny":
                return ApprovalDecision(
                    command=command,
                    verdict=ApprovalVerdict.AUTO_DENIED,
                    mode=mode,
                    matched_pattern=dp.pattern,
                    matched_description=dp.description,
                    severity=dp.severity,
                    reason=f"smart: {assessment.reasoning}",
                    duration_ms=(time.perf_counter() - start) * 1000.0,
                )
            # else escalate → fall through to MANUAL handling

        # MANUAL (or escalation from SMART)
        pending = PendingApproval(
            command=command,
            matched_pattern=dp.pattern,
            matched_description=dp.description,
            severity=dp.severity,
            actor=actor,
            deadline_at=time.time() + self._timeout,
        )
        pending_store().add(pending)
        return ApprovalDecision(
            request_id=pending.request_id,
            command=command,
            verdict=ApprovalVerdict.DENIED,  # pending — caller raises 202
            mode=mode,
            matched_pattern=dp.pattern,
            matched_description=dp.description,
            severity=dp.severity,
            reason="awaiting human approval",
            duration_ms=(time.perf_counter() - start) * 1000.0,
        )

    # ------------------------------------------------------------------
    # Operator resolution of a pending decision
    # ------------------------------------------------------------------

    def resolve(
        self, request_id: str, approve: bool, decided_by: str
    ) -> ApprovalDecision:
        item = pending_store().pop(request_id)
        if item is None:
            return ApprovalDecision(
                request_id=request_id,
                command="",
                verdict=ApprovalVerdict.TIMEOUT_DENIED,
                mode=self.mode,
                reason="request not found or already resolved/expired",
            )
        verdict = ApprovalVerdict.APPROVED if approve else ApprovalVerdict.DENIED
        return ApprovalDecision(
            request_id=request_id,
            command=item.command,
            verdict=verdict,
            mode=self.mode,
            matched_pattern=item.matched_pattern,
            matched_description=item.matched_description,
            severity=item.severity,
            decided_by=decided_by,
        )

    # ------------------------------------------------------------------
    # Smart assessment lazy-init
    # ------------------------------------------------------------------

    def _smart_assess(self, command, dp):  # type: ignore[no-untyped-def]
        from raven.approval.smart import SmartApprover

        if self._smart_approver is None:
            self._smart_approver = SmartApprover()
        return self._smart_approver.assess(command, dp)


# Convenience accessor
def approval_gate() -> ApprovalGate:
    return ApprovalGate.get_instance()
