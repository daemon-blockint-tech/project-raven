"""Approval-gate domain models."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ApprovalMode(str, Enum):
    """Three approval modes — mirrors Hermes Agent ``approvals.mode``."""

    MANUAL = "manual"  # always prompt
    SMART = "smart"  # auxiliary LLM triages; high-risk escalates
    OFF = "off"  # YOLO — only the hardline blocklist applies


class ApprovalVerdict(str, Enum):
    ALLOWED = "allowed"  # gate let it through
    AUTO_APPROVED = "auto_approved"  # smart mode auto-approved low-risk
    AUTO_DENIED = "auto_denied"  # smart mode auto-denied genuinely dangerous
    APPROVED = "approved"  # human said yes
    DENIED = "denied"  # human said no
    TIMEOUT_DENIED = "timeout_denied"  # fail-closed on operator no-response
    BLOCKLIST_HIT = "blocklist_hit"  # hardline floor — irreversible


@dataclass
class DangerousPattern:
    """Regex + human description of a sensitive command/action pattern."""

    pattern: str  # regex (Python re syntax)
    description: str  # one-line operator explanation
    severity: str  # "low" | "medium" | "high" | "critical"


@dataclass
class BlocklistMatch:
    """Hit on the UNRECOVERABLE_BLOCKLIST — there's no override flag."""

    pattern: str
    reason: str
    raw: str  # the actual command that tripped


class ApprovalDecision(BaseModel):
    """Result of running a command through the gate."""

    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    command: str
    verdict: ApprovalVerdict
    mode: ApprovalMode
    matched_pattern: Optional[str] = None
    matched_description: Optional[str] = None
    severity: Optional[str] = None
    reason: Optional[str] = None
    decided_at: float = Field(default_factory=time.time)
    decided_by: Optional[str] = None  # username when human-decided
    duration_ms: Optional[float] = None


class PendingApproval(BaseModel):
    """A command awaiting operator approval. Stored in-memory or Redis."""

    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    command: str
    matched_pattern: str
    matched_description: str
    severity: str
    actor: str
    created_at: float = Field(default_factory=time.time)
    deadline_at: float  # wallclock deadline; past this → TIMEOUT_DENIED
    smart_assessment: Optional[str] = None  # populated in smart mode
