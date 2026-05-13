"""REST endpoints for the red-team subsystem.

Defensive endpoints (`scan`, `decode`, `hardness`) require ``operator`` role.
Offensive endpoint (`godmode`) requires ``admin`` role AND the
``X-Raven-Authorization-Token`` header AND the global enable flag.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel

from raven.auth.dependencies import current_user, require_admin, require_operator
from raven.auth.models import User
from raven.observability.metrics import (
    JAILBREAK_DETECTIONS,
    PROVIDER_HARDNESS_SCORE,
    REDTEAM_GODMODE_ATTEMPTS,
)
from raven.redteam.detector import detector
from raven.redteam.hardness_test import ProviderHardnessTest
from raven.redteam.normalizer import ParseltongueNormaliser
from raven.redteam.offensive import OffensiveGodmode


router = APIRouter(prefix="/redteam", tags=["redteam"])


class ScanRequest(BaseModel):
    prompt: str


class DecodeRequest(BaseModel):
    text: str
    tier: str = ParseltongueNormaliser.HEAVY


class HardnessRequest(BaseModel):
    pass  # nothing — uses active provider from the registry


class OffensiveRequest(BaseModel):
    sandbox_session_id: str
    canary_question: str = "Briefly describe OWASP A1 Injection."


@router.post("/scan")
async def redteam_scan(payload: ScanRequest, user: User = Depends(require_operator)):
    """Run JailbreakDetector against an arbitrary prompt. Useful for triaging
    suspicious inbound traffic or testing custom detection rules."""
    result = detector().scan(payload.prompt)
    if result.detected:
        for tech in result.techniques:
            JAILBREAK_DETECTIONS.labels(technique=tech, action="scanned").inc()
    return result.model_dump()


@router.post("/decode")
async def redteam_decode(payload: DecodeRequest, user: User = Depends(require_operator)):
    """Run Parseltongue normalisation. Returns the decoded text and which
    obfuscation techniques fired."""
    norm = ParseltongueNormaliser(tier=payload.tier).normalise(payload.text)
    return {
        "original": norm.original,
        "normalised": norm.normalised,
        "changed": norm.changed,
        "techniques_detected": norm.techniques_detected,
    }


@router.post("/hardness")
async def redteam_hardness(
    payload: HardnessRequest,
    user: User = Depends(require_admin),
):
    """Run the canary suite against the active AI provider."""
    report = ProviderHardnessTest().run()
    PROVIDER_HARDNESS_SCORE.labels(provider=report.provider, model=report.model or "auto").set(
        report.overall_score
    )
    return report.model_dump()


@router.post("/godmode")
async def redteam_godmode(
    payload: OffensiveRequest,
    user: User = Depends(require_admin),
    x_raven_authorization_token: Optional[str] = Header(default=None, alias="X-Raven-Authorization-Token"),
):
    """OffensiveGodmode — sandboxed, audit-logged, double-gated.

    Returns 403 unless:
      * ``settings.offensive_redteam_enabled`` is true
      * ``X-Raven-Authorization-Token`` matches ``offensive_redteam_session_token``
    """
    from raven.config import settings

    if not settings.offensive_redteam_enabled:
        REDTEAM_GODMODE_ATTEMPTS.labels(outcome="refused").inc()
        raise HTTPException(
            status_code=403,
            detail="OffensiveGodmode is disabled. Set OFFENSIVE_REDTEAM_ENABLED=true to enable.",
        )
    if not x_raven_authorization_token:
        REDTEAM_GODMODE_ATTEMPTS.labels(outcome="refused").inc()
        raise HTTPException(
            status_code=403,
            detail="missing X-Raven-Authorization-Token",
        )

    result = OffensiveGodmode().run(
        canary_question=payload.canary_question,
        sandbox_session_id=payload.sandbox_session_id,
        authorization_token=x_raven_authorization_token,
    )
    if not result.enabled:
        REDTEAM_GODMODE_ATTEMPTS.labels(outcome="refused").inc()
        raise HTTPException(status_code=403, detail="authorization token mismatch")

    if result.winning_strategy is None:
        REDTEAM_GODMODE_ATTEMPTS.labels(outcome="full").inc()  # full resistance from provider
    else:
        REDTEAM_GODMODE_ATTEMPTS.labels(outcome="partial").inc()
    return result.model_dump()
