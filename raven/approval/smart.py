"""Smart approval — uses Raven's own ``ModelOrchestrator`` to triage risk.

The auxiliary classifier runs in the FAST role (cheap small model) and returns
``approve | deny | escalate``. Failure-modes fail-closed (escalate).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Literal, Optional

from raven.ai.base import AIMessage
from raven.approval.models import DangerousPattern

log = logging.getLogger(__name__)

SmartVerdict = Literal["approve", "deny", "escalate"]


@dataclass
class SmartAssessment:
    verdict: SmartVerdict
    reasoning: str
    raw: str


_SYSTEM_PROMPT = (
    "You are a security gatekeeper for Project Raven. You are shown a "
    "command that matched a dangerous-action pattern. Decide whether it is "
    "safe to auto-approve, must be auto-denied, or must be escalated to a "
    "human operator. Respond with strict JSON only:\n"
    '{"verdict": "approve" | "deny" | "escalate", "reason": "<short>"}.\n\n'
    "Rules:\n"
    " * Default to 'escalate' when uncertain.\n"
    " * 'approve' only for clearly benign cases that hit a false-positive pattern.\n"
    " * 'deny' only for clearly destructive or out-of-policy commands.\n"
    " * Never 'approve' anything that writes to /etc, /dev, ~/.ssh, or "
    "shuts services down without specific justification.\n"
)


class SmartApprover:
    """LLM-assisted approval triage."""

    def __init__(self, orchestrator: Optional[object] = None) -> None:
        # Lazy-import to keep the approval package importable without a live AI
        from raven.ai.model_orchestrator import ModelOrchestrator
        from raven.ai.registry import ProviderRegistry

        if orchestrator is None:
            client = ProviderRegistry.get_instance().get_client()
            orchestrator = ModelOrchestrator(client)
        self._orchestrator: ModelOrchestrator = orchestrator  # type: ignore[assignment]

    def assess(self, command: str, pattern: DangerousPattern) -> SmartAssessment:
        from raven.ai.model_orchestrator import ModelRole

        user = (
            f"Pattern matched: {pattern.description} (severity={pattern.severity})\n"
            f"Command:\n{command}\n\nReturn JSON now."
        )
        try:
            resp = self._orchestrator.chat(
                ModelRole.FAST,
                [
                    AIMessage(role="system", content=_SYSTEM_PROMPT),
                    AIMessage(role="user", content=user),
                ],
                temperature=0.0,
                max_tokens=200,
            )
        except Exception as exc:
            log.warning("SmartApprover LLM call failed (%s) — fail-closed escalate", exc)
            return SmartAssessment(
                verdict="escalate",
                reasoning=f"classifier_unavailable: {exc}",
                raw="",
            )

        return _parse(resp.content or "")


# ---------------------------------------------------------------------------
# Robust JSON parser — tolerant of LLM preambles / trailing markdown fences
# ---------------------------------------------------------------------------

_VERDICTS = {"approve", "deny", "escalate"}


def _parse(raw: str) -> SmartAssessment:
    text = raw.strip()
    # Try to extract a JSON object substring
    match = re.search(r"\{.*?\}", text, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(0))
            verdict = str(data.get("verdict", "")).lower().strip()
            if verdict in _VERDICTS:
                return SmartAssessment(
                    verdict=verdict,  # type: ignore[arg-type]
                    reasoning=str(data.get("reason", ""))[:300],
                    raw=raw,
                )
        except json.JSONDecodeError:
            pass

    # Fallback heuristic on plain text
    lo = text.lower()
    if "approve" in lo and "deny" not in lo:
        return SmartAssessment(verdict="approve", reasoning="text-heuristic", raw=raw)
    if "deny" in lo and "approve" not in lo:
        return SmartAssessment(verdict="deny", reasoning="text-heuristic", raw=raw)
    return SmartAssessment(verdict="escalate", reasoning="unparseable", raw=raw)
