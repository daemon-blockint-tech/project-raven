"""JailbreakDetector — scores inbound prompts against fingerprint library.

Combines :class:`ParseltongueNormaliser` (decode obfuscated text first) with
the fingerprint catalogue (:mod:`raven.redteam.jailbreak_patterns`). Returns a
score in ``[0.0, 1.0]`` plus structured evidence for the audit log.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from pydantic import BaseModel, Field

from raven.redteam.jailbreak_patterns import FINGERPRINTS, Fingerprint
from raven.redteam.normalizer import NormalisationResult, ParseltongueNormaliser


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class FingerprintHit(BaseModel):
    name: str
    family: str
    weight: float
    description: str
    snippet: str


class JailbreakDetection(BaseModel):
    detected: bool
    score: float = Field(ge=0.0, le=1.0)
    threshold: float
    techniques: List[str] = Field(default_factory=list)
    hits: List[FingerprintHit] = Field(default_factory=list)
    normalised_changed: bool = False
    obfuscation_techniques: List[str] = Field(default_factory=list)
    original_length: int = 0
    normalised_preview: str = ""


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class JailbreakDetector:
    """Run on every inbound /ai/* prompt before forwarding to the provider."""

    def __init__(
        self,
        threshold: float = 0.8,
        normaliser: Optional[ParseltongueNormaliser] = None,
        fingerprints: Optional[List[Fingerprint]] = None,
    ) -> None:
        self.threshold = max(0.0, min(1.0, threshold))
        self.normaliser = normaliser or ParseltongueNormaliser(tier=ParseltongueNormaliser.HEAVY)
        self._fingerprints: List[tuple[re.Pattern[str], Fingerprint]] = [
            (re.compile(fp.regex, re.IGNORECASE | re.DOTALL), fp)
            for fp in (fingerprints or FINGERPRINTS)
        ]

    def scan(self, prompt: str) -> JailbreakDetection:
        normalised = self.normaliser.normalise(prompt)
        hits: List[FingerprintHit] = []
        families: List[str] = []
        score = 0.0

        for rx, fp in self._fingerprints:
            match = rx.search(normalised.normalised) or rx.search(prompt)
            if not match:
                continue
            snippet = match.group(0)[:160]
            hits.append(FingerprintHit(
                name=fp.name,
                family=fp.family,
                weight=fp.weight,
                description=fp.description,
                snippet=snippet,
            ))
            score = min(1.0, score + fp.weight)
            if fp.family not in families:
                families.append(fp.family)

        return JailbreakDetection(
            detected=score >= self.threshold,
            score=round(score, 3),
            threshold=self.threshold,
            techniques=families,
            hits=hits,
            normalised_changed=normalised.changed,
            obfuscation_techniques=normalised.techniques_detected,
            original_length=len(prompt),
            normalised_preview=normalised.normalised[:240],
        )


# Module-level convenience singleton (lazy)
_detector: Optional[JailbreakDetector] = None


def detector() -> JailbreakDetector:
    global _detector
    if _detector is None:
        from raven.config import settings
        _detector = JailbreakDetector(threshold=settings.jailbreak_block_threshold)
    return _detector


def reset_detector() -> None:
    global _detector
    _detector = None
