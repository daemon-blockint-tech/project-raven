"""ABTestRouter — Bernoulli traffic split with auto-promote and auto-rollback.

The router maintains an in-memory ``ABTestRun`` (also persisted in the
registry) and provides:

  * ``choose()``  — pick "candidate" or "incumbent" per request
  * ``record()``  — log the outcome (with a numeric score); auto-decides if
                    sample count and win-rate cross thresholds
  * ``status()``  — current counters + decision

A single router instance is created per ``run_id``. For multi-replica K8s,
swap the internal counters for Redis (Phase 3 lite); the interface is the
same.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from typing import Optional

from raven.training.models import ABTestRun, ABTestState
from raven.training.registry import registry

log = logging.getLogger(__name__)

_VARIANT_CANDIDATE = "candidate"
_VARIANT_INCUMBENT = "incumbent"


class ABTestRouter:
    """Wraps an :class:`ABTestRun` with traffic-routing + decision logic."""

    def __init__(self, run: ABTestRun) -> None:
        self.run = run
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @classmethod
    def start(
        cls,
        *,
        candidate_model_id: str,
        incumbent_model_id: Optional[str] = None,
        traffic_pct: float = 0.05,
        min_samples: int = 500,
        promote_threshold_pct: float = 0.95,
    ) -> "ABTestRouter":
        run = ABTestRun(
            candidate_model_id=candidate_model_id,
            incumbent_model_id=incumbent_model_id,
            traffic_pct=max(0.0, min(1.0, traffic_pct)),
            min_samples=max(1, min_samples),
            promote_threshold_pct=max(0.5, min(1.0, promote_threshold_pct)),
        )
        registry().register_abtest(run)
        return cls(run)

    def stop(self, decision: str = "stopped") -> ABTestRun:
        with self._lock:
            self.run.state = ABTestState.STOPPED
            self.run.decided_at = time.time()
            self.run.decision = decision
            registry().update_abtest(self.run)
        return self.run

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def choose(self, _rand: Optional[random.Random] = None) -> str:
        if self.run.state != ABTestState.RUNNING:
            return _VARIANT_INCUMBENT
        rng = _rand or random
        return (
            _VARIANT_CANDIDATE
            if rng.random() < self.run.traffic_pct
            else _VARIANT_INCUMBENT
        )

    # ------------------------------------------------------------------
    # Recording outcomes
    # ------------------------------------------------------------------

    def record(self, variant: str, score: float = 1.0) -> ABTestRun:
        """Record an outcome. ``score`` ∈ [-1, 1] is the win signal.
        Positive = candidate won; negative = candidate lost.
        For incumbent-variant requests, score is from incumbent's POV
        (positive = incumbent won) so the sums stay comparable."""
        with self._lock:
            if self.run.state != ABTestState.RUNNING:
                return self.run
            if variant == _VARIANT_CANDIDATE:
                if score > 0:
                    self.run.candidate_wins += 1
                else:
                    self.run.incumbent_wins += 1
                self.run.candidate_score_sum += score
            else:
                if score > 0:
                    self.run.incumbent_wins += 1
                else:
                    self.run.candidate_wins += 1
                self.run.incumbent_score_sum += score
            registry().update_abtest(self.run)
            self._maybe_decide()
            return self.run

    def _maybe_decide(self) -> None:
        if self.run.total_samples < self.run.min_samples:
            return
        win_rate = self.run.candidate_win_rate
        if win_rate >= self.run.promote_threshold_pct:
            self.run.state = ABTestState.PROMOTED
            self.run.decision = "promote"
            self.run.decided_at = time.time()
            registry().update_abtest(self.run)
            try:
                registry().promote_model(self.run.candidate_model_id)
            except Exception as exc:
                log.warning("abtest.promote.failed run=%s err=%s", self.run.run_id, exc)
        elif win_rate <= (1.0 - self.run.promote_threshold_pct):
            self.run.state = ABTestState.ROLLED_BACK
            self.run.decision = "rollback"
            self.run.decided_at = time.time()
            registry().update_abtest(self.run)
            try:
                registry().rollback_model(
                    self.run.candidate_model_id,
                    reason="abtest_lost",
                )
            except Exception as exc:
                log.warning(
                    "abtest.rollback.failed run=%s err=%s", self.run.run_id, exc
                )


def get_router(run_id: str) -> Optional[ABTestRouter]:
    run = registry().get_abtest(run_id)
    if run is None:
        return None
    return ABTestRouter(run)
