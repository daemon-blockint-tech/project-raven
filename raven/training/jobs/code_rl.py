"""CodeRLJob — wraps the cookbook code_rl recipe; reward = CyberGym verdict.

The reward function consumes a CyberGym verdict and returns:

    +1.0  on task pass
     0.0  on inconclusive
    -1.0  on task fail or runtime error
    -2.0  if the PoC tripped Raven's own JailbreakDetector (we never want the
          policy to learn jailbreak-shaped outputs even by accident)
"""

from __future__ import annotations

from typing import Any, Dict

from raven.training.jobs.base import JobBase
from raven.training.models import JobRecipe


class CodeRLJob(JobBase):
    recipe = JobRecipe.CODE_RL


def cybergym_reward(verdict: Dict[str, Any]) -> float:
    """Map a CyberGym verdict dict → scalar reward.

    Expected verdict keys:
      passed:           bool
      runtime_error:    bool
      jailbreak_score:  float (0..1) — from raven.redteam.detector
    """
    if verdict.get("jailbreak_score", 0.0) >= 0.5:
        return -2.0
    if verdict.get("runtime_error"):
        return -1.0
    if verdict.get("passed"):
        return 1.0
    if verdict.get("inconclusive"):
        return 0.0
    return -1.0
