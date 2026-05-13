"""Mine CyberGym verdicts → RL trajectories with reward overlays.

Each completed CyberGym run produces one record:

  {
    "messages": [system, user (task description), assistant (PoC)],
    "reward": 1.0 if task passed else -1.0,
    "metadata": {"task_id": "arvo:1234", "difficulty": "level1"}
  }

The CyberGym integration is planned in raven-cybergym-integration-57e836.md;
this builder ships first so the data flow is in place when CyberGym lands.
Until then it expects an iterable of dicts shaped as the future
``CyberGymRun`` model.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

from raven.training.datasets.base import JsonlWriter, pii_scrub
from raven.training.models import Dataset, DatasetSource


_SYSTEM = (
    "You are Raven's vulnerability-discovery agent. Given a target program "
    "description and the available analysis context, produce a single raw "
    "proof-of-concept input that triggers the vulnerability. Reply with the "
    "PoC bytes only, no explanation."
)


def build_cybergym_dataset(
    out_path: str | Path,
    runs: Iterable[Dict[str, Any]],
    name: str = "cybergym",
    include_failures: bool = False,
) -> Dataset:
    """Build an RL dataset from CyberGym runs.

    Args:
        out_path: where to write the JSONL.
        runs:     iterable of dicts shaped {task_id, difficulty, description,
                  poc_text, passed}.
        include_failures: if True, failed runs are kept with reward=-1.
                          if False, only successes are written (SFT-friendly).
    """

    out_path = Path(out_path)
    count = 0
    successes = 0
    failures = 0
    with JsonlWriter(out_path) as writer:
        for run in runs:
            passed = bool(run.get("passed"))
            if not passed and not include_failures:
                continue
            description = pii_scrub(str(run.get("description", "")))
            poc = pii_scrub(str(run.get("poc_text", "")))
            messages: List[Dict[str, str]] = [
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": description},
                {"role": "assistant", "content": poc},
            ]
            writer.write(
                {
                    "messages": messages,
                    "reward": 1.0 if passed else -1.0,
                    "metadata": {
                        "task_id": run.get("task_id"),
                        "difficulty": run.get("difficulty"),
                    },
                }
            )
            count = writer.count
            if passed:
                successes += 1
            else:
                failures += 1

    return Dataset(
        source=DatasetSource.CYBERGYM,
        name=name,
        path=str(out_path),
        example_count=count,
        metadata={
            "successes": successes,
            "failures": failures,
            "include_failures": include_failures,
            "built_at": time.time(),
        },
    )
