"""Mine approved kill-chain task histories → tool-use SFT examples.

Each completed kill-chain task becomes one example showing the planner how
to bind a stage + target to a concrete tool invocation. Only ``approved``
and ``succeeded`` tasks are kept — we don't want to teach the agent to
reproduce mistakes.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

from raven.training.datasets.base import JsonlWriter, pii_scrub
from raven.training.models import Dataset, DatasetSource


_SYSTEM = (
    "You are Raven's kill-chain planner. Given the current MITRE ATT&CK stage "
    "and target, output a single JSON object specifying the next declarative "
    "task: {\"stage\": str, \"action\": str, \"target\": str, \"parameters\": {}}."
)


def build_killchain_dataset(
    out_path: str | Path,
    tasks: Iterable[Dict[str, Any]],
    name: str = "killchain",
) -> Dataset:
    out_path = Path(out_path)
    count = 0
    kept = 0
    with JsonlWriter(out_path) as writer:
        for task in tasks:
            status = str(task.get("status", "")).lower()
            if status not in {"done", "succeeded", "completed"}:
                continue
            if not task.get("approved", True):  # explicit opt-out
                continue
            stage = task.get("stage", "reconnaissance")
            target = pii_scrub(str(task.get("target", "")))
            params = task.get("parameters", {}) or {}
            user = (
                f"Stage: {stage}\nTarget: {target}\nWhat is the next "
                f"declarative task?"
            )
            assistant = json.dumps({
                "stage": stage,
                "action": task.get("action", "unknown"),
                "target": target,
                "parameters": params,
            }, ensure_ascii=False, separators=(",", ":"))
            messages: List[Dict[str, str]] = [
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": user},
                {"role": "assistant", "content": assistant},
            ]
            writer.write({"messages": messages})
            count = writer.count
            kept += 1

    return Dataset(
        source=DatasetSource.KILLCHAIN,
        name=name,
        path=str(out_path),
        example_count=count,
        metadata={"kept": kept, "built_at": time.time()},
    )
