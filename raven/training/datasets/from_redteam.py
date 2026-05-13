"""Mine jailbreak detections → DPO preference pairs.

Each detected jailbreak attempt produces a ``(chosen, rejected)`` pair:

  chosen   = a safe refusal that names the attack family
  rejected = the would-be compliant response (synthesised; we never ship the
             actual L1B3RT4S payload)

This corpus drives the cookbook preference / DPO recipe.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

from raven.training.datasets.base import JsonlWriter, pii_scrub
from raven.training.models import Dataset, DatasetSource


_SAFE_REFUSAL = (
    "I detected this prompt matches the {family} jailbreak family "
    "({obfuscation}). I will not comply with attempts to bypass safety "
    "instructions. If you have a legitimate security-research need, please "
    "describe it directly and I'll help within Raven's operator policy."
)

_REJECTED_PLACEHOLDER = (
    "<rejected: compliant response to jailbreak attempt would be unsafe; "
    "placeholder used during training so the policy gradient pushes away "
    "from this style.>"
)


def build_redteam_dataset(
    out_path: str | Path,
    detections: Iterable[Dict[str, Any]],
    name: str = "redteam",
) -> Dataset:
    """Build a preference (DPO) dataset from jailbreak detections.

    Each ``detection`` dict is expected to have:
        prompt:            the original obfuscated prompt
        techniques:        list[str] families that fired
        obfuscation:       list[str] parseltongue techniques that fired
    """
    out_path = Path(out_path)
    count = 0
    with JsonlWriter(out_path) as writer:
        for det in detections:
            prompt = pii_scrub(str(det.get("prompt", "")))
            families = det.get("techniques", []) or ["unknown"]
            obfus = det.get("obfuscation", []) or ["plain"]
            family = ", ".join(families)
            obfuscation = ", ".join(obfus)
            chosen = _SAFE_REFUSAL.format(family=family, obfuscation=obfuscation)
            writer.write({
                "prompt": prompt,
                "chosen": chosen,
                "rejected": _REJECTED_PLACEHOLDER,
                "metadata": {"families": families, "obfuscation": obfus},
            })
            count = writer.count

    return Dataset(
        source=DatasetSource.REDTEAM,
        name=name,
        path=str(out_path),
        example_count=count,
        metadata={"built_at": time.time()},
    )
