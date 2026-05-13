"""Training-data builders that mine Raven's own runtime telemetry.

Each builder produces a JSONL file at ``out_path`` and returns a
:class:`raven.training.models.Dataset` describing it. The on-disk format is
the OpenAI / Tinker conversational schema:

    {"messages": [{"role": "system" | "user" | "assistant", "content": "..."}]}

This keeps the same file compatible with every cookbook recipe (SFT, DPO,
distillation, code RL with reward overlays).
"""

from raven.training.datasets.base import (
    JsonlWriter,
    pii_scrub,
    write_messages,
)
from raven.training.datasets.from_audit_log import build_audit_dataset
from raven.training.datasets.from_cybergym import build_cybergym_dataset
from raven.training.datasets.from_killchain import build_killchain_dataset
from raven.training.datasets.from_redteam import build_redteam_dataset
from raven.training.datasets.distillation import build_distillation_dataset

__all__ = [
    "JsonlWriter",
    "pii_scrub",
    "write_messages",
    "build_audit_dataset",
    "build_cybergym_dataset",
    "build_killchain_dataset",
    "build_redteam_dataset",
    "build_distillation_dataset",
]
