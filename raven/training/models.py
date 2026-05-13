"""Training-subsystem domain models.

Used both as Pydantic API payloads and (when SQLAlchemy is available) as
ORM mappings. The Pydantic-only path stays usable without Postgres so dev
and CI can run without a DB.
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class DatasetSource(str, Enum):
    AUDIT_LOG = "audit_log"
    CYBERGYM = "cybergym"
    KILLCHAIN = "killchain"
    REDTEAM = "redteam"
    DISTILLATION = "distillation"
    MANUAL = "manual"


class JobRecipe(str, Enum):
    DISTILL = "distill"
    SFT = "sft"
    CODE_RL = "code_rl"
    TOOL_USE = "tool_use"
    PREFERENCE = "preference"


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ModelStatus(str, Enum):
    CANDIDATE = "candidate"
    EVALUATING = "evaluating"
    PROMOTED = "promoted"
    DEMOTED = "demoted"
    ROLLED_BACK = "rolled_back"
    ARCHIVED = "archived"


class ABTestState(str, Enum):
    RUNNING = "running"
    PROMOTED = "promoted"
    ROLLED_BACK = "rolled_back"
    STOPPED = "stopped"


# ---------------------------------------------------------------------------
# Payloads (Pydantic v2)
# ---------------------------------------------------------------------------


class Dataset(BaseModel):
    """A curated training corpus on disk (or remotely)."""

    dataset_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    source: DatasetSource
    name: str
    path: str
    example_count: int = 0
    schema_version: int = 1
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)


class TrainingJob(BaseModel):
    """A submitted Tinker fine-tune run."""

    job_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    recipe: JobRecipe
    dataset_id: str
    base_model: str
    rank: int = 64
    epochs: int = 3
    learning_rate: float = 1e-4
    state: JobState = JobState.QUEUED
    tinker_job_id: Optional[str] = None
    checkpoint_path: Optional[str] = None
    started_at: float = Field(default_factory=time.time)
    finished_at: Optional[float] = None
    error: Optional[str] = None
    metrics: Dict[str, float] = Field(default_factory=dict)
    actor: Optional[str] = None


class ModelVersion(BaseModel):
    """A trained checkpoint ready to be A/B-tested or promoted."""

    model_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str
    base_model: str
    rank: int
    dataset_id: str
    training_job_id: Optional[str] = None
    checkpoint_path: str
    status: ModelStatus = ModelStatus.CANDIDATE
    eval_scores: Dict[str, float] = Field(default_factory=dict)
    promoted_at: Optional[float] = None
    rolled_back_at: Optional[float] = None
    notes: Optional[str] = None
    created_at: float = Field(default_factory=time.time)


class ABTestRun(BaseModel):
    """Routes a percentage of traffic to a candidate model."""

    run_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    candidate_model_id: str
    incumbent_model_id: Optional[str] = None  # None => current ProviderRegistry default
    traffic_pct: float = 0.05
    min_samples: int = 500
    promote_threshold_pct: float = 0.95
    state: ABTestState = ABTestState.RUNNING
    candidate_wins: int = 0
    incumbent_wins: int = 0
    candidate_score_sum: float = 0.0
    incumbent_score_sum: float = 0.0
    started_at: float = Field(default_factory=time.time)
    decided_at: Optional[float] = None
    decision: Optional[str] = None  # "promote" | "rollback" | "inconclusive"

    @property
    def total_samples(self) -> int:
        return self.candidate_wins + self.incumbent_wins

    @property
    def candidate_win_rate(self) -> float:
        total = self.total_samples
        return self.candidate_wins / total if total else 0.0
