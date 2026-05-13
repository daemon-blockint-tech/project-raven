"""ModelRegistry — thread-safe in-memory store of versions, jobs, datasets,
and A/B-test runs.

Designed so the same interface can be backed by SQLAlchemy + Alembic later
(Phase 3 lite) without touching callers. The Pydantic models are JSON-able,
so a future ORM mapping is mechanical.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from raven.training.models import (
    ABTestRun,
    ABTestState,
    Dataset,
    ModelStatus,
    ModelVersion,
    TrainingJob,
)


class ModelRegistry:
    """Thread-safe in-memory registry. Public methods are deliberately
    declarative — no I/O beyond the optional JSONL spill below."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._datasets: Dict[str, Dataset] = {}
        self._jobs: Dict[str, TrainingJob] = {}
        self._models: Dict[str, ModelVersion] = {}
        self._abtests: Dict[str, ABTestRun] = {}
        self._promoted_model_id: Optional[str] = None

    # ----- datasets ----------------------------------------------------

    def register_dataset(self, dataset: Dataset) -> Dataset:
        with self._lock:
            self._datasets[dataset.dataset_id] = dataset
            return dataset

    def get_dataset(self, dataset_id: str) -> Optional[Dataset]:
        return self._datasets.get(dataset_id)

    def list_datasets(self) -> List[Dataset]:
        return sorted(self._datasets.values(), key=lambda d: d.created_at, reverse=True)

    # ----- jobs --------------------------------------------------------

    def register_job(self, job: TrainingJob) -> TrainingJob:
        with self._lock:
            self._jobs[job.job_id] = job
            return job

    def update_job(self, job: TrainingJob) -> TrainingJob:
        with self._lock:
            self._jobs[job.job_id] = job
            return job

    def get_job(self, job_id: str) -> Optional[TrainingJob]:
        return self._jobs.get(job_id)

    def list_jobs(self) -> List[TrainingJob]:
        return sorted(self._jobs.values(), key=lambda j: j.started_at, reverse=True)

    # ----- model versions ---------------------------------------------

    def register_model(self, model: ModelVersion) -> ModelVersion:
        with self._lock:
            self._models[model.model_id] = model
            return model

    def update_model(self, model: ModelVersion) -> ModelVersion:
        with self._lock:
            self._models[model.model_id] = model
            return model

    def get_model(self, model_id: str) -> Optional[ModelVersion]:
        return self._models.get(model_id)

    def list_models(self, status: Optional[ModelStatus] = None) -> List[ModelVersion]:
        models = list(self._models.values())
        if status is not None:
            models = [m for m in models if m.status == status]
        return sorted(models, key=lambda m: m.created_at, reverse=True)

    def promote_model(self, model_id: str) -> ModelVersion:
        with self._lock:
            model = self._models.get(model_id)
            if model is None:
                raise KeyError(f"model not found: {model_id}")
            # Demote the previous promoted model
            if self._promoted_model_id and self._promoted_model_id != model_id:
                prev = self._models.get(self._promoted_model_id)
                if prev is not None:
                    prev.status = ModelStatus.DEMOTED
                    self._models[prev.model_id] = prev
            model.status = ModelStatus.PROMOTED
            model.promoted_at = time.time()
            self._models[model_id] = model
            self._promoted_model_id = model_id
            return model

    def rollback_model(self, model_id: str, reason: Optional[str] = None) -> ModelVersion:
        with self._lock:
            model = self._models.get(model_id)
            if model is None:
                raise KeyError(f"model not found: {model_id}")
            model.status = ModelStatus.ROLLED_BACK
            model.rolled_back_at = time.time()
            if reason:
                model.notes = (model.notes or "") + f"\nrolled_back: {reason}"
            self._models[model_id] = model
            if self._promoted_model_id == model_id:
                self._promoted_model_id = None
            return model

    def promoted_model(self) -> Optional[ModelVersion]:
        if self._promoted_model_id is None:
            return None
        return self._models.get(self._promoted_model_id)

    # ----- A/B tests ---------------------------------------------------

    def register_abtest(self, run: ABTestRun) -> ABTestRun:
        with self._lock:
            self._abtests[run.run_id] = run
            return run

    def update_abtest(self, run: ABTestRun) -> ABTestRun:
        with self._lock:
            self._abtests[run.run_id] = run
            return run

    def get_abtest(self, run_id: str) -> Optional[ABTestRun]:
        return self._abtests.get(run_id)

    def list_abtests(self, state: Optional[ABTestState] = None) -> List[ABTestRun]:
        runs = list(self._abtests.values())
        if state is not None:
            runs = [r for r in runs if r.state == state]
        return sorted(runs, key=lambda r: r.started_at, reverse=True)

    # ----- maintenance -------------------------------------------------

    def reset(self) -> None:
        """Tests only."""
        with self._lock:
            self._datasets.clear()
            self._jobs.clear()
            self._models.clear()
            self._abtests.clear()
            self._promoted_model_id = None


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_singleton: Optional[ModelRegistry] = None
_singleton_lock = threading.Lock()


def registry() -> ModelRegistry:
    global _singleton
    if _singleton is not None:
        return _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = ModelRegistry()
        return _singleton


def reset_registry() -> None:
    """Tests only."""
    global _singleton
    _singleton = None
