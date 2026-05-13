"""Abstract training-job base. Each subclass wraps one cookbook recipe."""

from __future__ import annotations

import abc
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from raven.training.client import TinkerJobStatus, tinker_client
from raven.training.models import (
    Dataset,
    JobRecipe,
    JobState,
    ModelVersion,
    TrainingJob,
)
from raven.training.registry import registry

log = logging.getLogger(__name__)


@dataclass
class JobResult:
    job: TrainingJob
    model: Optional[ModelVersion]
    status: TinkerJobStatus


class JobBase(abc.ABC):
    """Base class for training jobs.

    Subclasses provide the recipe and parameters; this class handles
    submission, polling, registry updates, and audit/metric hooks.
    """

    recipe: JobRecipe = JobRecipe.SFT

    def __init__(
        self,
        dataset: Dataset,
        base_model: str = "meta-llama/Llama-3.1-8B-Instruct",
        rank: int = 64,
        epochs: int = 3,
        learning_rate: float = 1e-4,
        actor: Optional[str] = None,
    ) -> None:
        self.dataset = dataset
        self.base_model = base_model
        self.rank = rank
        self.epochs = epochs
        self.learning_rate = learning_rate
        self.actor = actor

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> TrainingJob:
        """Submit the job to Tinker (or the mock client) and register it."""
        client = tinker_client()
        tinker_job_id = client.start_job(
            base_model=self.base_model,
            dataset_path=self.dataset.path,
            rank=self.rank,
            epochs=self.epochs,
            learning_rate=self.learning_rate,
            recipe=self.recipe.value,
        )
        job = TrainingJob(
            recipe=self.recipe,
            dataset_id=self.dataset.dataset_id,
            base_model=self.base_model,
            rank=self.rank,
            epochs=self.epochs,
            learning_rate=self.learning_rate,
            state=JobState.RUNNING,
            tinker_job_id=tinker_job_id,
            actor=self.actor,
        )
        registry().register_job(job)
        log.info("training.job.started recipe=%s base=%s rank=%d", self.recipe.value, self.base_model, self.rank)
        return job

    def poll(self, job: TrainingJob) -> TrainingJob:
        """Refresh the registry entry from Tinker. Idempotent on terminal state."""
        if job.state in {JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED}:
            return job
        status = tinker_client().status(job.tinker_job_id or "")
        new_state = self._map_state(status.state)
        job.state = new_state
        if status.metrics:
            job.metrics.update({k: float(v) for k, v in status.metrics.items()})
        if status.checkpoint_path:
            job.checkpoint_path = status.checkpoint_path
        if new_state in {JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED}:
            job.finished_at = time.time()
            job.error = status.error
        registry().update_job(job)
        return job

    def cancel(self, job: TrainingJob) -> TrainingJob:
        ok = tinker_client().cancel(job.tinker_job_id or "")
        if ok:
            job.state = JobState.CANCELLED
            job.finished_at = time.time()
            registry().update_job(job)
        return job

    def to_model_version(self, job: TrainingJob, name: Optional[str] = None) -> ModelVersion:
        """Register a ModelVersion from a finished job."""
        if job.state != JobState.SUCCEEDED:
            raise ValueError(f"job not in SUCCEEDED state (got {job.state})")
        if not job.checkpoint_path:
            raise ValueError("job has no checkpoint_path")
        model_name = name or f"raven-{self.recipe.value}-{job.job_id}"
        model = ModelVersion(
            name=model_name,
            base_model=job.base_model,
            rank=job.rank,
            dataset_id=job.dataset_id,
            training_job_id=job.job_id,
            checkpoint_path=job.checkpoint_path,
        )
        return registry().register_model(model)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _map_state(raw: str) -> JobState:
        raw = (raw or "").lower()
        if raw in {"succeeded", "success", "completed"}:
            return JobState.SUCCEEDED
        if raw in {"failed", "error"}:
            return JobState.FAILED
        if raw in {"cancelled", "canceled"}:
            return JobState.CANCELLED
        if raw in {"queued", "pending"}:
            return JobState.QUEUED
        return JobState.RUNNING
