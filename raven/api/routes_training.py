"""REST endpoints for the training subsystem.

All mutating routes require ``admin`` role + audit log (provided by the
Phase 1 middleware). Read routes accept any authenticated user.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from raven.auth.dependencies import current_user, require_admin
from raven.auth.models import User
from raven.observability.metrics import (
    ABTEST_TRAFFIC,
    ABTEST_WIN_RATE,
    MODEL_VERSIONS,
    TRAINING_DATASET_SIZE,
    TRAINING_JOBS,
)
from raven.training.abtest import ABTestRouter, get_router
from raven.training.client import tinker_client
from raven.training.eval import evaluate_model
from raven.training.jobs import CodeRLJob, DistillJob, SFTJob
from raven.training.models import (
    Dataset,
    DatasetSource,
    JobRecipe,
    ModelStatus,
    ModelVersion,
    TrainingJob,
)
from raven.training.registry import registry


router = APIRouter(prefix="/training", tags=["training"])


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


class DatasetRegisterRequest(BaseModel):
    source: DatasetSource
    name: str
    path: str
    example_count: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class JobStartRequest(BaseModel):
    recipe: JobRecipe = JobRecipe.DISTILL
    dataset_id: str
    base_model: Optional[str] = None
    rank: int = 64
    epochs: int = 3
    learning_rate: float = 1e-4


class ABTestStartRequest(BaseModel):
    candidate_model_id: str
    traffic_pct: float = 0.05
    min_samples: int = 500
    promote_threshold_pct: float = 0.95


class ABTestRecordRequest(BaseModel):
    variant: str  # "candidate" | "incumbent"
    score: float = 1.0


# ---------------------------------------------------------------------------
# Tinker status (read-only)
# ---------------------------------------------------------------------------


@router.get("/tinker/status")
async def tinker_status(user: User = Depends(current_user)):
    client = tinker_client()
    return {
        "client_type": type(client).__name__,
        "available": client.is_available(),
        "base_models": client.list_base_models(),
    }


# ---------------------------------------------------------------------------
# Datasets
# ---------------------------------------------------------------------------


@router.get("/datasets", response_model=List[Dataset])
async def list_datasets(user: User = Depends(current_user)):
    return registry().list_datasets()


@router.post("/datasets", response_model=Dataset)
async def register_dataset(
    payload: DatasetRegisterRequest, user: User = Depends(require_admin)
):
    dataset = Dataset(
        source=payload.source,
        name=payload.name,
        path=payload.path,
        example_count=payload.example_count,
        metadata=payload.metadata,
    )
    registered = registry().register_dataset(dataset)
    TRAINING_DATASET_SIZE.labels(source=payload.source.value).set(payload.example_count)
    return registered


@router.get("/datasets/{dataset_id}", response_model=Dataset)
async def get_dataset(dataset_id: str, user: User = Depends(current_user)):
    dataset = registry().get_dataset(dataset_id)
    if dataset is None:
        raise HTTPException(status_code=404, detail="dataset not found")
    return dataset


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

_JOB_CLASSES = {
    JobRecipe.DISTILL: DistillJob,
    JobRecipe.SFT: SFTJob,
    JobRecipe.CODE_RL: CodeRLJob,
}


@router.get("/jobs", response_model=List[TrainingJob])
async def list_jobs(user: User = Depends(current_user)):
    return registry().list_jobs()


@router.post("/jobs", response_model=TrainingJob)
async def start_job(payload: JobStartRequest, user: User = Depends(require_admin)):
    from raven.config import settings

    dataset = registry().get_dataset(payload.dataset_id)
    if dataset is None:
        raise HTTPException(
            status_code=404, detail=f"dataset not found: {payload.dataset_id}"
        )
    job_cls = _JOB_CLASSES.get(payload.recipe)
    if job_cls is None:
        raise HTTPException(
            status_code=400, detail=f"unsupported recipe: {payload.recipe.value}"
        )
    job_obj = job_cls(
        dataset=dataset,
        base_model=payload.base_model or settings.tinker_default_base_model,
        rank=payload.rank,
        epochs=payload.epochs,
        learning_rate=payload.learning_rate,
        actor=user.username,
    )
    job = job_obj.start()
    TRAINING_JOBS.labels(recipe=payload.recipe.value, outcome="started").inc()
    return job


@router.get("/jobs/{job_id}", response_model=TrainingJob)
async def get_job(job_id: str, user: User = Depends(current_user)):
    job = registry().get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    # Poll for fresh state
    job_cls = _JOB_CLASSES.get(job.recipe, SFTJob)
    dataset = registry().get_dataset(job.dataset_id) or Dataset(
        source=DatasetSource.MANUAL,
        name="orphan",
        path="",
    )
    return job_cls(dataset=dataset, base_model=job.base_model, rank=job.rank).poll(job)


@router.post("/jobs/{job_id}/cancel", response_model=TrainingJob)
async def cancel_job(job_id: str, user: User = Depends(require_admin)):
    job = registry().get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    job_cls = _JOB_CLASSES.get(job.recipe, SFTJob)
    dataset = registry().get_dataset(job.dataset_id) or Dataset(
        source=DatasetSource.MANUAL,
        name="orphan",
        path="",
    )
    cancelled = job_cls(
        dataset=dataset, base_model=job.base_model, rank=job.rank
    ).cancel(job)
    TRAINING_JOBS.labels(recipe=job.recipe.value, outcome="cancelled").inc()
    return cancelled


@router.post("/jobs/{job_id}/finalize", response_model=ModelVersion)
async def finalize_job(
    job_id: str,
    name: Optional[str] = None,
    user: User = Depends(require_admin),
):
    """Convert a SUCCEEDED job into a ModelVersion."""
    job = registry().get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    job_cls = _JOB_CLASSES.get(job.recipe, SFTJob)
    dataset = registry().get_dataset(job.dataset_id) or Dataset(
        source=DatasetSource.MANUAL,
        name="orphan",
        path="",
    )
    job_obj = job_cls(dataset=dataset, base_model=job.base_model, rank=job.rank)
    try:
        model = job_obj.to_model_version(job, name=name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    TRAINING_JOBS.labels(recipe=job.recipe.value, outcome="succeeded").inc()
    _refresh_model_gauges()
    return model


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@router.get("/models", response_model=List[ModelVersion])
async def list_models(
    status: Optional[ModelStatus] = None,
    user: User = Depends(current_user),
):
    return registry().list_models(status=status)


@router.get("/models/{model_id}", response_model=ModelVersion)
async def get_model(model_id: str, user: User = Depends(current_user)):
    model = registry().get_model(model_id)
    if model is None:
        raise HTTPException(status_code=404, detail="model not found")
    return model


@router.post("/models/{model_id}/eval", response_model=ModelVersion)
async def eval_model(model_id: str, user: User = Depends(require_admin)):
    model = registry().get_model(model_id)
    if model is None:
        raise HTTPException(status_code=404, detail="model not found")
    return evaluate_model(model)


@router.post("/models/{model_id}/promote", response_model=ModelVersion)
async def promote_model(model_id: str, user: User = Depends(require_admin)):
    try:
        result = registry().promote_model(model_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    _refresh_model_gauges()
    return result


@router.post("/models/{model_id}/rollback", response_model=ModelVersion)
async def rollback_model(
    model_id: str,
    reason: Optional[str] = None,
    user: User = Depends(require_admin),
):
    try:
        result = registry().rollback_model(model_id, reason=reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    _refresh_model_gauges()
    return result


# ---------------------------------------------------------------------------
# A/B tests
# ---------------------------------------------------------------------------


@router.post("/abtest")
async def start_abtest(
    payload: ABTestStartRequest, user: User = Depends(require_admin)
):
    if registry().get_model(payload.candidate_model_id) is None:
        raise HTTPException(status_code=404, detail="candidate model not found")
    router_obj = ABTestRouter.start(
        candidate_model_id=payload.candidate_model_id,
        traffic_pct=payload.traffic_pct,
        min_samples=payload.min_samples,
        promote_threshold_pct=payload.promote_threshold_pct,
    )
    ABTEST_TRAFFIC.labels(run_id=router_obj.run.run_id).set(payload.traffic_pct)
    return router_obj.run


@router.get("/abtest")
async def list_abtests(user: User = Depends(current_user)):
    return registry().list_abtests()


@router.get("/abtest/{run_id}")
async def get_abtest(run_id: str, user: User = Depends(current_user)):
    run = registry().get_abtest(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="abtest run not found")
    ABTEST_WIN_RATE.labels(run_id=run_id).set(run.candidate_win_rate)
    return run


@router.post("/abtest/{run_id}/record")
async def record_abtest(
    run_id: str,
    payload: ABTestRecordRequest,
    user: User = Depends(require_admin),
):
    router_obj = get_router(run_id)
    if router_obj is None:
        raise HTTPException(status_code=404, detail="abtest run not found")
    run = router_obj.record(payload.variant, score=payload.score)
    ABTEST_WIN_RATE.labels(run_id=run_id).set(run.candidate_win_rate)
    return run


@router.post("/abtest/{run_id}/stop")
async def stop_abtest(run_id: str, user: User = Depends(require_admin)):
    router_obj = get_router(run_id)
    if router_obj is None:
        raise HTTPException(status_code=404, detail="abtest run not found")
    return router_obj.stop(decision="manual_stop")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _refresh_model_gauges() -> None:
    for status in ModelStatus:
        MODEL_VERSIONS.labels(status=status.value).set(
            len(registry().list_models(status=status))
        )
