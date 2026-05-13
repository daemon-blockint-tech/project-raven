"""`raven train` — Tinker training subsystem CLI."""

from __future__ import annotations

import json

import typer

from raven.training.client import tinker_client
from raven.training.eval import evaluate_model
from raven.training.jobs import CodeRLJob, DistillJob, SFTJob
from raven.training.models import JobRecipe
from raven.training.registry import registry

app = typer.Typer(
    name="train",
    help="Manage Tinker training jobs and model versions.",
    no_args_is_help=True,
)


# ---------------------------------------------------------------------------
# Tinker status
# ---------------------------------------------------------------------------


@app.command("status")
def cmd_status():
    """Show Tinker client status and available base models."""
    client = tinker_client()
    typer.echo(f"Client:    {type(client).__name__}")
    typer.echo(f"Available: {client.is_available()}")
    typer.echo("Base models:")
    for m in client.list_base_models():
        typer.echo(f"  • {m}")


# ---------------------------------------------------------------------------
# Datasets
# ---------------------------------------------------------------------------


@app.command("dataset-build")
def cmd_dataset_build(
    source: str = typer.Option(
        ..., "--source", help="audit|cybergym|killchain|redteam|distillation"
    ),
    out: str = typer.Option(..., "--out", help="Output JSONL path"),
    name: str = typer.Option("dataset", "--name"),
    limit: int = typer.Option(1000, "--limit"),
):
    """Build a dataset from one of the runtime sources."""
    if source == "audit":
        from raven.training.datasets import build_audit_dataset

        ds = build_audit_dataset(out_path=out, name=name, limit=limit)
    elif source in {"cybergym", "killchain", "redteam"}:
        typer.echo(
            f"[note] {source} dataset builder requires runs/tasks/detections via API or fixtures.",
            err=True,
        )
        typer.echo(
            "Use the REST endpoint POST /training/datasets after seeding the source data.",
            err=True,
        )
        raise typer.Exit(2)
    elif source == "distillation":
        typer.echo(
            "[note] distillation builder requires a prompt corpus (file). Pass via REST API.",
            err=True,
        )
        raise typer.Exit(2)
    else:
        typer.echo(f"[error] unknown source: {source!r}", err=True)
        raise typer.Exit(1)
    registry().register_dataset(ds)
    typer.echo(json.dumps(ds.model_dump(), indent=2, default=str))


@app.command("dataset-list")
def cmd_dataset_list():
    for ds in registry().list_datasets():
        typer.echo(
            f"{ds.dataset_id}  {ds.source.value:14s}  {ds.example_count:>6d}  {ds.path}"
        )


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

_RECIPES = {
    "distill": (DistillJob, JobRecipe.DISTILL),
    "sft": (SFTJob, JobRecipe.SFT),
    "code_rl": (CodeRLJob, JobRecipe.CODE_RL),
}


@app.command("job-start")
def cmd_job_start(
    recipe: str = typer.Option("distill", "--recipe", help="distill|sft|code_rl"),
    dataset_id: str = typer.Option(..., "--dataset-id"),
    base_model: str = typer.Option(None, "--base-model"),
    rank: int = typer.Option(64, "--rank"),
    epochs: int = typer.Option(3, "--epochs"),
):
    """Submit a training job to Tinker."""
    from raven.config import settings

    if recipe not in _RECIPES:
        typer.echo(f"[error] recipe must be one of: {list(_RECIPES)}", err=True)
        raise typer.Exit(1)
    dataset = registry().get_dataset(dataset_id)
    if dataset is None:
        typer.echo(f"[error] dataset not found: {dataset_id}", err=True)
        raise typer.Exit(1)
    job_cls, _ = _RECIPES[recipe]
    job_obj = job_cls(
        dataset=dataset,
        base_model=base_model or settings.tinker_default_base_model,
        rank=rank,
        epochs=epochs,
        actor="cli",
    )
    job = job_obj.start()
    typer.echo(json.dumps(job.model_dump(), indent=2, default=str))


@app.command("job-status")
def cmd_job_status(job_id: str = typer.Argument(...)):
    job = registry().get_job(job_id)
    if job is None:
        typer.echo(f"[error] job not found: {job_id}", err=True)
        raise typer.Exit(1)
    job_cls = {
        JobRecipe.DISTILL: DistillJob,
        JobRecipe.SFT: SFTJob,
        JobRecipe.CODE_RL: CodeRLJob,
    }.get(job.recipe, SFTJob)
    dataset = registry().get_dataset(job.dataset_id)
    if dataset is None:
        typer.echo("[warn] dataset record is missing; polling without it.", err=True)
        from raven.training.models import Dataset, DatasetSource

        dataset = Dataset(source=DatasetSource.MANUAL, name="orphan", path="")
    refreshed = job_cls(dataset=dataset, base_model=job.base_model, rank=job.rank).poll(
        job
    )
    typer.echo(json.dumps(refreshed.model_dump(), indent=2, default=str))


@app.command("job-list")
def cmd_job_list():
    for j in registry().list_jobs():
        typer.echo(
            f"{j.job_id}  {j.recipe.value:9s}  {j.state.value:11s}  {j.base_model}"
        )


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@app.command("model-list")
def cmd_model_list():
    for m in registry().list_models():
        scores = (
            ",".join(f"{k}={v:.2f}" for k, v in m.eval_scores.items()) or "(no eval)"
        )
        typer.echo(f"{m.model_id}  {m.status.value:10s}  {m.name:30s}  {scores}")


@app.command("model-eval")
def cmd_model_eval(model_id: str = typer.Argument(...)):
    model = registry().get_model(model_id)
    if model is None:
        typer.echo(f"[error] model not found: {model_id}", err=True)
        raise typer.Exit(1)
    result = evaluate_model(model)
    typer.echo(json.dumps(result.model_dump(), indent=2, default=str))


@app.command("model-promote")
def cmd_model_promote(model_id: str = typer.Argument(...)):
    try:
        result = registry().promote_model(model_id)
    except KeyError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)
    typer.echo(f"✓ promoted {result.model_id} ({result.name})")


@app.command("model-rollback")
def cmd_model_rollback(
    model_id: str = typer.Argument(...), reason: str = typer.Option(None, "--reason")
):
    try:
        result = registry().rollback_model(model_id, reason=reason)
    except KeyError as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)
    typer.echo(f"✓ rolled back {result.model_id}")
