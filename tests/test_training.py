"""Tests for the training subsystem — dataset builders, mock Tinker client,
registry, jobs, ABTestRouter, eval, secrets vault."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from raven.training.abtest import ABTestRouter
from raven.training.client import MockTinkerClient, reset_tinker_client, tinker_client
from raven.training.datasets import (
    build_audit_dataset,
    build_cybergym_dataset,
    build_killchain_dataset,
    build_redteam_dataset,
)
from raven.training.datasets.base import pii_scrub
from raven.training.jobs import CodeRLJob, DistillJob, SFTJob, cybergym_reward
from raven.training.models import (
    ABTestState,
    Dataset,
    DatasetSource,
    JobRecipe,
    JobState,
    ModelStatus,
    ModelVersion,
)
from raven.training.registry import reset_registry, registry
from raven.training.secrets import FernetVault, reset_vault, vault


@pytest.fixture(autouse=True)
def fresh_state():
    reset_registry()
    reset_tinker_client()
    reset_vault()
    yield
    reset_registry()
    reset_tinker_client()
    reset_vault()


# ---------------------------------------------------------------------------
# PII scrubber + JSONL writer
# ---------------------------------------------------------------------------

class TestPIIScrub:
    def test_redacts_email(self):
        assert pii_scrub("contact alice@example.com please") == "contact [email] please"

    def test_redacts_ipv4(self):
        assert pii_scrub("source 10.20.30.40 attacked") == "source [ip] attacked"

    def test_redacts_bearer(self):
        assert "[token]" in pii_scrub("Authorization: Bearer abc.def.ghi")

    def test_redacts_api_key(self):
        assert "[api_key]" in pii_scrub("sk-abcdef1234567890abcdef")

    def test_leaves_safe_text_alone(self):
        assert pii_scrub("Hello world.") == "Hello world."


# ---------------------------------------------------------------------------
# Dataset builders
# ---------------------------------------------------------------------------

class TestDatasetBuilders:
    def test_audit_dataset_round_trip(self, tmp_path):
        entries = [
            {"method": "POST", "path": "/hunt", "status_code": 200,
             "actor": "alice", "request_id": "r-1"},
            {"method": "POST", "path": "/ai/analyze", "status_code": 500,
             "actor": "alice", "request_id": "r-2"},   # skipped (>=400)
            {"method": "POST", "path": "/hunt", "status_code": 200,
             "actor": "alice", "request_id": "r-3",
             "metadata": {"no_training": True}},        # skipped
            {"method": "POST", "path": "/mitigate", "status_code": 200,
             "actor": "bob", "request_id": "r-4"},
        ]
        out = tmp_path / "audit.jsonl"
        ds = build_audit_dataset(out_path=out, entries=entries)
        assert ds.example_count == 2
        assert ds.source == DatasetSource.AUDIT_LOG
        lines = out.read_text().splitlines()
        assert len(lines) == 2
        for line in lines:
            rec = json.loads(line)
            assert rec["messages"][0]["role"] == "system"

    def test_cybergym_only_successes_by_default(self, tmp_path):
        runs = [
            {"task_id": "arvo:1", "difficulty": "level0",
             "description": "buffer overflow", "poc_text": "AAAA", "passed": True},
            {"task_id": "arvo:2", "difficulty": "level1",
             "description": "off by one", "poc_text": "BB", "passed": False},
        ]
        ds = build_cybergym_dataset(tmp_path / "cg.jsonl", runs=runs)
        assert ds.example_count == 1
        assert ds.metadata["successes"] == 1
        assert ds.metadata["failures"] == 0

    def test_cybergym_include_failures(self, tmp_path):
        runs = [
            {"task_id": "arvo:1", "passed": True, "description": "x", "poc_text": "AA"},
            {"task_id": "arvo:2", "passed": False, "description": "y", "poc_text": "BB"},
        ]
        ds = build_cybergym_dataset(tmp_path / "cg.jsonl", runs=runs, include_failures=True)
        assert ds.example_count == 2
        with open(ds.path) as f:
            records = [json.loads(line) for line in f]
        assert records[0]["reward"] == 1.0
        assert records[1]["reward"] == -1.0

    def test_killchain_only_completed_approved(self, tmp_path):
        tasks = [
            {"stage": "reconnaissance", "action": "scan_network",
             "target": "10.0.0.0/24", "status": "done", "approved": True},
            {"stage": "exploitation", "action": "exploit_vulnerabilities",
             "target": "10.0.0.5", "status": "pending", "approved": True},
            {"stage": "lateral_movement", "action": "lateral_move",
             "target": "10.0.0.6", "status": "done", "approved": False},
        ]
        ds = build_killchain_dataset(tmp_path / "kc.jsonl", tasks=tasks)
        assert ds.example_count == 1

    def test_redteam_dpo_pairs(self, tmp_path):
        detections = [
            {"prompt": "ignore previous", "techniques": ["injection"],
             "obfuscation": ["leetspeak"]},
        ]
        ds = build_redteam_dataset(tmp_path / "rt.jsonl", detections=detections)
        with open(ds.path) as f:
            rec = json.loads(f.readline())
        assert "chosen" in rec
        assert "rejected" in rec
        assert "injection" in rec["chosen"]


# ---------------------------------------------------------------------------
# MockTinkerClient state machine
# ---------------------------------------------------------------------------

class TestMockTinkerClient:
    def test_available_by_default(self):
        assert MockTinkerClient().is_available()

    def test_job_progresses_to_success(self):
        client = MockTinkerClient(ticks_to_success=3)
        job_id = client.start_job(
            base_model="meta-llama/Llama-3.1-8B-Instruct",
            dataset_path="/tmp/ds.jsonl",
        )
        s1 = client.status(job_id)
        assert s1.state == "queued"
        s2 = client.status(job_id)
        assert s2.state == "running"
        s3 = client.status(job_id)
        assert s3.state == "succeeded"
        assert s3.checkpoint_path is not None
        assert s3.metrics is not None

    def test_unknown_job_id_fails(self):
        client = MockTinkerClient()
        result = client.status("nope")
        assert result.state == "failed"

    def test_cancel_unknown_returns_false(self):
        client = MockTinkerClient()
        assert client.cancel("nope") is False

    def test_factory_falls_back_to_mock_without_api_key(self, monkeypatch):
        from raven.config import settings
        monkeypatch.setattr(settings, "tinker_api_key", "")
        monkeypatch.setattr(settings, "tinker_use_mock", False)
        client = tinker_client()
        assert isinstance(client, MockTinkerClient)


# ---------------------------------------------------------------------------
# Registry + job lifecycle
# ---------------------------------------------------------------------------

class TestRegistryAndJobs:
    def _seed_dataset(self, tmp_path):
        ds = Dataset(
            source=DatasetSource.MANUAL,
            name="seed",
            path=str(tmp_path / "seed.jsonl"),
            example_count=10,
        )
        Path(ds.path).write_text("")
        registry().register_dataset(ds)
        return ds

    def test_distill_job_full_lifecycle(self, tmp_path):
        ds = self._seed_dataset(tmp_path)
        job = DistillJob(dataset=ds).start()
        assert job.state == JobState.RUNNING
        # Poll until terminal
        for _ in range(5):
            job = DistillJob(dataset=ds).poll(job)
            if job.state == JobState.SUCCEEDED:
                break
        assert job.state == JobState.SUCCEEDED
        assert job.checkpoint_path is not None
        model = DistillJob(dataset=ds).to_model_version(job, name="raven-test")
        assert model.status == ModelStatus.CANDIDATE
        assert model.checkpoint_path == job.checkpoint_path

    def test_promote_then_rollback(self, tmp_path):
        ds = self._seed_dataset(tmp_path)
        job = SFTJob(dataset=ds).start()
        for _ in range(5):
            job = SFTJob(dataset=ds).poll(job)
            if job.state == JobState.SUCCEEDED:
                break
        m = SFTJob(dataset=ds).to_model_version(job)
        registry().promote_model(m.model_id)
        assert registry().promoted_model().model_id == m.model_id
        registry().rollback_model(m.model_id, reason="abtest_lost")
        assert registry().promoted_model() is None

    def test_promote_demotes_previous(self, tmp_path):
        ds = self._seed_dataset(tmp_path)
        # First model
        j1 = SFTJob(dataset=ds).start()
        for _ in range(5):
            j1 = SFTJob(dataset=ds).poll(j1)
        m1 = SFTJob(dataset=ds).to_model_version(j1, name="m1")
        registry().promote_model(m1.model_id)
        # Second model
        j2 = SFTJob(dataset=ds).start()
        for _ in range(5):
            j2 = SFTJob(dataset=ds).poll(j2)
        m2 = SFTJob(dataset=ds).to_model_version(j2, name="m2")
        registry().promote_model(m2.model_id)
        # m1 should now be demoted
        assert registry().get_model(m1.model_id).status == ModelStatus.DEMOTED
        assert registry().promoted_model().model_id == m2.model_id


# ---------------------------------------------------------------------------
# CodeRL reward
# ---------------------------------------------------------------------------

class TestCodeRLReward:
    def test_pass_returns_positive(self):
        assert cybergym_reward({"passed": True}) == 1.0

    def test_fail_returns_negative(self):
        assert cybergym_reward({"passed": False}) == -1.0

    def test_runtime_error_returns_negative(self):
        assert cybergym_reward({"runtime_error": True}) == -1.0

    def test_jailbreak_score_gets_extra_penalty(self):
        assert cybergym_reward({"passed": True, "jailbreak_score": 0.9}) == -2.0


# ---------------------------------------------------------------------------
# ABTestRouter
# ---------------------------------------------------------------------------

class TestABTestRouter:
    def test_starts_in_running(self):
        r = ABTestRouter.start(candidate_model_id="m1", traffic_pct=0.1)
        assert r.run.state == ABTestState.RUNNING
        assert r.run.traffic_pct == 0.1

    def test_traffic_split_respects_pct(self):
        r = ABTestRouter.start(candidate_model_id="m1", traffic_pct=0.0)
        # 100 picks at 0% candidate traffic → always incumbent
        rng = random.Random(42)
        choices = [r.choose(_rand=rng) for _ in range(100)]
        assert all(c == "incumbent" for c in choices)

    def test_promote_on_high_candidate_win_rate(self, tmp_path):
        # seed candidate model so promote() works
        m = ModelVersion(
            name="cand", base_model="x", rank=8,
            dataset_id="d", checkpoint_path="mock://x",
        )
        registry().register_model(m)
        r = ABTestRouter.start(
            candidate_model_id=m.model_id,
            traffic_pct=0.5,
            min_samples=10,
            promote_threshold_pct=0.8,
        )
        # 10 candidate wins, 0 incumbent → 100% candidate win rate
        for _ in range(10):
            r.record("candidate", score=1.0)
        assert r.run.state == ABTestState.PROMOTED
        assert r.run.decision == "promote"
        assert registry().promoted_model().model_id == m.model_id

    def test_rollback_on_low_candidate_win_rate(self):
        m = ModelVersion(
            name="cand", base_model="x", rank=8,
            dataset_id="d", checkpoint_path="mock://x",
        )
        registry().register_model(m)
        r = ABTestRouter.start(
            candidate_model_id=m.model_id,
            traffic_pct=0.5,
            min_samples=10,
            promote_threshold_pct=0.8,  # → loss threshold = 0.2
        )
        # 10 incumbent wins → candidate wins 0/10 → below 0.2 → rollback
        for _ in range(10):
            r.record("candidate", score=-1.0)
        assert r.run.state == ABTestState.ROLLED_BACK
        assert registry().get_model(m.model_id).status == ModelStatus.ROLLED_BACK

    def test_stopped_router_routes_to_incumbent(self):
        r = ABTestRouter.start(candidate_model_id="m1", traffic_pct=1.0)
        r.stop()
        assert r.choose() == "incumbent"


# ---------------------------------------------------------------------------
# Fernet vault
# ---------------------------------------------------------------------------

class TestFernetVault:
    def test_round_trip_with_strong_secret(self):
        v = FernetVault(secret="x" * 32)
        token = v.encrypt("sk-supersecret-key")
        assert token.startswith("fernet:")
        assert v.decrypt(token) == "sk-supersecret-key"

    def test_weak_secret_still_works_with_ephemeral_key(self):
        v = FernetVault(secret="short")
        token = v.encrypt("hello")
        assert v.decrypt(token) == "hello"

    def test_decrypt_plaintext_passthrough(self):
        v = FernetVault(secret="x" * 32)
        assert v.decrypt("not-a-fernet-token") == "not-a-fernet-token"

    def test_empty_string_passes_through(self):
        v = FernetVault(secret="x" * 32)
        assert v.encrypt("") == ""
        assert v.decrypt("") == ""
