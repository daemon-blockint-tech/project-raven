# Training & Continual Learning — Tinker Integration

Project Raven uses Thinking Machines Lab's [Tinker](https://thinkingmachines.ai/tinker/) managed-LoRA fine-tuning API to **produce** its own AI rather than only consume third-party providers. Every approved hunt + every CyberGym verdict + every red-team detection becomes training data, jobs run on Tinker's managed GPU pool, and resulting checkpoints register as `ModelVersion` rows that compete with the incumbent via `ABTestRouter`.

## Architecture

```
audit_log + cybergym + killchain + redteam
            │
            ▼
   raven/training/datasets/   →  JSONL on disk
            │
            ▼
   raven/training/jobs/       →  TinkerClient.start_job()
            │
            ▼
   Tinker managed GPU fine-tune
            │
            ▼
   raven/training/registry/   →  ModelVersion row
            │
            ▼
   raven/training/eval.py     →  hardness + canary + CyberGym smoke
            │
            ▼
   raven/training/abtest.py   →  Bernoulli traffic split, auto-promote
            │
            ▼
   raven/ai/providers/tinker  →  hot-swap promoted checkpoint as Raven's
                                 active provider via ProviderRegistry
```

## Configuration

```bash
# Tinker
TINKER_API_KEY=                              # required for real fine-tunes
TINKER_USE_MOCK=false                        # set true for offline mode
TINKER_DEFAULT_BASE_MODEL=meta-llama/Llama-3.1-70B-Instruct
TINKER_DEFAULT_RANK=64
TINKER_MAX_CONCURRENT_JOBS=2

# Continual learning loop (opt-in)
CONTINUAL_LEARNING_ENABLED=false
CONTINUAL_LEARNING_MIN_EXAMPLES=100

# A/B test defaults
ABTEST_DEFAULT_TRAFFIC_PCT=0.05
ABTEST_MIN_SAMPLES=500
ABTEST_PROMOTE_THRESHOLD_PCT=0.95
```

Prod-mode guard refuses to start when `CONTINUAL_LEARNING_ENABLED=true` without a `TINKER_API_KEY` and not in mock mode.

## Mock client — no API key required

When `TINKER_API_KEY` is empty (and `TINKER_USE_MOCK=false`), `tinker_client()` falls back to `MockTinkerClient`. The mock replays a 3-tick state machine (queued → running → succeeded) so the entire pipeline runs offline. Useful for CI, dev, and hackathon demos before Tinker beta access is granted.

## CLI

```bash
raven train status                                   # tinker client + base models
raven train dataset-build --source audit \
                          --out data/audit.jsonl    # mine audit log
raven train dataset-list
raven train job-start --recipe distill \
                      --dataset-id <id> \
                      --base-model meta-llama/Llama-3.1-70B-Instruct \
                      --rank 64
raven train job-status <job_id>
raven train job-list
raven train model-list
raven train model-eval <model_id>                    # hardness + canary
raven train model-promote <model_id>
raven train model-rollback <model_id> --reason X
```

## REST

```
GET    /training/tinker/status
GET    /training/datasets
POST   /training/datasets                  (admin)
GET    /training/datasets/{id}
GET    /training/jobs
POST   /training/jobs                      (admin)
GET    /training/jobs/{id}
POST   /training/jobs/{id}/cancel          (admin)
POST   /training/jobs/{id}/finalize        (admin)  → ModelVersion
GET    /training/models[?status=…]
GET    /training/models/{id}
POST   /training/models/{id}/eval          (admin)
POST   /training/models/{id}/promote       (admin)
POST   /training/models/{id}/rollback      (admin)
POST   /training/abtest                    (admin)
GET    /training/abtest
GET    /training/abtest/{id}
POST   /training/abtest/{id}/record        (admin)
POST   /training/abtest/{id}/stop          (admin)
```

## Dataset sources

| Source | Builder | Description |
|---|---|---|
| `audit_log` | `build_audit_dataset` | Mines `/audit/log` for (request → response) SFT pairs. Skips status ≥ 400 and `metadata.no_training=true`. PII-scrubbed. |
| `cybergym` | `build_cybergym_dataset` | Mines CyberGym verdicts. Reward = pass/fail. Defaults to successes-only; opt-in for failures with negative reward. |
| `killchain` | `build_killchain_dataset` | Approved + completed kill-chain tasks → tool-use SFT examples. |
| `redteam` | `build_redteam_dataset` | Jailbreak detections → DPO `(chosen=safe_refusal, rejected=placeholder)` pairs. |
| `distillation` | `build_distillation_dataset` | Queries a teacher provider (Claude/GPT) on a prompt corpus; student trains on the responses. |

## Recipes

| Recipe | Use case |
|---|---|
| `distill` | Claude Opus 4.6 → Llama-3.1-70B Raven-specialist (the demo path) |
| `sft` | Vanilla supervised fine-tune on the audit/killchain corpora |
| `code_rl` | RL with CyberGym verdict as reward (`raven.training.jobs.cybergym_reward`) |

## A/B test promotion

`ABTestRouter` does a Bernoulli traffic split. Each request is recorded with a numeric score:

* `score > 0` from a candidate request → candidate win
* `score < 0` from a candidate request → incumbent win
* `score > 0` from an incumbent request → incumbent win
* `score < 0` from an incumbent request → candidate win (incumbent failed)

When `total_samples >= min_samples`:

* `candidate_win_rate >= promote_threshold_pct` → **auto-promote** (incumbent demoted, candidate becomes the active model)
* `candidate_win_rate <= 1 - promote_threshold_pct` → **auto-rollback** (candidate marked ROLLED_BACK, incumbent stays)

## Prometheus metrics

```
raven_training_jobs_total{recipe, outcome}
raven_training_dataset_size{source}
raven_model_versions_total{status}
raven_abtest_win_rate{run_id}
raven_abtest_traffic_ratio{run_id}
```

## Security

* `tinker_api_key` can be encrypted at rest by `raven.training.secrets.vault()` (Fernet, key derived from `SECRET_KEY`).
* Dataset builders run `pii_scrub` on every record (email, IP, SSN, card numbers, Bearer tokens, `sk-…` API keys, long hex hashes).
* Audit entries can opt-out per-record via `metadata.no_training=true`.
* `OffensiveGodmode` patterns from the red-team subsystem are never folded back into training corpora.
