# Project Raven — Operations Runbooks

These runbooks document **how to respond** to specific production events.
Each runbook follows the same structure: Symptoms → Verify → Mitigate → Recover → Postmortem.

| Runbook | When to use |
|---|---|
| [`incident-response.md`](incident-response.md) | A live security incident is in progress |
| [`ai-provider-outage.md`](ai-provider-outage.md) | OpenAI / Anthropic / OpenRouter unreachable or returning 5xx |
| [`api-key-rotation.md`](api-key-rotation.md) | An AI provider API key is compromised |
| [`database-failover.md`](database-failover.md) | Postgres primary is down |
| [`killchain-stuck-approval.md`](killchain-stuck-approval.md) | A kill-chain task is stuck awaiting approval |
| [`pod-restart-loop.md`](pod-restart-loop.md) | Raven pod is CrashLoopBackOff |
| [`high-latency.md`](high-latency.md) | `/ai/*` p95 latency exceeds SLO |
| [`audit-investigation.md`](audit-investigation.md) | Investigating who did what, when |
