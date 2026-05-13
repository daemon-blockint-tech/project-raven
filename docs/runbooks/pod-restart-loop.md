# Runbook — Pod CrashLoopBackOff

## Verify

```bash
kubectl -n raven get pods
kubectl -n raven describe pod $POD
kubectl -n raven logs $POD --previous
```

## Most likely causes

| Symptom | Cause | Fix |
|---|---|---|
| `ValidationError: SECRET_KEY must be set` | Default secret in prod | Set `SECRET_KEY` >=32 chars via External Secrets / Sealed Secrets |
| `ValidationError: CORS_ORIGINS must not contain '*'` | Wildcard CORS in prod | Set `config.corsOrigins` in values.yaml |
| `OperationalError: could not connect to db` | DB unreachable | Check `raven-db` pod / NetworkPolicy / DATABASE_URL |
| OOMKilled | ML model loading exceeded memory limit | Bump `resources.limits.memory` or load smaller models |
| Readiness probe failing | AI provider unreachable | See `ai-provider-outage.md` |

## Mitigate

If the crash is due to a bad config, fix `values.yaml` and `helm upgrade`. If it's due to a bad image, rollback:

```bash
helm rollback raven   # rolls back one revision
```

## Postmortem

Add the failing condition to the chart's `tests/` so the next CI run catches it.
