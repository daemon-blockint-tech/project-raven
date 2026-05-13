# Runbook — Audit Investigation

**Use when:** answering "who did X, when, from where?" — security incident, compliance request, internal review.

## Endpoint

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
     'https://raven.example.com/audit/log?limit=1000&actor=alice' | jq
```

Returns up to 1000 entries (clamped server-side), each:

```json
{
  "timestamp": 1731491820.0,
  "actor": "alice",
  "method": "POST",
  "path": "/ai/provider",
  "status_code": 200,
  "client_ip": "10.20.0.7",
  "request_id": "5e9a...c3b2",
  "duration_ms": 142.5,
  "metadata": {}
}
```

## Common investigations

### Who switched the active AI provider in the last hour?
```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
     'https://raven.example.com/audit/log?limit=1000' \
   | jq '.entries[] | select(.path == "/ai/provider" and (.timestamp > (now - 3600)))'
```

### Did anyone load a kill-chain approval today?
```bash
... | jq '.entries[] | select(.path == "/hunt/killchain/approve")'
```

### Who is hitting the API the most?
```bash
... | jq '[.entries[].actor] | group_by(.) | map({actor: .[0], count: length}) | sort_by(-.count)'
```

## Correlation with logs + traces

Every audit entry carries `request_id`. The same ID is logged by structlog (JSON) and propagated to OTel spans, so you can pivot:

- **Loki:** `{app="raven"} |= "<request_id>"`
- **Tempo / Jaeger:** search by `request.id="<request_id>"`

## Retention

The Phase 1 audit store is an in-memory ring buffer of 10,000 entries.
Phase 3 (Data plane) moves this into Postgres with year+ retention and
PII-scrubbed export to S3 for compliance.

If you need long-term retention right now, the audit logs are also
written to stdout via structlog and captured by your log aggregator
(Loki / ELK / Datadog) — query there.
