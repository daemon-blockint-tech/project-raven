# Runbook — AI Provider Outage

**Trigger:** Active provider returning 5xx / timing out / rate-limiting persistently.

**Severity:** P2 (degraded capability, no data loss)

## Symptoms

- `raven_ai_requests_total{outcome="error"}` > 10/min
- `/ai/status` returns `available: false`
- Hunters falling back to keyword heuristics (logs: `LLM unavailable, falling back`)

## Verify

```bash
curl -H "Authorization: Bearer $TOKEN" https://raven.example.com/ai/status | jq
```

Check the provider's status page:
- OpenAI: https://status.openai.com
- Anthropic: https://status.anthropic.com
- OpenRouter: https://status.openrouter.ai

## Mitigate

**Option A — failover to a secondary provider** (admin role):

```bash
curl -X POST https://raven.example.com/ai/provider \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"provider":"openrouter","api_key":"sk-or-...","model":"anthropic/claude-3-5-sonnet"}'
```

**Option B — load a saved fallback profile**:

```bash
curl -X PUT https://raven.example.com/ai/provider/profiles/fallback \
     -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Option C — degrade to local LM Studio** if cloud is fully out:

```bash
curl -X POST https://raven.example.com/ai/provider \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{"provider":"lmstudio","base_url":"http://lmstudio-sidecar:1234"}'
```

## Recover

Once the primary provider is healthy again, switch back with the same `/ai/provider` POST.

## Postmortem

- Track time to detect (TTD) and time to recover (TTR).
- If TTD > 5 min: improve alerting (`AI Provider Health` panel + PagerDuty integration).
- If failover took > 2 min: pre-create the fallback profile so it's one PUT away.
