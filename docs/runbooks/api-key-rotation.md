# Runbook — AI Provider API Key Rotation

**Trigger:** A key has leaked (audit log shows unusual usage, billing alert, key exposed in a screenshot/repo/log).

**Severity:** P1 (cost + data exposure)

**Owner:** Platform / SecOps on-call.

## Symptoms

- Unexpected charges on the provider account
- `raven_ai_requests_total{outcome="error"}` spike
- Audit log shows `/ai/provider` switches from unknown actors
- Provider security email indicating credential exposure

## Verify (2 min)

1. Run `curl -H "Authorization: Bearer $TOKEN" https://raven.example.com/ai/provider` — confirm current `provider` and check `has_api_key`.
2. Pull recent audit entries:
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
        'https://raven.example.com/audit/log?limit=200' | jq '.entries[] | select(.path | startswith("/ai/provider"))'
   ```
3. Cross-reference with provider's usage dashboard (OpenAI Console, Anthropic Console, OpenRouter dashboard).

## Mitigate (5 min)

1. **Revoke at the provider** first:
   - OpenAI: https://platform.openai.com/api-keys → Revoke
   - Anthropic: https://console.anthropic.com/settings/keys → Revoke
   - OpenRouter: https://openrouter.ai/keys → Disable
2. **Rotate in Raven** without restart:
   ```bash
   # Issue a new key at the provider, then hot-swap:
   curl -X POST https://raven.example.com/ai/provider \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"provider":"openai","api_key":"sk-new-..."}'
   ```
3. Update the K8s Secret so the new key survives a pod restart:
   ```bash
   kubectl -n raven create secret generic raven \
       --from-literal=AI_API_KEY="sk-new-..." \
       --dry-run=client -o yaml | kubectl apply -f -
   kubectl -n raven rollout restart deployment/raven
   ```
   In an External-Secrets-Operator setup, update the source (AWS Secrets Manager / Vault) — the sync will propagate.

## Recover (10 min)

1. Smoke-test: `curl ... /ai/status` — verify `available: true`.
2. Run an `/ai/analyze` sample request — verify a real response comes back.
3. Confirm Grafana panel `AI Provider Health` shows green.

## Postmortem checklist

- How did the key leak? (commit history, screenshot share, log statement, third party)
- Was the key in a Secret or in a hardcoded fallback?
- Add gitleaks rule / pre-commit hook if it leaked through git.
- Confirm `secrets.aiApiKey` in `values.yaml` is now sourced from the secret backend, not a value override.
- File the incident in the security log and update this runbook with what was learned.
