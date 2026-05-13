# Approval Gate & Red-Team

Project Raven adopts two Hermes Agent-style subsystems: **YOLO/approval gating** and a **defensive red-team** with an operator-gated offensive mode.

## Approval gate

Three modes (settings: `APPROVAL_MODE=manual|smart|off`):

| Mode | Behaviour |
|---|---|
| **manual** | Always prompt the operator. Dangerous commands enqueue a `PendingApproval`; the route handler returns `202 Accepted` with a `request_id`. The operator approves/denies via `POST /approval/decisions/{id}/{approve,deny}`. |
| **smart** | An auxiliary LLM (`ModelOrchestrator(FAST)`) triages risk. Low-risk auto-approve, dangerous auto-deny, uncertain escalates to `manual`. |
| **off** (YOLO) | Auto-approves everything *that did not trip the blocklist*. Forbidden in `RAVEN_ENVIRONMENT=prod`. |

### UNRECOVERABLE_BLOCKLIST

Below all modes sits a hardline floor. Nothing — not YOLO, not the permanent allowlist, not the admin role — can bypass it. Patterns include:

- `rm -rf /` (including long-form `--recursive --force`)
- `rm --no-preserve-root`
- Fork bomb `:(){ :|:& };:`
- `mkfs.*` on `/dev/sd*`, `/dev/nvme*`, `/dev/vd*`
- `dd if=/dev/zero of=/dev/sd*`
- `curl|wget … | sh` at top level
- `shred /dev/sd*`
- Recursive `chmod`/`chown` on `/`

Hits return **451 Unavailable For Legal Reasons** and increment `raven_approval_blocklist_hits_total`.

### CLI

```bash
raven approval status                  # mode + allowlist
raven approval mode {manual|smart|off}
raven approval allow '^rm -rf /tmp/'   # permanent allow
raven approval forget '^rm -rf /tmp/'
raven approval test 'rm -rf /'         # dry-run
```

### REST

```
GET    /approval/mode
PATCH  /approval/mode                  (admin)
GET    /approval/decisions             (any auth)
POST   /approval/decisions/{id}/approve (operator)
POST   /approval/decisions/{id}/deny    (operator)
GET    /approval/allowlist
POST   /approval/allowlist             (admin)
DELETE /approval/allowlist/{pattern}   (admin)
```

## Defensive red-team (always on)

### ParseltongueNormaliser

Decodes 33 obfuscation techniques across 3 tiers (light / standard / heavy). Every inbound prompt to `/ai/*`, `/hunt/*`, `/investigate/*` is normalised **before** classification so attackers cannot smuggle a jailbreak past us via leetspeak, homoglyphs, Base64, hex, Braille, Morse, Pig Latin, zero-width joiners, mathematical alphabets, bracketed letters, or multi-layer combos.

### JailbreakDetector

Fingerprint library at `raven/redteam/jailbreak_patterns.py` covers L1B3RT4S families: `boundary_inversion`, `refusal_inversion`, `og_godmode`, `unfiltered_liberated`, `dan`, `injection`, `role_play`. Each hit contributes a weighted score (0.0–1.0). When `score >= JAILBREAK_BLOCK_THRESHOLD` (default 0.8), `JailbreakDetectionMiddleware` returns `403 jailbreak_detected`. All responses carry `X-Raven-Jailbreak-Score`.

### ProviderHardnessTest

`POST /redteam/hardness` (admin) runs 10 canary prompts against the active provider and reports resistance (0–10) plus weakest families. Canaries are intentionally low-impact ("explain what a buffer overflow is" rather than "write working exploit").

Metric: `raven_provider_hardness_score{provider,model}` gauge.

## Offensive Godmode (gated)

`POST /redteam/godmode` runs **synthesised** jailbreak strategies (we do NOT ship L1B3RT4S template strings) against the active provider. Triple-gated:

1. `settings.offensive_redteam_enabled` must be `true`
2. Caller must have `admin` role
3. Request must carry `X-Raven-Authorization-Token` matching `settings.offensive_redteam_session_token`
4. Body must include `sandbox_session_id`

Every invocation logs to the audit store and increments `raven_redteam_godmode_attempts_total{outcome}`. Default disabled.

## Configuration

```bash
# Approval gate
APPROVAL_MODE=manual                       # manual | smart | off
APPROVAL_TIMEOUT_SECONDS=60
YOLO_ENV_OVERRIDE=false                    # honour RAVEN_YOLO_MODE env var

# Jailbreak defence (always on)
JAILBREAK_DETECT_ENABLED=true
JAILBREAK_BLOCK_THRESHOLD=0.8
JAILBREAK_LOG_NORMALIZED=true

# Offensive red-team (operator opt-in)
OFFENSIVE_REDTEAM_ENABLED=false
OFFENSIVE_REDTEAM_SESSION_TOKEN=
```

Prod-mode guard refuses to start when:
- `APPROVAL_MODE=off` (YOLO forbidden in prod)
- `OFFENSIVE_REDTEAM_ENABLED=true` without `OFFENSIVE_REDTEAM_SESSION_TOKEN`
