---
advisory_id: RAVEN-ZD-2026-001
title: "Phase 1 Reconnaissance Scan — Missing Auth Gates on 19 GET Endpoints + 6 Additional Findings"
severity: P1 (High)
discovered: 2026-05-14
author: "Project Raven (self-audit)"
status: open
---

> **Authorization**: Self-audit of the Project Raven codebase (author's own repository).  
> **Scope**: `/Volumes/RadeNugroho/project-raven/raven/api/main.py`, `raven/config/__init__.py`,
> `raven/tools/bash_executor.py`, `raven/api/main.py` (kill-chain gates).  
> **Methodology**: Manual code review (source taint analysis, attack-surface enumeration, config audit).

---

## Summary

A systematic audit of the Project Raven API surface, config, and tooling revealed **2 P1,
2 P2, and 2 P3 findings**. The highest-impact issue is a broad class of **19 GET endpoints
with zero authentication** — including Shodan host lookups, AI provider configuration
(which leaks system prompts), and Prometheus metrics.

---

## Finding 1 (P1): No Authentication on 19 GET Endpoints

### Affected Versions

- All versions since Shodan/AI/monitoring endpoints were added (v0.1.0–v0.2.0)

### Root Cause

The existing `F4` regression test (`tests/test_security_findings.py::TestF4AuthRequired`)
only parametrizes **mutating** verbs (POST/PUT/DELETE). All **GET** endpoints in
`raven/api/main.py` are implicitly assumed safe — but many expose operational data,
third-party API surfaces (Shodan), and sensitive configuration.

### Unauthenticated Endpoints (Complete List)

**Shodan (11 GET + 1 mixed — data + credit consumption):**

| Endpoint | Line | Data Leaked | Credit Cost |
|----------|------|-------------|-------------|
| `GET /shodan/status` | 968 | API plan info, credit balance | 0 |
| `GET /shodan/host/{ip}` | 979 | Ports, banners, CVEs, honeyscore | 1 |
| `GET /shodan/cve/{cve_id}` | 1016 | Exposed hosts matching a CVE | 1/search |
| `GET /shodan/domain/{domain}` | 1050 | DNS records, subdomains | 1 |
| `GET /shodan/search/facets` | 1081 | Available facets | 0 |
| `GET /shodan/search/filters` | 1091 | Search filters | 0 |
| `GET /shodan/search/tokens` | 1101 | Query token breakdown | 0 |
| `GET /shodan/scan/{scan_id}` | 1139 | Scan status | 0 |
| `GET /shodan/scans` | 1155 | All on-demand scans | 0 |
| `GET /shodan/alerts` | 1200 | Active network alerts + filter config | 0 |
| `GET /shodan/alerts/triggers` | 1234 | Available trigger types | 0 |

**AI Provider (5 GET — configuration + system prompt leakage):**

| Endpoint | Line | Data Leaked |
|----------|------|-------------|
| `GET /ai/provider` | 572 | Active provider, model name, base URL |
| `GET /ai/providers` | 784 | All 7 supported providers and their default URLs |
| `GET /ai/models/status` | 801 | Loaded specialist models (fast/reason/vision) |
| `GET /ai/status` | 812 | Provider reachability, configured model, loaded models |
| `GET /ai/system-prompt` | 722 | **Full active system prompt** (may contain proprietary red-team instructions) |

**Monitoring (3 GET — operational intelligence):**

| Endpoint | Line | Data Leaked |
|----------|------|-------------|
| `GET /metrics` | 481 | Prometheus metrics (threat counts, detection times, system health) |
| `GET /metrics/summary` | 490 | Human-readable metrics summary |
| `GET /alerts` | 496 | All security alerts (titles, descriptions, severities) |

### Attack Scenario

1. An attacker who discovers the Raven API endpoint can call `GET /ai/system-prompt` to
   exfiltrate the full system prompt — which may contain proprietary red-team instructions,
   tool configurations, and security automation rules.
2. The attacker can then use `GET /shodan/host/{ip}` to proxy Shodan queries through
   Raven's API key, consuming the operator's Shodan query credits (1 credit per IP,
   paid-plan credits cost real money).
3. `GET /metrics` reveals threat detection patterns, alert volumes, and operational
   health — useful for an attacker timing their intrusion when Raven is degraded.

### Suggested Fix

Add a `require_viewer` (or at minimum `require_operator`) dependency to every GET
endpoint that returns operational data. The safest approach is a **default-deny** pattern:

```python
# Option A: Dependency wrapper for all sensitive GET endpoints
@app.get("/shodan/host/{ip}")
async def shodan_host(
    ip: str,
    user: User = Depends(require_operator),  # ADD THIS
    history: bool = False,
):
```

Rationale against leaving endpoints unauthenticated: every endpoint in the "Shodan"
and "AI" and "Monitoring" groups either (a) consumes third-party API credits,
(b) reveals operational intelligence, or (c) returns system configuration.
None are safe to expose without authentication.

---

## Finding 2 (P1): Rate-Limiting Config Exists but Is Never Enforced

### Affected Versions

- v0.1.0+

### Root Cause

The `Settings` class in `raven/config/__init__.py` defines two rate-limiting knobs:

```python
rate_limit_per_minute: int = 60           # line 87
rate_limit_auth_per_minute: int = 5       # line 88 — login/refresh stricter
```

These values are **never read by any middleware, dependency, or route handler**. No
rate-limiting middleware is registered in `app.add_middleware(...)`. The parameters
exist only as dead configuration.

### Attack Scenario

An attacker can brute-force `POST /auth/login` with unlimited speed:

```bash
# No rate limiting — try 10 000 passwords/min
for pw in $(cat rockyou.txt); do
  curl -s -X POST http://raven:8000/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"$pw\"}"
done
```

With the default bootstrap admin password (empty → `bootstrap_admin_password: str = ""`),
anyone who can reach the API can authenticate. But even with a set password, the absence
of rate limiting makes brute-force feasible.

### Suggested Fix

Implement rate-limiting middleware. For a zero-dependency approach, a simple token-bucket
per-IP in memory:

```python
# raven/api/ratelimit.py (simplified)
from collections import defaultdict
import time

class TokenBucket:
    def __init__(self, rate: int, per: int = 60):
        self.rate = rate
        self.per = per
        self.tokens: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.time()
        window = now - self.per
        self.tokens[key] = [t for t in self.tokens[key] if t > window]
        if len(self.tokens[key]) >= self.rate:
            return False
        self.tokens[key].append(now)
        return True
```

Mount it as ASGI middleware or a route-specific dependency.

---

## Finding 3 (P2): System Prompt Exfiltration via Unauthenticated GET

### Affected Versions

- v0.1.0+

### Root Cause

`GET /ai/system-prompt` (line 722) has no auth dependency and returns the full text of
the currently active system prompt:

```python
@app.get("/ai/system-prompt")
async def ai_get_system_prompt():
    registry = ProviderRegistry.get_instance()
    prompt = registry.get_system_prompt()
    return {
        "system_prompt": prompt,
        "length": len(prompt),
        "active": bool(prompt),
    }
```

The system prompt (loaded from `RAVEN_SYSTEM_PROMPT.md` by default) governs how the AI
layer behaves — it may contain red-team instructions, tool invocation rules, and
security-critical behavioral constraints. Leaking this prompt:
1. Reveals operational methodology to an attacker
2. Enables targeted prompt-injection payloads tailored to Raven's specific instructions
3. Bypasses the need for any other recon

### CVSS 4.0

- **Attack Vector**: Network
- **Attack Complexity**: Low
- **Privileges Required**: None
- **User Interaction**: None
- **Confidentiality**: High (prompt content)
- **Integrity**: None
- **Availability**: None
- **Base Score**: 6.9 (Medium) — but escalates to P1 when combined with Finding 1's
  overall auth-gap pattern.

### Suggested Fix

Add `require_admin` to every GET endpoint that leaks configuration or system prompts:

```python
@app.get("/ai/system-prompt")
async def ai_get_system_prompt(user: User = Depends(require_admin)):
    ...
```

---

## Finding 4 (P2): bash_executor.safe_execute — Denylist Bypass

### Affected Versions

- v0.1.0+

### Root Cause

`raven/tools/bash_executor.py` line 139–156 defines a denylist of 5 patterns:

```python
dangerous_patterns = [
    "rm -rf /",
    "mkfs",
    "dd if=/dev/zero",
    "> /dev/sda",
    "chmod 777 /",
]
```

This is a **denylist** approach and is trivially bypassable:

| Blocked Pattern | Bypass |
|----------------|--------|
| `rm -rf /` | `rm -rf /*`, `rm -rf --no-preserve-root /`, `rm -rf / --no-preserve-root` |
| `mkfs` | `mkfs.ext4 /dev/sda`, `/sbin/mkfs -t ext4 /dev/sda` |
| `dd if=/dev/zero` | `dd if=/dev/urandom of=/dev/sda bs=1M` |
| `> /dev/sda` | `: > /dev/sda`, `echo x > /dev/sda` |
| `chmod 777 /` | `chmod 777 /etc`, `chmod 0777 /` |

Additionally, `safe_execute()` is **not enforced** — any caller can call `execute()`
directly, which has zero safety checks. Nothing prevents this at the interface level.

### Impact

Low in practice (because `execute()` defaults to `shell=False` via `shlex.split`, so
shell-injection attack surface is small), but the denylist provides a false sense of
security. A caller that enables `allow_shell=True` and calls `safe_execute` can still
cause arbitrary destruction.

### Suggested Fix

Replace the denylist with an **allowlist** of safe operations, or remove `safe_execute()`
entirely since it provides no meaningful protection: `execute()` is always reachable and
`safe_execute()` just adds a bypassable gate. Document that callers must validate their
own commands before calling `execute()`.

---

## Finding 5 (P3): Shodan Credit Exhaustion (Unbound Resource Consumption)

### Affected Versions

- v0.1.0+

### Root Cause

The Shodan API integration in `raven/integrations/shodan_client.py` proxies queries
through Raven's configured `shodan_api_key`. Unauthenticated endpoints (Finding 1) let
any caller consume Shodan API credits:

- `GET /shodan/host/{ip}` → 1 query credit per call
- `GET /shodan/cve/{cve_id}` → search credits per CVE lookup
- `GET /shodan/domain/{domain}` → 1 query credit per call

Shodan query credits are priced per-request on paid plans. An attacker spinning a loop:

```bash
while true; do
  curl -s "http://raven:8000/shodan/host/$(shuf -i 1-255 -r).$(shuf -i 1-255 -r).$(shuf -i 1-255 -r).$(shuf -i 1-255 -r)"
done
```

could drain the account's query budget in minutes.

### Suggested Fix

1. Fix Finding 1 (add auth to Shodan GET endpoints) — the primary fix.
2. Add per-endpoint rate limiting (Finding 2) as defence-in-depth.
3. Consider a daily credit budget in the Shodan client that refuses queries after
   N credits are consumed.

---

## Finding 6 (P3): Kill-Chain Approval — No Lock on `_pending_approval` Slot

### Affected Versions

- v0.2.0+

### Root Cause

`raven/hunters/kill_chain_planner.py` uses a single `_pending_approval` slot (line 135):

```python
self._pending_approval: Optional[DeclarativeTask] = None
```

The approval endpoints (`/hunt/killchain/approve`, `/hunt/killchain/reject`) read
and write this slot without any locking:

```python
@app.post("/hunt/killchain/approve")
async def approve_kill_chain_task(user: User = Depends(require_admin)):
    planner: KillChainPlanner = components["kill_chain_planner"]
    if planner.pending_approval is None:
        raise HTTPException(status_code=404, detail="No task pending approval")
    result = planner.approve_pending_task()
```

While the race window is narrow and the consequence is "accidental approval" (not "auth
bypass"), it violates the principle that destructive actions should have deterministic
guards. Two simultaneous approve/reject requests could both pass the `is None` check
if the GIL releases between the property read and `approve_pending_task()` (unlikely in
CPython due to the GIL, but possible with async context switches).

### Suggested Fix

Add a simple `threading.Lock` guard:

```python
import threading

class KillChainPlanner:
    def __init__(self, ...):
        self._approval_lock = threading.Lock()
        ...
```

Wraps the approval check-and-clear in a context manager.

---

## Disclosure Plan

Internal disclosure to Project Raven maintainers via this document. Since this is a
self-audit of the author's own codebase, no external disclosure is needed. All findings
are actionable and tracked for remediation.

---

## Timeline

| Date | Event |
|------|-------|
| 2026-05-14 | Vulnerability discovered (systematic zero-day audit) |
| 2026-05-14 | Self-disclosure via audit report |
| TBD | Remediation PR |
| TBD | Verification of fixes |
