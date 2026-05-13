# Security Policy — Project Raven

## Supported versions

| Version | Status |
|---------|--------|
| 0.2.x   | ✅ Security fixes |
| 0.1.x   | ❌ End of life — please upgrade |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security bugs.

Email `security@raven.example.com` (replace with your real address) with:
- A clear description of the issue
- Steps to reproduce
- Affected version (`raven --version`)
- Impact assessment

We aim to acknowledge within **48 hours** and ship a fix within **14 days**
for critical issues, **30 days** for high, **90 days** for medium/low.

## Threat model — summary

Raven is an autonomous defense system. The threat model assumes:

| Trust zone | Component | Notes |
|---|---|---|
| **Untrusted** | Inbound HTTP traffic | All `/ai/*`, `/hunt/*`, `/mitigate`, `/investigate/*` mutations require JWT + role |
| **Operator** | Authenticated user with `operator` role | Can run hunts, set targets, call AI |
| **Privileged** | Authenticated user with `admin` role | Can hot-swap AI providers, set system prompts, save profiles |
| **Internal** | DB, Redis, AI providers | Reached only via NetworkPolicy-restricted egress |
| **Out of band** | SSH targets investigated by hunters | `RejectPolicy` host-key checks; operator pre-provisions `known_hosts` |

## Security controls (Phase 1)

| Finding | Mitigation |
|---|---|
| F1 — base_url override → API key exfil | `base_url` validated against `AI_ALLOWED_BASE_URLS` allowlist + built-in defaults; route requires `admin` role |
| F2 — filesystem read via `/hunt/*` | `repo_path` must resolve inside `SCAN_ROOT`; route requires `operator` role |
| F3 — persistent prompt injection | `/ai/system-prompt` requires `admin` role; file loads jailed to CWD; all mutations audit-logged |
| F4 — no auth on `/ai/*` | JWT bearer required on every mutating route; CORS allowlist (no wildcard); rate-limiting middleware |
| F5 — profile name traversal | `^[A-Za-z0-9_-]{1,64}$` regex; route requires `admin` role |
| F6 — paramiko AutoAddPolicy MITM | `RejectPolicy` + operator-supplied `known_hosts` file; loud refusal on key mismatch |

## Cryptographic defaults

- **Password hashing:** Argon2id (`t=2, m=19_456 KiB, p=1`, OWASP 2023)
- **JWT:** HS256 by default (HS256 acceptable for single-issuer single-audience); switch to RS256/EdDSA when federating
- **TLS:** terminated at the ingress (cert-manager + Let's Encrypt); pod-to-pod can use mTLS via service mesh
- **Secrets at rest:** mounted as K8s Secrets sourced from External Secrets Operator → AWS Secrets Manager / Vault

## Operational guardrails

- **Production startup checks** refuse to boot when `SECRET_KEY` is default, `DEBUG=true`, or `CORS_ORIGINS` contains `*`.
- **Audit log** records every mutating authenticated request (actor, method, path, status, request ID, duration).
- **Kill-chain destructive stages** (Exploitation, Lateral Movement, Exfiltration, Privilege Escalation, Post-Exploitation) require an `admin` role approval via `/hunt/killchain/approve`.

## Disclosure timeline (template)

1. Day 0  — Researcher reports
2. Day 1–2  — Triage + acknowledgement
3. Day 3–14 — Fix + regression test + advisory drafted
4. Day 14 — Coordinated release; CVE assigned if applicable
5. Day 30 — Public advisory + remediation guide
