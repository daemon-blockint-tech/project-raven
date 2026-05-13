# Project Raven — Service Level Objectives

Measured over a rolling 28-day window.

## Availability

| Tier | SLO | Error budget (28d) |
|---|---|---|
| `/health`, `/health/ready` | 99.95 % | 20 min |
| `/auth/*` | 99.9 % | 40 min |
| `/ai/*` (read) | 99.5 % | 3 h 22 min |
| `/ai/*` (mutate) | 99.9 % | 40 min |
| `/hunt/*` | 99.0 % | 6 h 43 min |

A response is "good" when status code is 2xx or 4xx (4xx is the client's fault).
Status 5xx counts against the budget.

## Latency

| Route | SLO p95 | SLO p99 |
|---|---|---|
| `/analyze` | < 800 ms | < 2 s |
| `/ai/analyze` | < 5 s | < 15 s |
| `/auth/login` | < 250 ms | < 800 ms |
| `/health` | < 50 ms | < 150 ms |

## Burn-rate alerts

Two-window, two-burn-rate alerts (Google SRE pattern):

| Severity | Long window | Short window | Burn rate |
|---|---|---|---|
| **Page** | 1 h | 5 min | 14.4× |
| **Ticket** | 6 h | 30 min | 6× |

Prometheus expression for `/ai/*` availability:
```promql
sum(rate(raven_http_requests_total{path=~"/ai/.*", status=~"5.."}[5m]))
  / sum(rate(raven_http_requests_total{path=~"/ai/.*"}[5m]))
  > 14.4 * 0.005
```
