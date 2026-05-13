"""Prometheus metrics for Raven.

Conventions follow Prometheus best practices:
  - Counters: `*_total` suffix
  - Histograms: `*_seconds` suffix
  - Gauges: present-tense state
  - Labels stay low-cardinality (no user IDs, no IPs)
"""

from __future__ import annotations

import time
from typing import Awaitable, Callable

from prometheus_client import Counter, Gauge, Histogram
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

REQUEST_COUNT = Counter(
    "raven_http_requests_total",
    "HTTP requests handled by Raven API.",
    ["method", "path", "status"],
)

REQUEST_LATENCY = Histogram(
    "raven_http_request_duration_seconds",
    "HTTP request latency in seconds.",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# ---------------------------------------------------------------------------
# AI
# ---------------------------------------------------------------------------

AI_REQUEST_COUNT = Counter(
    "raven_ai_requests_total",
    "AI provider chat requests.",
    ["provider", "model", "outcome"],   # outcome: success|error|timeout
)

AI_TOKENS_PROMPT = Counter(
    "raven_ai_prompt_tokens_total",
    "Cumulative prompt tokens sent to AI providers.",
    ["provider", "model"],
)

AI_TOKENS_COMPLETION = Counter(
    "raven_ai_completion_tokens_total",
    "Cumulative completion tokens received from AI providers.",
    ["provider", "model"],
)

AI_PROVIDER_SWITCH_COUNT = Counter(
    "raven_ai_provider_switch_total",
    "Number of times the active AI provider was hot-swapped.",
    ["from_provider", "to_provider"],
)

# ---------------------------------------------------------------------------
# Threat hunting
# ---------------------------------------------------------------------------

HUNT_SESSIONS = Counter(
    "raven_hunt_sessions_total",
    "Threat-hunting sessions started.",
    ["outcome"],   # threats_found|no_threats
)

KILLCHAIN_STAGE = Counter(
    "raven_killchain_stage_total",
    "Kill-chain tasks executed by stage.",
    ["stage", "status"],   # status: completed|failed|pending_approval
)

KILLCHAIN_APPROVAL_QUEUE = Gauge(
    "raven_killchain_approval_queue_size",
    "Number of kill-chain tasks awaiting operator approval.",
)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class MetricsMiddleware(BaseHTTPMiddleware):
    """Records HTTP request count + latency to Prometheus."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Use the route template (e.g. "/ai/provider/profiles/{name}") to keep
        # cardinality bounded; falls back to the raw path for unmatched routes.
        path = request.url.path
        route = request.scope.get("route")
        if route is not None and getattr(route, "path", None):
            path = route.path

        start = time.perf_counter()
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        except Exception:
            status = 500
            raise
        finally:
            elapsed = time.perf_counter() - start
            REQUEST_LATENCY.labels(method=request.method, path=path).observe(elapsed)
            REQUEST_COUNT.labels(
                method=request.method, path=path, status=str(status)
            ).inc()
