"""Observability layer — structured logging, metrics, tracing."""

from raven.observability.logging import configure_logging, get_logger
from raven.observability.metrics import (
    REQUEST_COUNT,
    REQUEST_LATENCY,
    AI_REQUEST_COUNT,
    AI_TOKENS_PROMPT,
    AI_TOKENS_COMPLETION,
    AI_PROVIDER_SWITCH_COUNT,
    HUNT_SESSIONS,
    KILLCHAIN_STAGE,
    KILLCHAIN_APPROVAL_QUEUE,
    MetricsMiddleware,
)
from raven.observability.tracing import configure_tracing

__all__ = [
    "configure_logging",
    "get_logger",
    "configure_tracing",
    "MetricsMiddleware",
    "REQUEST_COUNT",
    "REQUEST_LATENCY",
    "AI_REQUEST_COUNT",
    "AI_TOKENS_PROMPT",
    "AI_TOKENS_COMPLETION",
    "AI_PROVIDER_SWITCH_COUNT",
    "HUNT_SESSIONS",
    "KILLCHAIN_STAGE",
    "KILLCHAIN_APPROVAL_QUEUE",
]
