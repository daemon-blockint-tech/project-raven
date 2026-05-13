"""Structured JSON logging via structlog.

Replaces ad-hoc `print()` calls with structured events. Fields like
`request_id`, `user`, `provider`, `model`, `latency_ms` are first-class —
the log aggregator (Loki / ELK) can query them as columns.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog


def configure_logging(level: str = "INFO", json: bool = True) -> None:
    """Configure structlog + stdlib logging.

    Args:
        level: minimum log level (INFO in prod, DEBUG locally).
        json:  True → JSON to stdout (production); False → human-readable.
    """
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )

    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if json:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> Any:
    """Return a structlog logger bound to `name`."""
    return structlog.get_logger(name)
