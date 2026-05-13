"""Test-suite bootstrap.

Sets environment variables BEFORE ``raven.config`` is imported so the
module-level ``settings = Settings()`` does not crash when a real
``SECRET_KEY`` is not configured. We use a deterministic 64-char hex string
so JWT signatures stay reproducible across test runs.
"""

from __future__ import annotations

import os

# Run before any Raven module is imported.
os.environ.setdefault(
    "SECRET_KEY",
    # 64 chars, fixed for determinism. Never used in production — the
    # production safety guard refuses to start with this value too because
    # `_enforce_secret_key_floor` checks against the literal `_DEFAULT_SECRET`,
    # not this test string.
    "raven-test-suite-secret-key-deterministic-fixture-aaaaaaaaaaaaaaaa",
)
os.environ.setdefault("RAVEN_ENVIRONMENT", "dev")
# Do NOT set CORS_ORIGINS as an env var — pydantic-settings tries to
# JSON-decode List[str] fields from env vars, which would clash with our
# before-validator that handles comma-separated strings. The field default
# already matches what tests need (http://localhost:3000).
