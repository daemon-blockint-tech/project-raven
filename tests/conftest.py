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
# Provide test-safe overrides so the .env file values don't cause parse
# errors when pydantic-settings reads them before our validators run.
os.environ.setdefault("DATABASE_URL", "postgresql://raven:test@localhost/raven_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
# CORS_ORIGINS must be a JSON array string for pydantic-settings List[str]
# when loaded from env; the before-validator handles plain comma strings too
# but pydantic-settings JSON-decodes first, so we give a JSON array here.
os.environ.setdefault("CORS_ORIGINS", '["http://localhost:3000"]')
