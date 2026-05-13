"""ASGI middleware that records every mutating, authenticated request to the audit store.

Records: POST, PUT, PATCH, DELETE (skips GET to avoid noise).
Actor is resolved by reading `request.state.user` populated by `current_user`
dependency; falls back to the bearer-extracted subject or "anonymous".
"""

from __future__ import annotations

import time
import uuid
from typing import Iterable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from raven.audit.store import AuditEntry, audit_store


_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Records mutating requests to the audit store + propagates X-Request-ID."""

    def __init__(self, app, skip_paths: Iterable[str] = ()):
        super().__init__(app)
        self.skip_paths = tuple(skip_paths)

    async def dispatch(self, request: Request, call_next):
        # Propagate or assign request ID
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        start = time.perf_counter()
        response: Response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000.0
        response.headers["X-Request-ID"] = request_id

        if request.method in _MUTATING_METHODS and not request.url.path.startswith(
            self.skip_paths
        ):
            actor = "anonymous"
            user = getattr(request.state, "user", None)
            if user is not None:
                actor = user.username

            client_ip = request.client.host if request.client else "unknown"
            audit_store().record(
                AuditEntry(
                    timestamp=time.time(),
                    actor=actor,
                    method=request.method,
                    path=request.url.path,
                    status_code=response.status_code,
                    client_ip=client_ip,
                    request_id=request_id,
                    duration_ms=round(duration_ms, 2),
                )
            )

        return response
