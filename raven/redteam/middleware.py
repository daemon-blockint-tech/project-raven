"""ASGI middleware that scans inbound /ai/* request bodies for jailbreaks.

The middleware:
  * Buffers the request body so the downstream handler can still read it.
  * Extracts known prompt-bearing fields (``code``, ``prompt``, ``messages``,
    ``vuln_data``, ``indicators``) and runs them through
    :class:`JailbreakDetector`.
  * Adds ``X-Raven-Jailbreak-Score`` to every response.
  * Returns ``403`` if the score exceeds the configured threshold AND
    ``jailbreak_detect_enabled`` is true.
"""

from __future__ import annotations

import json
import logging
from typing import Iterable

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

log = logging.getLogger(__name__)

# Body fields that we scan when present.
_PROMPT_FIELDS = ("code", "prompt", "messages", "vuln_data", "indicators",
                  "system_prompt", "objective", "target_network")

# Only inspect bodies on these path prefixes.
_SCAN_PREFIXES = ("/ai/", "/hunt/", "/investigate/", "/redteam/scan")


def _extract_prompts(body: dict) -> str:
    """Flatten any prompt-like fields in a JSON body into a single string."""
    chunks: list[str] = []
    for field in _PROMPT_FIELDS:
        value = body.get(field)
        if value is None:
            continue
        if isinstance(value, str):
            chunks.append(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    text = item.get("content") or item.get("text")
                    if isinstance(text, str):
                        chunks.append(text)
                elif isinstance(item, str):
                    chunks.append(item)
        elif isinstance(value, dict):
            try:
                chunks.append(json.dumps(value, ensure_ascii=False))
            except Exception:
                pass
    return "\n".join(chunks)


class JailbreakDetectionMiddleware(BaseHTTPMiddleware):
    """Scans inbound prompts; blocks or annotates depending on settings."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if request.method not in {"POST", "PUT", "PATCH"} or not any(
            path.startswith(p) for p in _SCAN_PREFIXES
        ):
            return await call_next(request)

        from raven.config import settings
        if not settings.jailcheck_enabled if hasattr(settings, "jailcheck_enabled") else False:
            pass  # placeholder for old toggle

        if not settings.jailbreak_detect_enabled:
            return await call_next(request)

        # Buffer + reuse the body
        body_bytes = await request.body()

        async def _receive() -> dict:
            return {"type": "http.request", "body": body_bytes, "more_body": False}

        request = Request(request.scope, receive=_receive)

        try:
            payload = json.loads(body_bytes) if body_bytes else {}
        except (ValueError, TypeError):
            payload = {}

        flat = _extract_prompts(payload) if isinstance(payload, dict) else ""
        if not flat:
            return await call_next(request)

        from raven.observability.metrics import JAILBREAK_DETECTIONS
        from raven.redteam.detector import detector

        result = detector().scan(flat)

        if result.detected:
            for tech in result.techniques:
                JAILBREAK_DETECTIONS.labels(technique=tech, action="blocked").inc()
            log.warning(
                "jailbreak.detected path=%s score=%.2f techniques=%s",
                path, result.score, result.techniques,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "jailbreak_detected",
                    "score": result.score,
                    "threshold": result.threshold,
                    "techniques": result.techniques,
                    "obfuscation_techniques": result.obfuscation_techniques,
                },
                headers={"X-Raven-Jailbreak-Score": f"{result.score:.3f}"},
            )

        # Below threshold but maybe still annotate
        if result.hits:
            for tech in result.techniques:
                JAILBREAK_DETECTIONS.labels(technique=tech, action="logged").inc()

        response = await call_next(request)
        response.headers["X-Raven-Jailbreak-Score"] = f"{result.score:.3f}"
        return response
