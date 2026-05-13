"""CyberChef integration.

CyberChef is a JavaScript single-page app for data manipulation
("recipes"). Two integration paths:

  * **CLI** — `chef` from `cyberchef-server` (Node.js project at
    [gchq/CyberChef-server](https://github.com/gchq/CyberChef-server))
  * **HTTP** — `cyberchef-server` exposes ``POST /bake`` for headless
    recipe execution. We prefer this path because it works from a
    sidecar container without needing a Node CLI on the Raven host.

Default endpoint is ``http://cyberchef-server:8000``; override via
``settings.cyberchef_server_url`` or constructor config.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

import requests

from raven.tools.adapter_base import ToolResult

log = logging.getLogger(__name__)


class CyberchefAdapter:
    """HTTP client for a self-hosted `cyberchef-server`. No subprocess."""

    tool_name = "cyberchef"

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        config = config or {}
        self.url = (
            config.get("cyberchef_server_url")
            or "http://cyberchef-server:8000"
        ).rstrip("/")
        self.timeout = int(config.get("cyberchef_timeout", 30))

    def is_available(self) -> bool:
        try:
            resp = requests.get(self.url, timeout=3)
            return resp.status_code < 500
        except Exception:
            return False

    def bake(
        self,
        input_text: str,
        recipe: List[Dict[str, Any]],
    ) -> ToolResult:
        """Run a recipe against an input string.

        ``recipe`` follows the upstream JSON schema::

            [{"op": "From Base64", "args": ["A-Za-z0-9+/=", true, false]},
             {"op": "Decode text", "args": ["UTF-8"]}]
        """
        body = {"input": input_text, "recipe": recipe}
        start = time.perf_counter()
        try:
            resp = requests.post(f"{self.url}/bake", json=body, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            self._metric(success=False)
            return ToolResult(
                tool=self.tool_name, success=False,
                error=f"cyberchef HTTP error: {exc}",
                execution_time=time.perf_counter() - start,
            )
        self._metric(success=True)
        return ToolResult(
            tool=self.tool_name, success=True,
            stdout=str(data.get("value", ""))[:4000],
            parsed=data,
            execution_time=time.perf_counter() - start,
        )

    def magic(self, input_text: str, depth: int = 3) -> ToolResult:
        """Run CyberChef's `Magic` operation — auto-detect encoding/cipher
        and recursively decode."""
        return self.bake(
            input_text,
            recipe=[{"op": "Magic", "args": [depth, False, False, ""]}],
        )

    @staticmethod
    def _metric(success: bool) -> None:
        try:
            from raven.observability.metrics import TOOL_INVOCATIONS
            TOOL_INVOCATIONS.labels(
                tool="cyberchef",
                outcome="success" if success else "failure",
            ).inc()
        except Exception:
            pass
