"""Frida — dynamic instrumentation.

Used for sandboxed runtime tracing of suspicious binaries (Phase 7 use-case:
when static analysis is inconclusive, attach Frida and trace API calls).
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from raven.tools.adapter_base import ToolAdapter, ToolResult, is_safe_arg

log = logging.getLogger(__name__)


class FridaAdapter(ToolAdapter):
    binary = "frida"
    install_hint = "pip install frida-tools  (server: deploy frida-server on target)"

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        try:
            import frida as _frida  # type: ignore
            self._frida: Any = _frida
        except ImportError:
            self._frida = None

    def is_available(self) -> bool:
        return self._frida is not None or super().is_available()

    # ------------------------------------------------------------------
    # Python API path
    # ------------------------------------------------------------------

    def list_devices(self) -> ToolResult:
        if self._frida is None:
            return ToolResult(tool=self.tool_name, success=False,
                              error="frida Python module not installed")
        try:
            devices = self._frida.get_device_manager().enumerate_devices()
        except Exception as exc:
            return ToolResult(tool=self.tool_name, success=False,
                              error=f"frida error: {exc}")
        return ToolResult(
            tool=self.tool_name, success=True,
            parsed=[{"id": d.id, "name": d.name, "type": str(d.type)} for d in devices],
        )

    def trace_apis(
        self,
        target_process: str,
        api_patterns: List[str],
        duration_seconds: int = 10,
        device_id: str = "local",
    ) -> ToolResult:
        """Attach to ``target_process`` and trace calls matching
        ``api_patterns``. Returns matched calls as parsed structured events."""

        if self._frida is None:
            return ToolResult(tool=self.tool_name, success=False, target=target_process,
                              error="frida Python module not installed")
        if not is_safe_arg(target_process):
            return ToolResult(tool=self.tool_name, success=False, target=target_process,
                              error="invalid target_process")
        # Compose Frida JS — Interceptor.attach on each matched export
        api_list = json.dumps(api_patterns)
        script_src = f"""
        var patterns = {api_list};
        function attachToMatches() {{
          patterns.forEach(function(p) {{
            var matches = Module.enumerateExportsSync(null).filter(function(e) {{
              return e.name.toLowerCase().indexOf(p.toLowerCase()) !== -1;
            }});
            matches.forEach(function(m) {{
              try {{
                Interceptor.attach(m.address, {{
                  onEnter: function(args) {{
                    send({{ type: 'call', api: m.name }});
                  }}
                }});
              }} catch(e) {{}}
            }});
          }});
        }}
        attachToMatches();
        """
        events: List[Dict[str, Any]] = []

        def _on_message(msg, _data):
            payload = (msg or {}).get("payload") or {}
            if isinstance(payload, dict):
                events.append(payload)

        start = time.perf_counter()
        try:
            device = self._frida.get_device(device_id)
            session = device.attach(target_process)
            script = session.create_script(script_src)
            script.on("message", _on_message)
            script.load()
            time.sleep(max(1, min(int(duration_seconds), 120)))
            session.detach()
        except Exception as exc:
            self._record_metric(success=False)
            return ToolResult(tool=self.tool_name, success=False, target=target_process,
                              error=f"frida error: {exc}",
                              execution_time=time.perf_counter() - start,
                              parsed=events)
        self._record_metric(success=True)
        return ToolResult(
            tool=self.tool_name, success=True, target=target_process,
            execution_time=time.perf_counter() - start,
            parsed={
                "event_count": len(events),
                "events_preview": events[:50],
                "api_patterns": api_patterns,
            },
        )
