"""WHOIS client — domain and IP reconnaissance.

Uses the ``python-whois`` Python module if available, otherwise falls back
to the system ``whois`` binary via :class:`ToolAdapter`.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from raven.tools.adapter_base import ToolAdapter, ToolResult


class WhoisClient(ToolAdapter):
    """WHOIS lookup adapter.

    Prefer python-whois module (``pip install python-whois``) for structured
    output; falls back to the ``whois`` CLI binary when the module is absent.
    """

    binary = "whois"
    tool_name = "whois"
    install_hint = "apt install whois  OR  pip install python-whois"

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self.timeout = int((config or {}).get("whois_timeout", 15))

    # ------------------------------------------------------------------ #
    # Availability                                                         #
    # ------------------------------------------------------------------ #

    def is_available(self) -> bool:
        try:
            import whois  # python-whois
            return True
        except ImportError:
            pass
        from raven.tools.adapter_base import which
        return which(self.binary) is not None

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def lookup(self, target: str) -> ToolResult:
        """Run a WHOIS lookup for *target* (domain or IP)."""
        try:
            import whois as pywhois
            data = pywhois.whois(target)
            parsed: Dict[str, Any] = {}
            if hasattr(data, "__dict__"):
                for k, v in data.__dict__.items():
                    if not k.startswith("_") and v is not None:
                        parsed[k] = str(v) if not isinstance(v, (str, int, float, list)) else v
            else:
                parsed = dict(data)
            return ToolResult(
                tool=self.tool_name,
                success=True,
                target=target,
                stdout=str(data),
                parsed=parsed,
            )
        except ImportError:
            pass
        except Exception as exc:
            return ToolResult(
                tool=self.tool_name,
                success=False,
                target=target,
                error=f"python-whois error: {exc}",
            )

        # CLI fallback
        result = self._run([self.binary, target], timeout=self.timeout, target=target)
        if result.success:
            result.parsed = self._parse_raw(result.stdout)
        return result

    # alias
    def query(self, target: str) -> Dict[str, Any]:
        return self.lookup(target).to_dict()

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_raw(raw: str) -> Dict[str, str]:
        parsed: Dict[str, str] = {}
        for line in raw.splitlines():
            if line.startswith(("%", "#", ">")):
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                k, v = key.strip().lower(), val.strip()
                if k and v and k not in parsed:
                    parsed[k] = v
        return parsed
