"""ProjectDiscovery suite — subfinder, naabu, httpx, interactsh.

Each adapter wraps the Go binary as a subprocess via :class:`ToolAdapter`,
parses JSONL output where supported, and returns a structured
:class:`ToolResult`. Inspired by ``pd-agent`` (https://github.com/projectdiscovery/pd-agent).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from raven.tools.adapter_base import ToolAdapter, ToolResult, is_safe_arg


# ---------------------------------------------------------------------------
# subfinder — passive subdomain enumeration
# ---------------------------------------------------------------------------

class SubfinderAdapter(ToolAdapter):
    binary = "subfinder"
    install_hint = "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

    def enumerate(
        self,
        domain: str,
        sources: Optional[List[str]] = None,
        all_sources: bool = False,
    ) -> ToolResult:
        """Enumerate subdomains for ``domain``. Parses JSONL output."""
        if not is_safe_arg(domain):
            return ToolResult(tool=self.tool_name, success=False,
                              target=domain, error="invalid domain")
        args = [self.binary, "-d", domain, "-silent", "-oJ"]
        if all_sources:
            args.append("-all")
        if sources:
            args += ["-s", ",".join(s for s in sources if is_safe_arg(s))]
        result = self._run(args, target=domain)
        result.parsed = self._parse_jsonl(result.stdout)
        return result

    @staticmethod
    def _parse_jsonl(text: str) -> List[Dict[str, Any]]:
        hosts: List[Dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                hosts.append(json.loads(line))
            except json.JSONDecodeError:
                hosts.append({"host": line})
        return hosts


# ---------------------------------------------------------------------------
# naabu — fast SYN/CONNECT port scanner
# ---------------------------------------------------------------------------

class NaabuAdapter(ToolAdapter):
    binary = "naabu"
    install_hint = "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"

    def scan(
        self,
        target: str,
        ports: str = "top-100",
        rate: int = 1000,
    ) -> ToolResult:
        """Run a port scan against ``target``.

        ``ports`` can be ``top-100`` / ``top-1000`` / a port list ``80,443`` /
        a range ``1-10000``. ``rate`` is packets/sec.
        """
        if not is_safe_arg(target):
            return ToolResult(tool=self.tool_name, success=False,
                              target=target, error="invalid target")
        args = [
            self.binary, "-host", target,
            "-p", str(ports),
            "-rate", str(int(rate)),
            "-silent", "-json",
        ]
        result = self._run(args, target=target)
        result.parsed = self._parse_jsonl(result.stdout)
        return result

    @staticmethod
    def _parse_jsonl(text: str) -> List[Dict[str, Any]]:
        ports: List[Dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ports.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return ports


# ---------------------------------------------------------------------------
# httpx — fast, multi-purpose HTTP toolkit
# ---------------------------------------------------------------------------

class HttpxAdapter(ToolAdapter):
    binary = "httpx"
    tool_name = "httpx_pd"   # disambiguate from python httpx
    install_hint = "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"

    def probe(
        self,
        targets: List[str],
        status_code: bool = True,
        title: bool = True,
        tech_detect: bool = True,
        favicon: bool = False,
    ) -> ToolResult:
        """Probe a list of URLs / hosts and return per-target HTTP metadata."""
        targets = [t for t in targets if is_safe_arg(t)]
        if not targets:
            return ToolResult(tool=self.tool_name, success=False,
                              error="no valid targets supplied")
        args: List[str] = [self.binary, "-silent", "-json", "-no-color"]
        if status_code:
            args += ["-status-code"]
        if title:
            args += ["-title"]
        if tech_detect:
            args += ["-tech-detect"]
        if favicon:
            args += ["-favicon"]
        # Feed targets via stdin
        result = self._run(args, stdin_data=("\n".join(targets) + "\n").encode("utf-8"),
                            target=",".join(targets)[:120])
        result.parsed = self._parse_jsonl(result.stdout)
        return result

    @staticmethod
    def _parse_jsonl(text: str) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items


# ---------------------------------------------------------------------------
# interactsh — OOB interaction server (client-side; payload generation)
# ---------------------------------------------------------------------------

class InteractshAdapter(ToolAdapter):
    """Lightweight wrapper around ``interactsh-client``.

    We do NOT host the server side from Raven — instead, the operator runs
    ``interactsh-client -json``, captures payload URLs, and Raven correlates
    them with ongoing hunts via the returned JSONL stream.
    """

    binary = "interactsh-client"
    install_hint = "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"

    def generate_payloads(self, count: int = 1, server: str = "oast.pro") -> ToolResult:
        if count < 1 or count > 100:
            return ToolResult(tool=self.tool_name, success=False,
                              error="count must be in [1, 100]")
        if not is_safe_arg(server):
            return ToolResult(tool=self.tool_name, success=False,
                              error="invalid server")
        args = [
            self.binary,
            "-n", str(int(count)),
            "-server", server,
            "-json",
            "-poll-interval", "5",
            "-session-file", "/dev/null",
        ]
        # Bounded short run — operator wants the URLs only, not a long poll
        timeout = min(self.timeout, 30)
        return self._run(args, timeout=timeout, target=server)


# ---------------------------------------------------------------------------
# Facade — single component composing all four adapters
# ---------------------------------------------------------------------------

class ProjectDiscoverySuite:
    """Backwards-compat facade that exposes all four ProjectDiscovery adapters
    through one component. ``main.py`` registers this as
    ``components['projectdiscovery']`` so hunters can call
    ``components['projectdiscovery'].subfinder.enumerate(...)`` etc.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.subfinder = SubfinderAdapter(config)
        self.naabu = NaabuAdapter(config)
        self.httpx = HttpxAdapter(config)
        self.interactsh = InteractshAdapter(config)

    def availability(self) -> Dict[str, bool]:
        return {
            "subfinder": self.subfinder.is_available(),
            "naabu": self.naabu.is_available(),
            "httpx": self.httpx.is_available(),
            "interactsh": self.interactsh.is_available(),
        }

    # Convenience shortcuts so legacy call sites keep working
    def enumerate_subdomains(self, domain: str) -> List[str]:
        result = self.subfinder.enumerate(domain)
        if not result.success or not result.parsed:
            return []
        return [item.get("host", "") for item in result.parsed if item.get("host")]

    def scan_ports(self, host: str) -> List[int]:
        result = self.naabu.scan(host)
        if not result.success or not result.parsed:
            return []
        return [int(item.get("port", 0)) for item in result.parsed if item.get("port")]

    def probe_http(self, target: str) -> Dict[str, Any]:
        result = self.httpx.probe([target])
        if not result.success or not result.parsed:
            return {}
        return result.parsed[0] if result.parsed else {}
