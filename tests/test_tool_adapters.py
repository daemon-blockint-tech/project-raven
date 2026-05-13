"""Tests for the unified tool-adapter framework.

Focused on:
  * ToolAdapter base — safety check rejects shell metacharacters
  * Per-tool wrappers — argument construction + JSONL parsing
  * MCP registry — defaults + capability lookup
  * Legacy shim re-exports still resolve

Subprocess execution is patched in every test so we can run offline.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from raven.tools.adapter_base import ToolAdapter, ToolResult, is_safe_arg


# ---------------------------------------------------------------------------
# is_safe_arg
# ---------------------------------------------------------------------------

class TestSafeArg:
    @pytest.mark.parametrize("arg", [
        "example.com",
        "1.2.3.4",
        "10.0.0.0/24",
        "192.168.1.1:8080",
        "subdomain.example.com",
        "/tmp/file.txt",
        "top-1000",
        "80,443,8080",
        "CVE-2024-1234",
        "exploit-id_42",
    ])
    def test_safe_args_accepted(self, arg):
        assert is_safe_arg(arg)

    @pytest.mark.parametrize("arg", [
        "; rm -rf /",
        "$(id)",
        "`whoami`",
        "a|b",
        "a&b",
        "a>b",
        "a<b",
        "a\nb",
        "",
    ])
    def test_unsafe_args_rejected(self, arg):
        assert not is_safe_arg(arg)


# ---------------------------------------------------------------------------
# ToolAdapter._run — happy path + safety rejection
# ---------------------------------------------------------------------------

class _DummyAdapter(ToolAdapter):
    binary = "echo"
    tool_name = "dummy"


class TestRun:
    def test_run_rejects_unsafe_args(self):
        adapter = _DummyAdapter()
        result = adapter._run(["echo", "; rm -rf /"])
        assert result.success is False
        assert "unsafe argument" in (result.error or "")

    def test_run_records_timeout(self):
        adapter = _DummyAdapter({"echo_timeout": 1})
        with patch("raven.tools.adapter_base.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="echo", timeout=1)):
            result = adapter._run(["echo", "hi"])
        assert result.success is False
        assert "timed out" in (result.error or "")

    def test_run_happy_path(self):
        adapter = _DummyAdapter()
        proc = MagicMock(returncode=0, stdout=b"hello\n", stderr=b"")
        with patch("raven.tools.adapter_base.subprocess.run", return_value=proc):
            result = adapter._run(["echo", "hello"])
        assert result.success is True
        assert result.stdout == "hello\n"
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# ProjectDiscovery: subfinder + httpx + naabu JSONL parsing
# ---------------------------------------------------------------------------

class TestProjectDiscovery:
    def test_subfinder_parses_jsonl(self):
        from raven.tools.projectdiscovery import SubfinderAdapter
        adapter = SubfinderAdapter()
        sample = '{"host":"a.example.com"}\n{"host":"b.example.com"}\n'
        proc = MagicMock(returncode=0, stdout=sample.encode(), stderr=b"")
        with patch("raven.tools.adapter_base.subprocess.run", return_value=proc):
            result = adapter.enumerate("example.com")
        assert result.success
        assert [item["host"] for item in result.parsed] == ["a.example.com", "b.example.com"]

    def test_subfinder_rejects_bad_domain(self):
        from raven.tools.projectdiscovery import SubfinderAdapter
        result = SubfinderAdapter().enumerate("example.com; rm -rf /")
        assert result.success is False

    def test_naabu_parses_jsonl(self):
        from raven.tools.projectdiscovery import NaabuAdapter
        sample = '{"port":80}\n{"port":443}\n'
        proc = MagicMock(returncode=0, stdout=sample.encode(), stderr=b"")
        with patch("raven.tools.adapter_base.subprocess.run", return_value=proc):
            result = NaabuAdapter().scan("10.0.0.1", ports="80,443")
        assert [item["port"] for item in result.parsed] == [80, 443]

    def test_httpx_rejects_empty_target_list(self):
        from raven.tools.projectdiscovery import HttpxAdapter
        result = HttpxAdapter().probe([])
        assert result.success is False

    def test_httpx_probe_parses_jsonl(self):
        from raven.tools.projectdiscovery import HttpxAdapter
        sample = '{"url":"https://x","status_code":200,"title":"X"}\n'
        proc = MagicMock(returncode=0, stdout=sample.encode(), stderr=b"")
        with patch("raven.tools.adapter_base.subprocess.run", return_value=proc):
            result = HttpxAdapter().probe(["https://x"])
        assert result.parsed[0]["status_code"] == 200

    def test_suite_facade(self):
        from raven.tools.projectdiscovery import ProjectDiscoverySuite
        suite = ProjectDiscoverySuite()
        avail = suite.availability()
        assert set(avail) == {"subfinder", "naabu", "httpx", "interactsh"}
        # Mock subfinder for enumerate shortcut
        with patch.object(suite.subfinder, "enumerate") as mock:
            mock.return_value = ToolResult(
                tool="subfinder", success=True,
                parsed=[{"host": "a.example.com"}, {"host": "b.example.com"}],
            )
            assert suite.enumerate_subdomains("example.com") == [
                "a.example.com", "b.example.com",
            ]


# ---------------------------------------------------------------------------
# Searchsploit
# ---------------------------------------------------------------------------

class TestSearchsploit:
    def test_search_builds_args(self):
        from raven.tools.exploitdb import SearchsploitAdapter
        sample = json.dumps({"RESULTS_EXPLOIT": [
            {"EDB-ID": "42", "Title": "OpenSSL XYZ"},
        ]}).encode()
        proc = MagicMock(returncode=0, stdout=sample, stderr=b"")
        with patch("raven.tools.adapter_base.subprocess.run", return_value=proc) as run:
            result = SearchsploitAdapter().search("openssl heartbleed")
        assert result.success
        # Args were assembled with two positional keywords
        args_used = run.call_args[0][0]
        assert "openssl" in args_used and "heartbleed" in args_used
        assert "--json" in args_used

    def test_search_rejects_metacharacters(self):
        from raven.tools.exploitdb import SearchsploitAdapter
        result = SearchsploitAdapter().search("openssl; rm -rf /")
        assert result.success is False


# ---------------------------------------------------------------------------
# YARA — fallback CLI path (yara-python not required for this test)
# ---------------------------------------------------------------------------

class TestYara:
    def test_missing_target_returns_error(self, tmp_path):
        from raven.tools.yara_scan import YaraScanner
        scanner = YaraScanner()
        result = scanner.scan_with_rules(
            str(tmp_path / "no.yar"),
            str(tmp_path / "no-such-binary"),
        )
        assert result.success is False
        assert "not found" in (result.error or "")


# ---------------------------------------------------------------------------
# Volatility — plugin allowlist
# ---------------------------------------------------------------------------

class TestVolatility:
    def test_rejects_unlisted_plugin(self, tmp_path):
        from raven.tools.volatility import VolatilityAdapter
        memimg = tmp_path / "image.raw"
        memimg.write_bytes(b"x")
        adapter = VolatilityAdapter()
        result = adapter.run_plugin(str(memimg), "evil.dangerous.Plugin")
        assert result.success is False
        assert "allowlist" in (result.error or "")

    def test_missing_image_returns_error(self):
        from raven.tools.volatility import VolatilityAdapter
        result = VolatilityAdapter().run_plugin(
            "/nonexistent.raw", "windows.pslist.PsList",
        )
        assert result.success is False


# ---------------------------------------------------------------------------
# CyberChef HTTP client
# ---------------------------------------------------------------------------

class TestCyberchef:
    def test_bake_happy_path(self):
        from raven.tools.cyberchef import CyberchefAdapter
        with patch("raven.tools.cyberchef.requests.post") as post:
            post.return_value.json.return_value = {"value": "decoded"}
            post.return_value.raise_for_status = lambda: None
            result = CyberchefAdapter().bake(
                "aGVsbG8=",
                recipe=[{"op": "From Base64", "args": []}],
            )
        assert result.success
        assert result.stdout == "decoded"


# ---------------------------------------------------------------------------
# MCP Registry
# ---------------------------------------------------------------------------

class TestMCPRegistry:
    def test_defaults_present(self):
        from raven.tools.mcp_registry import registry, reset_registry
        reset_registry()
        names = {s.name for s in registry().list()}
        assert "ghidra-mcp" in names
        assert "radare2-mcp" in names

    def test_find_capability(self):
        from raven.tools.mcp_registry import registry, reset_registry
        reset_registry()
        found = [s.name for s in registry().find_capability("decompile_function")]
        assert "ghidra-mcp" in found
        assert "radare2-mcp" in found


# ---------------------------------------------------------------------------
# Legacy shim re-exports still resolve
# ---------------------------------------------------------------------------

class TestLegacyShims:
    @pytest.mark.parametrize("legacy_name", [
        "ExploitDBClient", "RadareClient", "FridaHook",
        "VolatilityAnalyzer", "ReconNgClient", "JadxAnalyzer",
        "CyberChefClient",
    ])
    def test_legacy_name_resolves(self, legacy_name):
        import raven.tools as tools
        cls = getattr(tools, legacy_name)
        assert cls is not None
        # All adapters accept an optional config dict
        instance = cls({}) if legacy_name != "CyberChefClient" else cls({})
        assert hasattr(instance, "is_available")
