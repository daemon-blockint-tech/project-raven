"""Tests for AresAdapter (ARES-v3 Solana static auditor)."""
from __future__ import annotations

import json
import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_adapter(binary_exists: bool = True):
    from raven.tools.ares import AresAdapter
    adapter = AresAdapter()
    adapter.is_available = MagicMock(return_value=binary_exists)
    return adapter


def _fake_tool_result(stdout: str = "", success: bool = True):
    from raven.tools.adapter_base import ToolResult
    return ToolResult(
        tool="ares-v3",
        success=success,
        target="/tmp/program",
        stdout=stdout,
        exit_code=0 if success else 1,
    )


# ---------------------------------------------------------------------------
# is_available / install_hint
# ---------------------------------------------------------------------------

def test_install_hint_present():
    from raven.tools.ares import AresAdapter
    a = AresAdapter()
    assert "cargo install" in a.install_hint
    assert "ARES-v3" in a.install_hint


def test_not_available_returns_error_result():
    a = _make_adapter(binary_exists=False)
    result = a.scan("/tmp/prog")
    assert result.success is False
    assert "ares binary not found" in (result.error or "")


# ---------------------------------------------------------------------------
# scan — JSON output parsing
# ---------------------------------------------------------------------------

FAKE_ARES_JSON = json.dumps({
    "target": "/tmp/prog",
    "findings": [
        {
            "class": "type-cosplay",
            "severity": "HIGH",
            "location": "src/lib.rs:42",
            "message": "Account discriminator not checked"
        },
        {
            "class": "arithmetic-overflow",
            "severity": "MEDIUM",
            "location": "src/state.rs:88",
            "message": "Unchecked u64 addition"
        }
    ],
    "stats": {"total_findings": 2, "high": 1, "medium": 1, "low": 0},
    "recall": 0.97,
})


def test_scan_parses_json_output():
    a = _make_adapter()
    fake = _fake_tool_result(stdout=FAKE_ARES_JSON)
    with patch.object(a, "_run", return_value=fake):
        result = a.scan("/tmp/prog", fmt="json")
    assert result.success is True
    assert isinstance(result.parsed, dict)
    assert "findings" in result.parsed
    assert len(result.parsed["findings"]) == 2


def test_scan_with_policy_flag():
    a = _make_adapter()
    fake = _fake_tool_result(stdout=FAKE_ARES_JSON)
    with patch.object(a, "_run", return_value=fake) as mock_run:
        a.scan("/tmp/prog", policy="/etc/ares.toml")
    cmd = mock_run.call_args[0][0]
    assert "--policy" in cmd
    assert "/etc/ares.toml" in cmd


def test_scan_with_llm_flag():
    a = _make_adapter()
    fake = _fake_tool_result(stdout=FAKE_ARES_JSON)
    with patch.object(a, "_run", return_value=fake) as mock_run:
        a.scan("/tmp/prog", use_llm=True)
    cmd = mock_run.call_args[0][0]
    assert "--llm" in cmd


def test_scan_format_md_no_json_parse():
    a = _make_adapter()
    md_content = "# ARES Report\n\n## Findings\n- type-cosplay at src/lib.rs:42\n"
    fake = _fake_tool_result(stdout=md_content)
    with patch.object(a, "_run", return_value=fake):
        result = a.scan("/tmp/prog", fmt="md")
    assert result.parsed == {"raw": md_content, "format": "md"}


def test_scan_json_with_leading_log_lines():
    """_parse_json_output should skip leading log lines and find the JSON blob."""
    a = _make_adapter()
    raw = f"[INFO] ARES v3.0 starting\n[INFO] Loading rules\n{FAKE_ARES_JSON}"
    fake = _fake_tool_result(stdout=raw)
    with patch.object(a, "_run", return_value=fake):
        result = a.scan("/tmp/prog")
    assert result.parsed is not None
    assert "findings" in result.parsed


def test_scan_malformed_json_returns_raw():
    a = _make_adapter()
    fake = _fake_tool_result(stdout="not json at all")
    with patch.object(a, "_run", return_value=fake):
        result = a.scan("/tmp/prog")
    assert result.parsed == {"raw": "not json at all"}


# ---------------------------------------------------------------------------
# benchmark
# ---------------------------------------------------------------------------

def test_benchmark_not_available():
    a = _make_adapter(binary_exists=False)
    result = a.benchmark()
    assert result.success is False


def test_benchmark_with_ground_truth():
    a = _make_adapter()
    bench_out = json.dumps({"recall": 0.97, "f1": 0.94, "protocols": 20})
    fake = _fake_tool_result(stdout=bench_out)
    with patch.object(a, "_run", return_value=fake) as mock_run:
        result = a.benchmark(ground_truth="/data/gt.json")
    cmd = mock_run.call_args[0][0]
    assert "--ground-truth" in cmd
    assert result.parsed["recall"] == 0.97


# ---------------------------------------------------------------------------
# list_classes
# ---------------------------------------------------------------------------

def test_list_classes():
    from raven.tools.ares import AresAdapter, VULN_CLASSES
    result = AresAdapter().list_classes()
    assert result.success is True
    assert result.parsed["count"] == len(VULN_CLASSES)
    assert "type-cosplay" in result.parsed["vulnerability_classes"]
    assert "arbitrary-cpi" in result.parsed["vulnerability_classes"]
    assert "arithmetic-overflow" in result.parsed["vulnerability_classes"]


# ---------------------------------------------------------------------------
# to_dict round-trip
# ---------------------------------------------------------------------------

def test_scan_result_to_dict():
    a = _make_adapter()
    fake = _fake_tool_result(stdout=FAKE_ARES_JSON)
    with patch.object(a, "_run", return_value=fake):
        result = a.scan("/tmp/prog")
    d = result.to_dict()
    assert d["tool"] == "ares-v3"
    assert d["success"] is True
    assert isinstance(d["parsed"], dict)
