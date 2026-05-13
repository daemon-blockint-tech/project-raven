"""Tests for NucleiScanner"""

import json
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from raven.tools.nuclei_scanner import NucleiScanner, NucleiResult


CONFIG = {"nuclei_binary": "nuclei", "nuclei_timeout": 30}


def _make_scanner(**overrides) -> NucleiScanner:
    cfg = {**CONFIG, **overrides}
    return NucleiScanner(cfg)


# ---------------------------------------------------------------------------
# binary availability
# ---------------------------------------------------------------------------

def test_scan_returns_failure_when_binary_missing():
    scanner = _make_scanner()
    with patch.object(scanner, "_binary_available", return_value=False):
        result = scanner.scan("192.168.1.1")
    assert isinstance(result, NucleiResult)
    assert result.success is False
    assert result.findings == []


# ---------------------------------------------------------------------------
# successful scan with mocked subprocess
# ---------------------------------------------------------------------------

_FINDING_1 = {
    "template-id": "CVE-2021-44228",
    "host": "192.168.1.10",
    "info": {"severity": "critical", "name": "Log4Shell"},
    "matched-at": "http://192.168.1.10:8080",
}

_FINDING_LOW = {
    "template-id": "info-disclosure",
    "host": "192.168.1.10",
    "info": {"severity": "info"},
}


def _mock_proc(stdout: str, returncode: int = 0) -> MagicMock:
    proc = MagicMock()
    proc.stdout = stdout
    proc.returncode = returncode
    return proc


def test_scan_parses_json_findings():
    scanner = _make_scanner()
    stdout = "\n".join([json.dumps(_FINDING_1), json.dumps(_FINDING_LOW)])
    with patch.object(scanner, "_binary_available", return_value=True), \
         patch("subprocess.run", return_value=_mock_proc(stdout)):
        result = scanner.scan("192.168.1.10")
    assert result.success is True
    assert len(result.findings) == 2
    assert result.findings[0]["template-id"] == "CVE-2021-44228"


def test_scan_ignores_non_json_lines():
    scanner = _make_scanner()
    stdout = "[INF] Using Nuclei Engine\n" + json.dumps(_FINDING_1)
    with patch.object(scanner, "_binary_available", return_value=True), \
         patch("subprocess.run", return_value=_mock_proc(stdout)):
        result = scanner.scan("192.168.1.10")
    assert result.success is True
    assert len(result.findings) == 1


def test_scan_timeout_returns_failure():
    scanner = _make_scanner()
    with patch.object(scanner, "_binary_available", return_value=True), \
         patch("subprocess.run", side_effect=subprocess.TimeoutExpired("nuclei", 30)):
        result = scanner.scan("192.168.1.10")
    assert result.success is False
    assert result.findings == []


# ---------------------------------------------------------------------------
# convenience wrappers
# ---------------------------------------------------------------------------

def test_scan_cves_uses_cve_tag():
    scanner = _make_scanner()
    with patch.object(scanner, "_binary_available", return_value=True), \
         patch("subprocess.run", return_value=_mock_proc("")) as mock_run:
        scanner.scan_cves("10.0.0.1")
    cmd = mock_run.call_args[0][0]
    assert "-tags" in cmd
    assert "cve" in cmd[cmd.index("-tags") + 1]


def test_scan_exposures_uses_exposure_tag():
    scanner = _make_scanner()
    with patch.object(scanner, "_binary_available", return_value=True), \
         patch("subprocess.run", return_value=_mock_proc("")) as mock_run:
        scanner.scan_exposures("10.0.0.1")
    cmd = mock_run.call_args[0][0]
    assert "exposure" in cmd[cmd.index("-tags") + 1]
