"""Tests for EBPFGhidraSetup (Solana eBPF-for-Ghidra integration helper)."""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_setup(ghidra_dir: str = "", binary_avail: bool = False):
    from raven.tools.ebpf_ghidra import EBPFGhidraSetup
    s = EBPFGhidraSetup({"ghidra_install_dir": ghidra_dir})
    s.is_available = MagicMock(return_value=binary_avail)
    return s


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_solana_language_id():
    from raven.tools.ebpf_ghidra import SOLANA_EBPF_LANGUAGE
    assert "Solana" in SOLANA_EBPF_LANGUAGE
    assert "eBPF" in SOLANA_EBPF_LANGUAGE


def test_install_hint_contains_repo():
    from raven.tools.ebpf_ghidra import INSTALL_HINT
    assert "blastrock/Solana-eBPF-for-Ghidra" in INSTALL_HINT
    assert "gradle" in INSTALL_HINT


# ---------------------------------------------------------------------------
# extension_installed / extension_path
# ---------------------------------------------------------------------------

def test_extension_not_installed_no_ghidra_dir():
    s = _make_setup(ghidra_dir="")
    assert s.extension_installed() is False
    assert s.extension_path() is None


def test_extension_installed_glob_match(tmp_path):
    ghidra_dir = tmp_path
    ext_dir = ghidra_dir / "Extensions" / "Ghidra"
    ext_dir.mkdir(parents=True)
    ext_zip = ext_dir / "eBPF-for-Ghidra-Solana-1.0.0.zip"
    ext_zip.write_bytes(b"fake zip")

    s = _make_setup(ghidra_dir=str(ghidra_dir))
    assert s.extension_installed() is True
    assert s.extension_path() == str(ext_zip)


def test_extension_not_installed_no_matching_files(tmp_path):
    ghidra_dir = tmp_path
    ext_dir = ghidra_dir / "Extensions" / "Ghidra"
    ext_dir.mkdir(parents=True)
    (ext_dir / "SomeOtherExtension.zip").write_bytes(b"x")

    s = _make_setup(ghidra_dir=str(ghidra_dir))
    assert s.extension_installed() is False


# ---------------------------------------------------------------------------
# setup_status
# ---------------------------------------------------------------------------

def test_setup_status_no_ghidra():
    s = _make_setup(binary_avail=False)
    result = s.setup_status()
    assert result.success is False
    assert "analyzeHeadless not found" in (result.error or "")
    assert result.parsed["analyzeHeadless"] is False


def test_setup_status_ghidra_but_no_extension(tmp_path):
    s = _make_setup(ghidra_dir=str(tmp_path), binary_avail=True)
    result = s.setup_status()
    assert result.success is False
    assert "eBPF-for-Ghidra extension not installed" in (result.error or "")
    assert result.parsed["analyzeHeadless"] is True
    assert result.parsed["ebpf_extension_installed"] is False


def test_setup_status_all_ok(tmp_path):
    ghidra_dir = tmp_path
    ext_dir = ghidra_dir / "Extensions" / "Ghidra"
    ext_dir.mkdir(parents=True)
    (ext_dir / "eBPFSolana-1.0.zip").write_bytes(b"fake")

    s = _make_setup(ghidra_dir=str(ghidra_dir), binary_avail=True)
    result = s.setup_status()
    assert result.success is True
    assert result.parsed["analyzeHeadless"] is True
    assert result.parsed["ebpf_extension_installed"] is True
    assert result.parsed["solana_language_id"] is not None


# ---------------------------------------------------------------------------
# setup_status to_dict
# ---------------------------------------------------------------------------

def test_setup_status_to_dict(tmp_path):
    s = _make_setup(binary_avail=False)
    d = s.setup_status().to_dict()
    assert d["tool"] == "solana-ebpf-ghidra"
    assert d["success"] is False
    assert isinstance(d["parsed"], dict)


# ---------------------------------------------------------------------------
# analyze_solana_so
# ---------------------------------------------------------------------------

def test_analyze_solana_so_no_ghidra():
    s = _make_setup(binary_avail=False)
    result = s.analyze_solana_so("/tmp/program.so")
    assert result.success is False
    assert "analyzeHeadless" in (result.error or "")


def test_analyze_solana_so_no_extension(tmp_path):
    s = _make_setup(ghidra_dir=str(tmp_path), binary_avail=True)
    result = s.analyze_solana_so("/tmp/program.so")
    assert result.success is False
    assert "extension not installed" in (result.error or "")


def test_analyze_solana_so_runs_headless(tmp_path):
    from raven.tools.ebpf_ghidra import EBPFGhidraSetup, SOLANA_EBPF_LANGUAGE
    from raven.tools.adapter_base import ToolResult

    ghidra_dir = tmp_path
    ext_dir = ghidra_dir / "Extensions" / "Ghidra"
    ext_dir.mkdir(parents=True)
    (ext_dir / "eBPFSolana-1.0.zip").write_bytes(b"fake")

    s = EBPFGhidraSetup({"ghidra_install_dir": str(ghidra_dir)})
    s.is_available = MagicMock(return_value=True)

    fake = ToolResult(tool="solana-ebpf-ghidra", success=True, target="/tmp/program.so",
                      stdout="Analysis complete", exit_code=0)
    with patch.object(s, "_run", return_value=fake) as mock_run:
        result = s.analyze_solana_so("/tmp/program.so", project_dir=str(tmp_path))

    assert result.success is True
    cmd = mock_run.call_args[0][0]
    assert "-import" in cmd
    assert "/tmp/program.so" in cmd
    assert SOLANA_EBPF_LANGUAGE in cmd
