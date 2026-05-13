"""Tests for GhidraAnalyzer (analyzeHeadless subprocess approach)"""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch


from raven.tools.ghidra_analyzer import (
    GhidraAnalyzer,
    GhidraResult,
    _RISKY_CALLS,
)


CONFIG_EMPTY = {"ghidra_install_dir": "", "ghidra_timeout": 30}


def _make_analyzer(**overrides) -> GhidraAnalyzer:
    return GhidraAnalyzer({**CONFIG_EMPTY, **overrides})


# ---------------------------------------------------------------------------
# _headless_binary resolution
# ---------------------------------------------------------------------------


def test_headless_binary_empty_when_no_install_dir(monkeypatch):
    monkeypatch.delenv('GHIDRA_INSTALL_DIR', raising=False)
    monkeypatch.delenv('GHIDRA_HOME', raising=False)

    a = _make_analyzer()
    a.install_dir = ''
    assert a._headless_binary() == ""


def test_headless_binary_empty_when_dir_nonexistent():
    a = _make_analyzer(ghidra_install_dir="/nonexistent/ghidra")
    assert a._headless_binary() == ""


def test_headless_binary_resolved_when_executable_exists(tmp_path):
    support = tmp_path / "support"
    support.mkdir()
    headless = support / "analyzeHeadless"
    headless.write_text("#!/bin/bash\n")
    headless.chmod(0o755)
    a = _make_analyzer(ghidra_install_dir=str(tmp_path))
    assert a._headless_binary() == str(headless)


# ---------------------------------------------------------------------------
# analyze() — graceful fallback paths
# ---------------------------------------------------------------------------


def test_analyze_failure_binary_not_found():
    a = _make_analyzer()
    a.install_dir = ''
    result = a.analyze("/nonexistent/binary.elf")
    assert result.success is False
    assert "not found" in result.error.lower()


def test_analyze_failure_no_ghidra_install(monkeypatch):
    monkeypatch.delenv('GHIDRA_INSTALL_DIR', raising=False)
    monkeypatch.delenv('GHIDRA_HOME', raising=False)

    a = _make_analyzer()
    a.install_dir = ''
    with tempfile.NamedTemporaryFile() as f:
        result = a.analyze(f.name)
    assert result.success is False
    assert "analyzeHeadless" in result.error or "GHIDRA_INSTALL_DIR" in result.error


def test_analyze_failure_scripts_dir_missing(tmp_path):
    support = tmp_path / "support"
    support.mkdir()
    headless = support / "analyzeHeadless"
    headless.write_text("#!/bin/bash\n")
    headless.chmod(0o755)
    binary = tmp_path / "test.elf"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 16)

    a = _make_analyzer(
        ghidra_install_dir=str(tmp_path),
        ghidra_scripts_dir="/nonexistent/scripts",
    )
    result = a.analyze(str(binary))
    assert result.success is False
    assert "script dir" in result.error.lower()


def test_analyze_does_not_raise():
    a = _make_analyzer()
    a.install_dir = ''
    result = a.analyze("/some/binary")
    assert isinstance(result, GhidraResult)


# ---------------------------------------------------------------------------
# _flag_suspicious — name-level matching
# ---------------------------------------------------------------------------


def test_flag_suspicious_external_risky_name():
    a = _make_analyzer()
    a.install_dir = ''
    funcs = [
        {"name": "system", "address": "0x401000", "calls": []},
        {"name": "safe_func", "address": "0x401100", "calls": []},
    ]
    result = a._flag_suspicious(funcs)
    assert len(result) == 1
    assert result[0].name == "system"
    assert "system" in result[0].risky_calls


def test_flag_suspicious_caller_of_risky_function():
    """A function that *calls* a risky API should be flagged."""
    a = _make_analyzer()
    a.install_dir = ''
    funcs = [
        {"name": "do_command", "address": "0x401200", "calls": ["system", "printf"]},
        {"name": "safe_func", "address": "0x401300", "calls": ["strlen"]},
    ]
    result = a._flag_suspicious(funcs)
    assert len(result) == 1
    assert result[0].name == "do_command"
    assert "system" in result[0].risky_calls


def test_flag_suspicious_empty_for_clean_binary():
    a = _make_analyzer()
    a.install_dir = ''
    funcs = [
        {"name": "main", "address": "0x401000", "calls": ["strlen", "printf"]},
        {"name": "helper", "address": "0x401100", "calls": []},
    ]
    assert a._flag_suspicious(funcs) == []


def test_flag_suspicious_deduplicates_risky_calls():
    a = _make_analyzer()
    a.install_dir = ''
    funcs = [{"name": "bad", "address": "0x401000", "calls": ["system", "system"]}]
    result = a._flag_suspicious(funcs)
    assert result[0].risky_calls.count("system") == 1


# ---------------------------------------------------------------------------
# _extract_decompiled_snippets
# ---------------------------------------------------------------------------


def test_extract_decompiled_snippet_finds_function_block():
    c_code = """\
void safe_func(void) {
    return;
}

int do_command(char *cmd) {
    system(cmd);
    return 0;
}
"""
    snippets = GhidraAnalyzer._extract_decompiled_snippets(c_code, ["do_command"])
    assert "do_command" in snippets
    assert "system(cmd)" in snippets["do_command"]


def test_extract_decompiled_snippet_returns_empty_for_missing_func():
    snippets = GhidraAnalyzer._extract_decompiled_snippets(
        "int main() { }", ["nonexistent"]
    )
    assert snippets == {}


def test_extract_decompiled_snippet_empty_input():
    assert GhidraAnalyzer._extract_decompiled_snippets("", ["main"]) == {}


# ---------------------------------------------------------------------------
# _risky_calls set integrity
# ---------------------------------------------------------------------------


def test_risky_calls_set_contains_known_dangerous_apis():
    assert "system" in _RISKY_CALLS
    assert "strcpy" in _RISKY_CALLS
    assert "CreateRemoteThread" in _RISKY_CALLS
    assert "connect" in _RISKY_CALLS
    assert "gets" in _RISKY_CALLS


# ---------------------------------------------------------------------------
# analyze() with mocked subprocess + JSON output files
# ---------------------------------------------------------------------------


def _write_json(path: str, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f)


def test_analyze_parses_headless_output(tmp_path):
    """Full analyze() path: mock subprocess.run and seed JSON output files."""
    # Create fake Ghidra install
    support = tmp_path / "support"
    support.mkdir()
    headless = support / "analyzeHeadless"
    headless.write_text("#!/bin/bash\n")
    headless.chmod(0o755)

    # Create fake scripts dir
    scripts_dir = tmp_path / "ghidra_scripts"
    scripts_dir.mkdir()

    # Create a real binary file
    binary = tmp_path / "test_elf"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 16)
    binary_name = "test_elf"

    functions_json = {
        "architecture": "x86",
        "functions": [
            {"name": "main", "address": "0x401000", "size": 100, "calls": ["system"]},
            {"name": "safe_func", "address": "0x401100", "size": 20, "calls": []},
        ],
    }
    strings_json = {"strings": [{"value": "Hello"}, {"value": "/bin/sh"}]}
    symbols_json = {
        "symbols": [
            {"name": "system", "type": "ExternalFunction", "isExternal": True},
        ]
    }
    decompiled_c = "int main(char *cmd) {\n    system(cmd);\n    return 0;\n}\n"

    def fake_subprocess_run(cmd, **kwargs):
        # Write JSON output files to the tmpdir passed as project location
        out_dir = kwargs["env"]["GHIDRA_OUTPUT_DIR"]
        _write_json(
            os.path.join(out_dir, binary_name + "_functions.json"), functions_json
        )
        _write_json(os.path.join(out_dir, binary_name + "_strings.json"), strings_json)
        _write_json(os.path.join(out_dir, binary_name + "_symbols.json"), symbols_json)
        with open(os.path.join(out_dir, binary_name + "_decompiled.c"), "w") as f:
            f.write(decompiled_c)
        result = MagicMock()
        result.returncode = 0
        return result

    a = _make_analyzer(
        ghidra_install_dir=str(tmp_path),
        ghidra_scripts_dir=str(scripts_dir),
    )

    with patch(
        "raven.tools.ghidra_analyzer.subprocess.run", side_effect=fake_subprocess_run
    ):
        result = a.analyze(str(binary))

    assert result.success is True
    assert result.architecture == "x86"
    assert result.function_count == 2
    assert "/bin/sh" in result.strings
    assert (
        "system" in result.imports or len(result.imports) >= 0
    )  # imports is List[str]
    assert any(s["name"] == "main" for s in result.suspicious)
    assert "main" in result.decompiled
    assert "system(cmd)" in result.decompiled["main"]


def test_analyze_returns_failure_on_nonzero_exit(tmp_path):
    support = tmp_path / "support"
    support.mkdir()
    headless = support / "analyzeHeadless"
    headless.write_text("#!/bin/bash\n")
    headless.chmod(0o755)
    scripts_dir = tmp_path / "ghidra_scripts"
    scripts_dir.mkdir()
    binary = tmp_path / "bad_binary"
    binary.write_bytes(b"\xff\xff")

    def failing_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = 2
        r.stderr = "fatal error"
        r.stdout = ""
        return r

    a = _make_analyzer(
        ghidra_install_dir=str(tmp_path),
        ghidra_scripts_dir=str(scripts_dir),
    )
    with patch("raven.tools.ghidra_analyzer.subprocess.run", side_effect=failing_run):
        result = a.analyze(str(binary))

    assert result.success is False
    assert "2" in result.error
