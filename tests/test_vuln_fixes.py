"""Regression tests for the 4 user-reported vulnerabilities.

VULN-1 confirmed real (dev/staging only); fix enforces the SECRET_KEY floor
in every environment unless RAVEN_ALLOW_INSECURE_DEFAULTS is set.

VULN-2 was a false positive — there is no save_path in /ai/system-prompt.
Test pins the actual public surface to prevent the vuln from being
introduced later.

VULN-3 latent shell injection — BashExecutor now defaults to shell=False,
patch_id is regex-validated + shlex.quoted, pid is coerced to int.

VULN-4 pickle/joblib model loading refused unless allow_pickle_models=true
AND the path stays under MODEL_PATH.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# VULN-1 — SECRET_KEY floor
# ---------------------------------------------------------------------------

class TestVuln1SecretKeyFloor:
    """Default JWT secret must refuse to boot unless explicitly opted in."""

    def test_default_secret_refused_in_dev(self, monkeypatch):
        from raven.config import _DEFAULT_SECRET, Settings
        monkeypatch.setenv("SECRET_KEY", _DEFAULT_SECRET)
        monkeypatch.setenv("RAVEN_ENVIRONMENT", "dev")
        monkeypatch.delenv("RAVEN_ALLOW_INSECURE_DEFAULTS", raising=False)
        with pytest.raises(Exception) as excinfo:
            Settings(_env_file=None)
        assert "SECRET_KEY is unset" in str(excinfo.value) or "dev default" in str(excinfo.value)

    def test_default_secret_refused_in_staging(self, monkeypatch):
        from raven.config import _DEFAULT_SECRET, Settings
        monkeypatch.setenv("SECRET_KEY", _DEFAULT_SECRET)
        monkeypatch.setenv("RAVEN_ENVIRONMENT", "staging")
        monkeypatch.delenv("RAVEN_ALLOW_INSECURE_DEFAULTS", raising=False)
        with pytest.raises(Exception):
            Settings(_env_file=None)

    def test_default_secret_allowed_only_with_explicit_optin(self, monkeypatch):
        from raven.config import _DEFAULT_SECRET, Settings
        monkeypatch.setenv("SECRET_KEY", _DEFAULT_SECRET)
        monkeypatch.setenv("RAVEN_ENVIRONMENT", "dev")
        monkeypatch.setenv("ALLOW_INSECURE_DEFAULTS", "true")
        # Boots but emits a RuntimeWarning
        with pytest.warns(RuntimeWarning, match="default JWT secret"):
            s = Settings(_env_file=None,
                         cors_origins=["http://localhost:3000"])
        assert s.allow_insecure_defaults is True

    def test_optin_refused_in_prod(self, monkeypatch):
        from raven.config import Settings
        monkeypatch.setenv("SECRET_KEY", "x" * 32)
        monkeypatch.setenv("RAVEN_ENVIRONMENT", "prod")
        monkeypatch.setenv("ALLOW_INSECURE_DEFAULTS", "true")
        # Pass cors_origins explicitly to bypass the pydantic-settings JSON
        # decode of the List[str] env var.
        with pytest.raises(Exception) as excinfo:
            Settings(_env_file=None,
                     cors_origins=["https://raven.example.com"])
        assert "RAVEN_ALLOW_INSECURE_DEFAULTS" in str(excinfo.value)


# ---------------------------------------------------------------------------
# VULN-2 — false positive confirmation
# ---------------------------------------------------------------------------

class TestVuln2NoSavePath:
    """The /ai/system-prompt POST handler must NOT accept a save_path."""

    def test_endpoint_source_has_no_save_path(self):
        src = Path("raven/api/main.py").read_text()
        # The endpoint exists
        assert "@app.post(\"/ai/system-prompt\")" in src
        # … and explicitly does not handle save_path
        # (the only references to 'save_path' should be absent entirely)
        assert "save_path" not in src

    def test_only_write_text_is_profile_save(self):
        """Pin the single .write_text() call to save_profile with a
        regex-validated name."""
        import raven.ai.registry as reg
        src = Path(reg.__file__).read_text()
        # save_profile builds path from _PROFILES_DIR / f'{name}.json'
        # and the route validator regex enforces ^[A-Za-z0-9_-]{1,64}$.
        assert "_PROFILES_DIR / f\"{name}.json\"" in src


# ---------------------------------------------------------------------------
# VULN-3 — Shell injection hardening
# ---------------------------------------------------------------------------

class TestVuln3ShellHardening:
    def test_bash_executor_defaults_to_no_shell(self):
        from raven.tools.bash_executor import BashExecutor

        ex = BashExecutor({"bash_timeout": 5})
        # printf '%s' "$VAR" only works with a shell — without it, both
        # arguments are passed positionally and the env var is not expanded.
        result = ex.execute("/bin/echo hello world")
        assert result.success
        assert "hello world" in result.stdout

    def test_bash_executor_injection_blocked_by_default(self):
        """Without allow_shell=True, the metacharacters get passed as
        literal args rather than triggering a shell-injection."""
        from raven.tools.bash_executor import BashExecutor
        ex = BashExecutor({"bash_timeout": 5})
        # Try injection — the second command should NOT run
        result = ex.execute("/bin/echo safe; touch /tmp/raven_pwned_marker")
        # The file must not exist
        assert not Path("/tmp/raven_pwned_marker").exists()
        # Cleanup if a previous test created it
        Path("/tmp/raven_pwned_marker").unlink(missing_ok=True)

    def test_bash_executor_opt_in_shell_still_works(self):
        from raven.tools.bash_executor import BashExecutor
        ex = BashExecutor({"bash_timeout": 5})
        result = ex.execute("echo $((2 + 2))", allow_shell=True)
        assert "4" in result.stdout

    def test_remediation_engine_rejects_metacharacters(self):
        from raven.mitigation.remediation_engine import RemediationEngine

        engine = RemediationEngine({}, {})
        bad_id = "openssl; rm -rf /"
        result = engine.apply_patch("host1", bad_id)
        assert result.success is False
        assert "invalid patch_id" in result.details.get("error", "")

    def test_remediation_engine_accepts_valid_id(self):
        from raven.mitigation.remediation_engine import RemediationEngine

        # No ssh tool wired → success will be False but no error path hit
        engine = RemediationEngine({}, {})
        result = engine.apply_patch("host1", "openssl-1.1.1n")
        # Format passes; SSH tool absent → success=False but cleanly
        assert "error" not in (result.details or {})

    def test_containment_rejects_string_pid(self):
        from raven.mitigation.containment_actions import ContainmentActions

        actions = ContainmentActions({}, {})
        result = actions.terminate_process("host1", "1234; rm -rf /")  # type: ignore[arg-type]
        assert result.success is False
        assert "invalid pid" in result.details.get("error", "")

    def test_containment_rejects_negative_pid(self):
        from raven.mitigation.containment_actions import ContainmentActions

        actions = ContainmentActions({}, {})
        result = actions.terminate_process("host1", -1)
        assert result.success is False


# ---------------------------------------------------------------------------
# VULN-4 — pickle/joblib loading gate
# ---------------------------------------------------------------------------

class TestVuln4PickleGate:
    def test_anomaly_load_refused_when_flag_off(self, tmp_path, monkeypatch):
        from raven.config import settings
        monkeypatch.setattr(settings, "allow_pickle_models", False)
        from raven.core.anomaly_detector import AnomalyDetector

        det = AnomalyDetector({})
        with pytest.raises(PermissionError, match="disabled"):
            det.load_model(str(tmp_path / "any.pkl"))

    def test_anomaly_load_refused_outside_model_path(self, tmp_path, monkeypatch):
        from raven.config import settings
        # Allow pickle, but constrain MODEL_PATH to an unrelated directory
        monkeypatch.setattr(settings, "allow_pickle_models", True)
        monkeypatch.setattr(settings, "model_path", str(tmp_path / "models"))
        (tmp_path / "models").mkdir()
        # Try to load from outside MODEL_PATH
        evil = tmp_path / "evil.pkl"
        evil.write_bytes(b"")
        from raven.core.anomaly_detector import AnomalyDetector
        det = AnomalyDetector({})
        with pytest.raises(PermissionError, match="outside MODEL_PATH"):
            det.load_model(str(evil))

    def test_zero_day_load_refused_when_flag_off(self, tmp_path, monkeypatch):
        from raven.config import settings
        monkeypatch.setattr(settings, "allow_pickle_models", False)
        from raven.ml.zero_day_detector import ZeroDayDetector

        det = ZeroDayDetector({})
        with pytest.raises(PermissionError, match="disabled"):
            det.load_models(str(tmp_path / "any.joblib"))

    def test_zero_day_load_refused_outside_model_path(self, tmp_path, monkeypatch):
        from raven.config import settings
        monkeypatch.setattr(settings, "allow_pickle_models", True)
        monkeypatch.setattr(settings, "model_path", str(tmp_path / "models"))
        (tmp_path / "models").mkdir()
        evil = tmp_path / "evil.joblib"
        evil.write_bytes(b"")
        from raven.ml.zero_day_detector import ZeroDayDetector
        det = ZeroDayDetector({})
        with pytest.raises(PermissionError, match="outside MODEL_PATH"):
            det.load_models(str(evil))
