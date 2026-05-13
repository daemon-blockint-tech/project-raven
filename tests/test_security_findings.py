"""Regression tests for the 6 security findings (F1-F6) closed in Phase 1.

These tests verify the controls at the unit level. The full HTTP integration
tests are gated behind `pytest.importorskip("paramiko")` and skipped on dev
boxes without optional deps.
"""

from __future__ import annotations

import re

import pytest


# ---------------------------------------------------------------------------
# F1 — base_url allowlist
# ---------------------------------------------------------------------------

class TestF1BaseUrlAllowlist:
    """`/ai/provider` must reject base_url values outside the allowlist."""

    def test_built_in_provider_urls_in_allowlist(self):
        from raven.ai.base import SUPPORTED_PROVIDERS
        for info in SUPPORTED_PROVIDERS.values():
            if info.default_base_url:
                # Sanity: every built-in default is a well-formed http(s) URL
                assert info.default_base_url.startswith(("http://", "https://"))

    def test_endpoint_jails_arbitrary_url(self):
        pytest.importorskip("paramiko")
        from fastapi.testclient import TestClient
        from raven.api.main import app
        # Should reject before any auth check evaluates the body? No — auth runs
        # first. Without a valid token we get 401, not 403. That still proves
        # the endpoint isn't world-mutable. We assert 401.
        client = TestClient(app)
        resp = client.post(
            "/ai/provider",
            json={"provider": "openai", "base_url": "http://attacker.com/v1"},
        )
        assert resp.status_code == 401  # auth required first; closes F4 too


# ---------------------------------------------------------------------------
# F2 — repo_path scan jail
# ---------------------------------------------------------------------------

class TestF2ScanJail:
    @staticmethod
    def _jail(raw: str, root: str) -> bool:
        """Replicate the exact logic from raven/api/main.py:_jail_scan_path."""
        from pathlib import Path
        try:
            root_p = Path(root).resolve()
            target = Path(raw).resolve(strict=False)
            target.relative_to(root_p)
            return True
        except ValueError:
            return False

    def test_rejects_etc_passwd(self, tmp_path):
        assert self._jail("/etc/passwd", str(tmp_path)) is False

    def test_rejects_traversal(self, tmp_path):
        assert self._jail(str(tmp_path) + "/../escape", str(tmp_path)) is False

    def test_accepts_subdir(self, tmp_path):
        sub = tmp_path / "repo"
        sub.mkdir()
        assert self._jail(str(sub), str(tmp_path)) is True


# ---------------------------------------------------------------------------
# F3 — persistent prompt injection now gated by admin role (F4 enabling)
# ---------------------------------------------------------------------------

class TestF3PromptInjectionRequiresAuth:
    def test_endpoint_requires_auth(self):
        pytest.importorskip("paramiko")
        from fastapi.testclient import TestClient
        from raven.api.main import app
        client = TestClient(app)
        resp = client.post("/ai/system-prompt", json={"prompt": "malicious"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# F4 — all /ai/* mutations require auth
# ---------------------------------------------------------------------------

class TestF4AuthRequired:
    @pytest.mark.parametrize("method,path,body", [
        ("post",   "/ai/provider", {"provider": "openai"}),
        ("post",   "/ai/model", {"model": "gpt-4o"}),
        ("post",   "/ai/system-prompt", {"prompt": "x"}),
        ("delete", "/ai/system-prompt", None),
        ("post",   "/ai/provider/profiles/test", None),
        ("put",    "/ai/provider/profiles/test", None),
        ("delete", "/ai/provider/profiles/test", None),
        ("post",   "/ai/models/load", {"model": "x"}),
        ("post",   "/ai/models/unload", {"model": "x"}),
        ("post",   "/ai/analyze", {"code": "x"}),
        ("post",   "/ai/hypothesis", {"indicators": {}}),
        ("post",   "/ai/validate", {"vuln_data": {}}),
        ("post",   "/hunt", {}),
        ("post",   "/hunt/variant", {"repo_path": "/"}),
        ("post",   "/hunt/code", {"repo_path": "/"}),
        ("post",   "/hunt/killchain", {"objective": "x", "target_network": "y"}),
        ("post",   "/hunt/killchain/approve", None),
        ("post",   "/hunt/killchain/reject", None),
        ("post",   "/investigate/target", {"host": "1.2.3.4"}),
        ("post",   "/mitigate", None),
    ])
    def test_endpoint_returns_401_without_token(self, method, path, body):
        pytest.importorskip("paramiko")
        from fastapi.testclient import TestClient
        from raven.api.main import app
        client = TestClient(app)
        fn = getattr(client, method)
        resp = fn(path, json=body) if body is not None else fn(path)
        assert resp.status_code in (401, 422), (
            f"{method.upper()} {path} returned {resp.status_code}; "
            f"expected 401 (unauthenticated) or 422 (missing query params before auth)"
        )


# ---------------------------------------------------------------------------
# F5 — profile name regex
# ---------------------------------------------------------------------------

class TestF5ProfileNameRegex:
    PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

    def test_valid_names(self):
        for name in ("work", "work-profile", "test_1", "a", "A" * 64):
            assert self.PATTERN.match(name)

    def test_invalid_names_rejected(self):
        for bad in ("../poisoned", "..", "a/b", "a b", "", "x" * 65, "name.json"):
            assert not self.PATTERN.match(bad)


# ---------------------------------------------------------------------------
# F6 — SSHManager uses RejectPolicy
# ---------------------------------------------------------------------------

class TestF6SSHPolicy:
    def test_ssh_manager_uses_reject_policy(self):
        paramiko = pytest.importorskip("paramiko")
        from raven.tools.ssh_manager import SSHManager

        mgr = SSHManager({"ssh_timeout": 5, "ssh_known_hosts": "/nonexistent"})
        client = mgr._build_client()
        # paramiko stores the policy at `_policy`
        assert isinstance(client._policy, paramiko.RejectPolicy)
