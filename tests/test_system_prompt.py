"""Tests for system prompt integration — BaseAIClient + ProviderRegistry."""

import json
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from raven.ai.base import AIMessage, AIResponse, BaseAIClient
from raven.ai.providers.lmstudio import LMStudioClient
from raven.ai.registry import ProviderRegistry, ProviderConfig


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fresh_registry():
    ProviderRegistry._instance = None
    yield
    ProviderRegistry._instance = None


@pytest.fixture
def registry() -> ProviderRegistry:
    return ProviderRegistry.get_instance()


@pytest.fixture
def client() -> LMStudioClient:
    return LMStudioClient({"ai_provider": "lmstudio"})


# ---------------------------------------------------------------------------
# BaseAIClient._build_messages
# ---------------------------------------------------------------------------

class TestBuildMessages:
    def test_prepends_when_no_system_message(self, client):
        client.system_prompt = "Be concise."
        msgs = [AIMessage(role="user", content="hello")]
        built = client._build_messages(msgs)
        assert built[0].role == "system"
        assert built[0].content == "Be concise."
        assert built[1].role == "user"

    def test_does_not_prepend_when_system_already_present(self, client):
        client.system_prompt = "Be concise."
        msgs = [
            AIMessage(role="system", content="Custom system."),
            AIMessage(role="user", content="hello"),
        ]
        built = client._build_messages(msgs)
        assert len(built) == 2
        assert built[0].content == "Custom system."

    def test_noop_when_prompt_empty(self, client):
        client.system_prompt = ""
        msgs = [AIMessage(role="user", content="hello")]
        built = client._build_messages(msgs)
        assert built == msgs

    def test_original_list_not_mutated(self, client):
        client.system_prompt = "Injected."
        original = [AIMessage(role="user", content="test")]
        built = client._build_messages(original)
        assert len(original) == 1
        assert len(built) == 2


# ---------------------------------------------------------------------------
# ProviderRegistry system prompt methods
# ---------------------------------------------------------------------------

class TestRegistrySystemPrompt:
    def test_set_and_get(self, registry):
        registry.set_system_prompt("You are Raven.")
        assert registry.get_system_prompt() == "You are Raven."

    def test_set_propagates_to_client(self, registry):
        registry.switch("lmstudio")
        registry.set_system_prompt("Injected after switch.")
        client = registry.get_client()
        assert client.system_prompt == "Injected after switch."

    def test_clear_prompt(self, registry):
        registry.set_system_prompt("Something")
        registry.set_system_prompt("")
        assert registry.get_system_prompt() == ""

    def test_prompt_persists_in_profile(self, registry, tmp_path, monkeypatch):
        import raven.ai.registry as reg_module
        monkeypatch.setattr(reg_module, "_PROFILES_DIR", tmp_path)
        registry.set_system_prompt("Persisted prompt.")
        registry.save_profile("test")
        data = json.loads((tmp_path / "test.json").read_text())
        assert data["system_prompt"] == "Persisted prompt."

    def test_prompt_restored_on_profile_load(self, registry, tmp_path, monkeypatch):
        import raven.ai.registry as reg_module
        monkeypatch.setattr(reg_module, "_PROFILES_DIR", tmp_path)
        registry.set_system_prompt("Persisted prompt.")
        registry.save_profile("test")

        registry.set_system_prompt("")
        assert registry.get_system_prompt() == ""

        registry.load_profile("test")
        assert registry.get_system_prompt() == "Persisted prompt."

    def test_status_includes_prompt_meta(self, registry):
        registry.set_system_prompt("Hello Raven")
        st = registry.status()
        assert st["system_prompt_set"] is True
        assert st["system_prompt_len"] == len("Hello Raven")

    def test_status_no_prompt(self, registry):
        st = registry.status()
        assert st["system_prompt_set"] is False
        assert st["system_prompt_len"] == 0


# ---------------------------------------------------------------------------
# load_system_prompt_from_file
# ---------------------------------------------------------------------------

class TestLoadSystemPromptFromFile:
    def test_load_plain_text(self, registry, tmp_path):
        f = tmp_path / "prompt.txt"
        f.write_text("You are Raven.")
        prompt = registry.load_system_prompt_from_file(str(f))
        assert prompt == "You are Raven."
        assert registry.get_system_prompt() == "You are Raven."

    def test_load_md_extracts_fenced_block(self, registry, tmp_path):
        md = textwrap.dedent("""\
            # System Prompt

            Some intro text.

            ```
            You are Raven, a cybersecurity AI.
            Be concise.
            ```

            Trailing text.
        """)
        f = tmp_path / "prompt.md"
        f.write_text(md)
        prompt = registry.load_system_prompt_from_file(str(f))
        assert "You are Raven" in prompt
        assert "Trailing text" not in prompt

    def test_load_md_falls_back_to_full_content_if_no_fence(self, registry, tmp_path):
        md = "# No fence here\n\nJust plain markdown."
        f = tmp_path / "prompt.md"
        f.write_text(md)
        prompt = registry.load_system_prompt_from_file(str(f))
        assert "No fence here" in prompt

    def test_missing_file_raises(self, registry):
        with pytest.raises(FileNotFoundError):
            registry.load_system_prompt_from_file("/nonexistent/prompt.md")

    def test_missing_file_silent_returns_empty(self, registry):
        result = registry.load_system_prompt_from_file("/nonexistent/prompt.md", silent=True)
        assert result == ""

    def test_loads_actual_raven_system_prompt_md(self, registry):
        """Integration: RAVEN_SYSTEM_PROMPT.md should exist and parse correctly."""
        raven_md = Path(__file__).parent.parent / "RAVEN_SYSTEM_PROMPT.md"
        if not raven_md.exists():
            pytest.skip("RAVEN_SYSTEM_PROMPT.md not found")
        prompt = registry.load_system_prompt_from_file(str(raven_md))
        assert len(prompt) > 100
        assert "Raven" in prompt


# ---------------------------------------------------------------------------
# initialise_from_config auto-loads prompt
# ---------------------------------------------------------------------------

class TestProviderChatInjectsSystemPrompt:
    """Regression tests for Bug 1: providers' chat() must auto-inject
    the registry's system prompt. Previously _build_messages() was only
    called by base-class task helpers, so ModelOrchestrator and any
    direct chat() caller silently dropped the prompt."""

    def _capture_payload(self, client):
        """Return a list that captures the messages sent to the wire."""
        captured: list = []

        def fake_post(url, json=None, **kwargs):  # noqa: A002
            captured.append(json)
            mock = MagicMock()
            mock.status_code = 200
            mock.raise_for_status = MagicMock()
            mock.json.return_value = {
                "content": "ok",
                "model": "test",
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }
            return mock

        return captured, fake_post

    def test_lmstudio_chat_injects_prompt_for_user_only_messages(self):
        client = LMStudioClient({"ai_provider": "lmstudio"})
        client.system_prompt = "OPERATIONAL_GUARDRAIL"
        captured, fake_post = self._capture_payload(client)
        with patch("raven.ai.providers.lmstudio.requests.post", side_effect=fake_post):
            client.chat([AIMessage(role="user", content="hi")])
        sent = captured[0]["messages"]
        assert sent[0]["role"] == "system"
        assert sent[0]["content"] == "OPERATIONAL_GUARDRAIL"
        assert sent[1]["role"] == "user"

    def test_openai_compat_chat_injects_prompt_for_user_only_messages(self):
        from raven.ai.providers.openai_compat import OpenAICompatClient
        client = OpenAICompatClient({
            "ai_provider": "openai",
            "ai_api_key": "test",
        })
        client.system_prompt = "OPERATIONAL_GUARDRAIL"
        captured, fake_post = self._capture_payload(client)
        with patch("raven.ai.providers.openai_compat.requests.post", side_effect=fake_post):
            client.chat([AIMessage(role="user", content="hi")])
        sent = captured[0]["messages"]
        assert sent[0]["role"] == "system"
        assert sent[0]["content"] == "OPERATIONAL_GUARDRAIL"

    def test_chat_does_not_double_inject_when_caller_provides_system(self):
        """If the caller already provides a system message, registry prompt must NOT be added."""
        client = LMStudioClient({"ai_provider": "lmstudio"})
        client.system_prompt = "REGISTRY_PROMPT"
        captured, fake_post = self._capture_payload(client)
        with patch("raven.ai.providers.lmstudio.requests.post", side_effect=fake_post):
            client.chat([
                AIMessage(role="system", content="CALLER_PROMPT"),
                AIMessage(role="user", content="hi"),
            ])
        sent = captured[0]["messages"]
        # Only ONE system message — the caller's, not the registry's
        system_msgs = [m for m in sent if m["role"] == "system"]
        assert len(system_msgs) == 1
        assert system_msgs[0]["content"] == "CALLER_PROMPT"

    def test_model_orchestrator_chat_propagates_system_prompt(self):
        """ModelOrchestrator.chat() routes through client.chat() — must inherit injection."""
        from raven.ai.model_orchestrator import ModelOrchestrator, ModelRole
        client = LMStudioClient({"ai_provider": "lmstudio"})
        client.system_prompt = "OPERATIONAL_GUARDRAIL"
        captured, fake_post = self._capture_payload(client)
        orchestrator = ModelOrchestrator(client)
        # Skip the _ensure_loaded round-trip by stubbing it
        with patch.object(orchestrator, "_ensure_loaded"), \
             patch.object(orchestrator, "_model_id", return_value="test-model"), \
             patch("raven.ai.providers.lmstudio.requests.post", side_effect=fake_post):
            orchestrator.chat(ModelRole.FAST, [AIMessage(role="user", content="hi")])
        sent = captured[0]["messages"]
        assert sent[0]["role"] == "system"
        assert sent[0]["content"] == "OPERATIONAL_GUARDRAIL"


class TestSystemPromptPathTraversal:
    """Regression test for Bug 2: POST /ai/system-prompt must reject paths
    outside the server CWD to prevent arbitrary file read.

    Tests the jail logic directly (doesn't boot the full FastAPI app which
    pulls heavy optional deps like paramiko)."""

    @staticmethod
    def _jail_check(raw_path: str) -> bool:
        """Replicates the exact jail check in /ai/system-prompt POST handler.
        Returns True if path is allowed, False otherwise."""
        import os
        from pathlib import Path as _Path
        try:
            target = _Path(raw_path).resolve(strict=False)
            cwd = _Path(os.getcwd()).resolve()
            target.relative_to(cwd)
            return True
        except ValueError:
            return False

    def test_jail_rejects_absolute_path_outside_cwd(self):
        assert self._jail_check("/etc/passwd") is False

    def test_jail_rejects_dot_dot_traversal(self):
        assert self._jail_check("../../../etc/passwd") is False

    def test_jail_rejects_root(self):
        assert self._jail_check("/") is False

    def test_jail_accepts_path_inside_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "sys.txt").write_text("ok")
        assert self._jail_check("sys.txt") is True

    def test_jail_accepts_resolved_absolute_path_inside_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "sys.txt"
        f.write_text("ok")
        assert self._jail_check(str(f)) is True

    def test_endpoint_integration(self):
        """Full HTTP test — skipped when optional API deps (paramiko) missing."""
        pytest.importorskip("paramiko")
        from fastapi.testclient import TestClient
        from raven.api.main import app
        client = TestClient(app)
        resp = client.post("/ai/system-prompt", json={"file": "/etc/passwd"})
        assert resp.status_code == 403


class TestInitialiseAutoLoad:
    def test_auto_loads_prompt_from_path(self, registry, tmp_path):
        f = tmp_path / "sys.txt"
        f.write_text("Auto-loaded prompt.")
        registry.initialise_from_config({
            "ai_provider": "lmstudio",
            "ai_system_prompt_path": str(f),
        })
        assert registry.get_system_prompt() == "Auto-loaded prompt."
        assert registry.get_client().system_prompt == "Auto-loaded prompt."

    def test_skips_if_path_empty(self, registry):
        registry.initialise_from_config({
            "ai_provider": "lmstudio",
            "ai_system_prompt_path": "",
        })
        assert registry.get_system_prompt() == ""

    def test_silent_on_missing_file(self, registry):
        registry.initialise_from_config({
            "ai_provider": "lmstudio",
            "ai_system_prompt_path": "/no/such/file.md",
        })
        assert registry.get_system_prompt() == ""
