"""Tests for ProviderRegistry — runtime switching and named profiles."""

import json

import pytest

from raven.ai.registry import ProviderRegistry, ProviderConfig
from raven.ai.providers.lmstudio import LMStudioClient
from raven.ai.providers.openai_compat import OpenAICompatClient


@pytest.fixture(autouse=True)
def fresh_registry():
    """Reset singleton between tests."""
    ProviderRegistry._instance = None
    yield
    ProviderRegistry._instance = None


@pytest.fixture
def registry() -> ProviderRegistry:
    return ProviderRegistry.get_instance()


@pytest.fixture
def tmp_profiles(tmp_path, monkeypatch):
    """Redirect profile storage to a temp directory."""
    import raven.ai.registry as reg_module

    monkeypatch.setattr(reg_module, "_PROFILES_DIR", tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_same_instance(self):
        a = ProviderRegistry.get_instance()
        b = ProviderRegistry.get_instance()
        assert a is b


# ---------------------------------------------------------------------------
# Provider switching
# ---------------------------------------------------------------------------


class TestSwitch:
    def test_switch_to_openai(self, registry):
        client = registry.switch("openai", api_key="sk-test", model="gpt-4o")
        assert isinstance(client, OpenAICompatClient)
        assert client.provider_name == "openai"
        assert client.model == "gpt-4o"

    def test_switch_to_openrouter(self, registry):
        client = registry.switch("openrouter", api_key="sk-or-test")
        assert isinstance(client, OpenAICompatClient)
        assert "openrouter.ai" in client.base_url

    def test_switch_to_lmstudio(self, registry):
        client = registry.switch("lmstudio")
        assert isinstance(client, LMStudioClient)

    def test_switch_invalid_raises(self, registry):
        with pytest.raises(ValueError, match="Unknown provider"):
            registry.switch("totally-fake-provider")

    def test_set_model_keeps_provider(self, registry):
        registry.switch("openai", api_key="sk-test", model="gpt-4o")
        client = registry.set_model("gpt-4o-mini")
        assert client.provider_name == "openai"
        assert client.model == "gpt-4o-mini"

    def test_get_client_lazy_init(self, registry):
        client = registry.get_client()
        assert isinstance(client, LMStudioClient)

    def test_status_reflects_switch(self, registry):
        registry.switch("openrouter", api_key="sk-or-key", model="nous-hermes")
        st = registry.status()
        assert st["provider"] == "openrouter"
        assert st["model"] == "nous-hermes"
        assert st["has_api_key"] is True


# ---------------------------------------------------------------------------
# initialise_from_config
# ---------------------------------------------------------------------------


class TestInitialise:
    def test_from_full_config(self, registry):
        config = {
            "ai_provider": "openai",
            "ai_model": "gpt-4o",
            "ai_api_key": "sk-test",
            "ai_base_url": "",
            "ai_temperature": 0.5,
            "ai_max_tokens": 2048,
            "ai_timeout": 60,
        }
        client = registry.initialise_from_config(config)
        assert client.provider_name == "openai"
        assert client.model == "gpt-4o"
        assert client.temperature == 0.5

    def test_backward_compat_lmstudio_keys(self, registry):
        config = {
            "lmstudio_base_url": "http://localhost:9999",
            "lmstudio_model": "ibm/granite-4-micro",
        }
        client = registry.initialise_from_config(config)
        assert isinstance(client, LMStudioClient)
        assert client.model == "ibm/granite-4-micro"


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------


class TestProfiles:
    def test_save_and_load(self, registry, tmp_profiles):
        registry.switch("openai", api_key="sk-test-123", model="gpt-4o")
        path = registry.save_profile("work")
        assert path.exists()

        data = json.loads(path.read_text())
        assert data["provider"] == "openai"
        assert data["model"] == "gpt-4o"
        assert data["api_key"] == "sk-test-123"

    def test_load_profile(self, registry, tmp_profiles):
        registry.switch("openai", api_key="sk-test", model="gpt-4o")
        registry.save_profile("work")

        registry.switch("lmstudio")
        assert registry.status()["provider"] == "lmstudio"

        client = registry.load_profile("work")
        assert client.provider_name == "openai"
        assert registry.status()["provider"] == "openai"

    def test_load_nonexistent_raises(self, registry, tmp_profiles):
        with pytest.raises(FileNotFoundError):
            registry.load_profile("does-not-exist")

    def test_list_profiles(self, registry, tmp_profiles):
        registry.switch("openai", api_key="sk-test")
        registry.save_profile("alpha")
        registry.save_profile("beta")
        profiles = registry.list_profiles()
        assert "alpha" in profiles
        assert "beta" in profiles

    def test_delete_profile(self, registry, tmp_profiles):
        registry.switch("openai", api_key="sk-test")
        registry.save_profile("to-delete")
        assert "to-delete" in registry.list_profiles()
        deleted = registry.delete_profile("to-delete")
        assert deleted is True
        assert "to-delete" not in registry.list_profiles()

    def test_delete_nonexistent_returns_false(self, registry, tmp_profiles):
        assert registry.delete_profile("ghost") is False

    def test_profile_permissions(self, registry, tmp_profiles):
        registry.switch("openai", api_key="sk-secret")
        path = registry.save_profile("secure")
        mode = oct(path.stat().st_mode)[-3:]
        assert mode == "600", f"Profile file should be 600, got {mode}"


# ---------------------------------------------------------------------------
# ProviderConfig serialisation
# ---------------------------------------------------------------------------


class TestProviderConfig:
    def test_to_client_config(self):
        cfg = ProviderConfig(provider="openrouter", model="test-model", api_key="key")
        cc = cfg.to_client_config()
        assert cc["ai_provider"] == "openrouter"
        assert cc["ai_model"] == "test-model"
        assert cc["ai_api_key"] == "key"

    def test_from_dict_roundtrip(self):
        original = ProviderConfig(
            provider="anthropic", model="claude-3-5-sonnet", api_key="sk-ant"
        )
        data = {
            "provider": original.provider,
            "model": original.model,
            "api_key": original.api_key,
            "base_url": original.base_url,
            "temperature": original.temperature,
            "max_tokens": original.max_tokens,
            "timeout": original.timeout,
        }
        restored = ProviderConfig.from_dict(data)
        assert restored.provider == original.provider
        assert restored.model == original.model
        assert restored.api_key == original.api_key
