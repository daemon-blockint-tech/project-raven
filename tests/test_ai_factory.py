"""Tests for the AI client factory and provider routing."""

import pytest

from raven.ai.base import parse_provider_model, SUPPORTED_PROVIDERS
from raven.ai.factory import create_client_from_config
from raven.ai.providers.lmstudio import LMStudioClient
from raven.ai.providers.openai_compat import OpenAICompatClient
from raven.ai.providers.anthropic_provider import AnthropicClient


# ---------------------------------------------------------------------------
# parse_provider_model
# ---------------------------------------------------------------------------


class TestParseProviderModel:
    def test_full_spec(self):
        assert parse_provider_model("openrouter:nous-hermes-2-mixtral-8x7b") == (
            "openrouter",
            "nous-hermes-2-mixtral-8x7b",
        )

    def test_plain_model(self):
        provider, model = parse_provider_model("gpt-4o")
        assert provider == ""
        assert model == "gpt-4o"

    def test_provider_only(self):
        provider, model = parse_provider_model("openrouter:")
        assert provider == "openrouter"
        assert model == ""

    def test_whitespace_stripped(self):
        assert parse_provider_model("  anthropic : claude-3-5-sonnet ") == (
            "anthropic",
            "claude-3-5-sonnet",
        )


# ---------------------------------------------------------------------------
# Factory routing
# ---------------------------------------------------------------------------


class TestFactory:
    def test_lmstudio_default(self):
        client = create_client_from_config({})
        assert isinstance(client, LMStudioClient)
        assert client.provider_name == "lmstudio"

    def test_lmstudio_explicit(self):
        client = create_client_from_config({"ai_provider": "lmstudio"})
        assert isinstance(client, LMStudioClient)

    def test_openai(self):
        client = create_client_from_config(
            {"ai_provider": "openai", "ai_api_key": "sk-test"}
        )
        assert isinstance(client, OpenAICompatClient)
        assert client.provider_name == "openai"

    def test_openrouter(self):
        client = create_client_from_config(
            {"ai_provider": "openrouter", "ai_api_key": "sk-or-test"}
        )
        assert isinstance(client, OpenAICompatClient)
        assert client.provider_name == "openrouter"
        assert "openrouter.ai" in client.base_url

    def test_ollama(self):
        client = create_client_from_config({"ai_provider": "ollama"})
        assert isinstance(client, OpenAICompatClient)
        assert "11434" in client.base_url

    def test_nous(self):
        client = create_client_from_config({"ai_provider": "nous", "ai_api_key": "key"})
        assert isinstance(client, OpenAICompatClient)
        assert "nousresearch" in client.base_url

    def test_anthropic(self):
        client = create_client_from_config(
            {"ai_provider": "anthropic", "ai_api_key": "sk-ant-test"}
        )
        assert isinstance(client, AnthropicClient)
        assert client.provider_name == "anthropic"

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="Unknown AI provider"):
            create_client_from_config({"ai_provider": "unknown-xyz"})

    def test_provider_model_shorthand(self):
        client = create_client_from_config(
            {
                "ai_model": "openrouter:nous-hermes-2-mixtral-8x7b",
                "ai_api_key": "sk-or-test",
            }
        )
        assert isinstance(client, OpenAICompatClient)
        assert client.provider_name == "openrouter"
        assert client.model == "nous-hermes-2-mixtral-8x7b"

    def test_base_url_override(self):
        client = create_client_from_config(
            {
                "ai_provider": "openai",
                "ai_base_url": "http://custom-proxy:8080/v1",
            }
        )
        assert client.base_url == "http://custom-proxy:8080/v1"

    def test_backward_compat_lmstudio_keys(self):
        client = create_client_from_config(
            {
                "lmstudio_base_url": "http://localhost:9999",
                "lmstudio_model": "my-custom-model",
            }
        )
        assert isinstance(client, LMStudioClient)
        assert client.model == "my-custom-model"


# ---------------------------------------------------------------------------
# Supported providers catalogue
# ---------------------------------------------------------------------------


class TestSupportedProviders:
    def test_all_required_providers_present(self):
        required = {
            "lmstudio",
            "openai",
            "openrouter",
            "anthropic",
            "ollama",
            "opencode",
            "nous",
        }
        assert required.issubset(set(SUPPORTED_PROVIDERS.keys()))

    def test_local_providers_need_no_key(self):
        assert SUPPORTED_PROVIDERS["lmstudio"].needs_api_key is False
        assert SUPPORTED_PROVIDERS["ollama"].needs_api_key is False

    def test_cloud_providers_need_key(self):
        for name in ("openai", "openrouter", "anthropic", "nous", "opencode"):
            assert (
                SUPPORTED_PROVIDERS[name].needs_api_key is True
            ), f"{name} should need API key"
