"""
AI client factory.

create_client_from_config(config) → BaseAIClient

Provider is selected via config["ai_provider"]. The factory is also the
canonical place to resolve "provider:model" shorthand strings.
"""

from __future__ import annotations

from typing import Any, Dict

from raven.ai.base import BaseAIClient, SUPPORTED_PROVIDERS, parse_provider_model


def create_client_from_config(config: Dict[str, Any]) -> BaseAIClient:
    """Instantiate the right provider adapter from a config dict.

    config keys used:
        ai_provider  — one of SUPPORTED_PROVIDERS keys (default: lmstudio)
        ai_model     — model name; may be "provider:model" shorthand
        ai_api_key   — API key for cloud providers
        ai_base_url  — optional override for the provider base URL

    All remaining config keys are forwarded to the adapter constructor
    for backward-compatibility (e.g. lmstudio_base_url, lmstudio_model).
    """
    cfg = dict(config)

    ai_model = cfg.get("ai_model", "")
    if ai_model and ":" in ai_model:
        inferred_provider, bare_model = parse_provider_model(ai_model)
        if inferred_provider:
            cfg.setdefault("ai_provider", inferred_provider)
        cfg["ai_model"] = bare_model

    provider = cfg.get("ai_provider", "lmstudio").lower().strip()
    cfg["ai_provider"] = provider

    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(
            f"Unknown AI provider: {provider!r}. "
            f"Supported: {', '.join(SUPPORTED_PROVIDERS)}"
        )

    if provider == "lmstudio":
        from raven.ai.providers.lmstudio import LMStudioClient
        return LMStudioClient(cfg)

    if provider == "anthropic":
        from raven.ai.providers.anthropic_provider import AnthropicClient
        return AnthropicClient(cfg)

    if provider == "tinker":
        from raven.ai.providers.tinker_provider import TinkerClient
        return TinkerClient(cfg)

    from raven.ai.providers.openai_compat import OpenAICompatClient
    return OpenAICompatClient(cfg)
