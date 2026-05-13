"""
Abstract base class for all AI provider clients in Project Raven.

Pattern inspired by Hermes Agent (NousResearch) and Claude Code:
  - provider:model syntax   e.g. "openrouter:nous-hermes-2-mixtral-8x7b"
  - runtime hot-swap via ProviderRegistry without server restart
  - unified interface regardless of underlying provider SDK
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional


# ---------------------------------------------------------------------------
# Shared message / response types (provider-agnostic)
# ---------------------------------------------------------------------------

@dataclass
class AIMessage:
    role: str                          # "system" | "user" | "assistant"
    content: str
    reasoning: Optional[str] = None   # populated for reasoning models


@dataclass
class AIResponse:
    content: str
    model: str
    reasoning: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    finish_reason: str = "stop"
    prompt_tokens: int = 0
    completion_tokens: int = 0
    provider: str = ""
    chat_id: Optional[str] = None     # LM Studio stateful chat session ID


# ---------------------------------------------------------------------------
# Provider catalogue
# ---------------------------------------------------------------------------

@dataclass
class ProviderInfo:
    name: str
    default_base_url: str             # empty = SDK-managed (e.g. Anthropic)
    needs_api_key: bool
    description: str
    example_models: List[str] = field(default_factory=list)


SUPPORTED_PROVIDERS: Dict[str, ProviderInfo] = {
    "lmstudio": ProviderInfo(
        name="lmstudio",
        default_base_url="http://localhost:1234",
        needs_api_key=False,
        description="Local LM Studio server (OpenAI-compat, no key required)",
        example_models=["ibm/granite-4-micro", "nvidia/nemotron-3-nano-4b"],
    ),
    "openai": ProviderInfo(
        name="openai",
        default_base_url="https://api.openai.com/v1",
        needs_api_key=True,
        description="OpenAI API",
        example_models=["gpt-4o", "gpt-4o-mini", "o3-mini"],
    ),
    "openrouter": ProviderInfo(
        name="openrouter",
        default_base_url="https://openrouter.ai/api/v1",
        needs_api_key=True,
        description="OpenRouter — 300+ models via single API key",
        example_models=[
            "nous/hermes-2-mixtral-8x7b",
            "anthropic/claude-3-5-sonnet",
            "openai/gpt-4o",
            "google/gemini-2.5-pro",
            "nvidia/nemotron-4-340b-instruct",
        ],
    ),
    "anthropic": ProviderInfo(
        name="anthropic",
        default_base_url="",
        needs_api_key=True,
        description="Anthropic Claude (native SDK)",
        example_models=["claude-opus-4-5", "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022"],
    ),
    "ollama": ProviderInfo(
        name="ollama",
        default_base_url="http://localhost:11434/v1",
        needs_api_key=False,
        description="Ollama local models (OpenAI-compat endpoint)",
        example_models=["llama3.2", "mistral", "deepseek-r1"],
    ),
    "opencode": ProviderInfo(
        name="opencode",
        default_base_url="https://api.opencode.ai/v1",
        needs_api_key=True,
        description="OpenCode AI",
        example_models=[],
    ),
    "nous": ProviderInfo(
        name="nous",
        default_base_url="https://portal.nousresearch.com/api/v1",
        needs_api_key=True,
        description="Nous Research Portal (Hermes models)",
        example_models=["nous-hermes-2-mixtral-8x7b", "hermes-3-llama-3.1-405b"],
    ),
}


def parse_provider_model(spec: str) -> tuple[str, str]:
    """Parse 'provider:model' or plain 'model' spec.

    Examples:
        'openrouter:nous-hermes-2-mixtral-8x7b' → ('openrouter', 'nous-hermes-2-mixtral-8x7b')
        'gpt-4o'                                → ('', 'gpt-4o')
        'openrouter:'                           → ('openrouter', '')
    """
    if ":" in spec:
        provider, _, model = spec.partition(":")
        return provider.strip(), model.strip()
    return "", spec.strip()


# ---------------------------------------------------------------------------
# Abstract base client
# ---------------------------------------------------------------------------

class BaseAIClient(ABC):
    """Common interface for all AI provider adapters.

    Concrete implementations live in raven/ai/providers/.
    Task-specific helpers (analyze_code, generate_hypothesis, etc.) have
    default implementations here. Subclasses only need to implement
    chat() and is_available().
    """

    def __init__(self, config: Dict[str, Any]):
        self.provider_name: str = config.get("ai_provider", "lmstudio")
        self.model: str = config.get("ai_model", config.get("lmstudio_model", ""))
        self.api_key: str = config.get("ai_api_key", config.get("lmstudio_api_key", ""))
        self.base_url: str = config.get("ai_base_url", "")
        self.timeout: int = int(config.get("ai_timeout", config.get("lmstudio_timeout", 120)))
        self.temperature: float = float(
            config.get("ai_temperature", config.get("lmstudio_temperature", 0.2))
        )
        self.max_tokens: int = int(
            config.get("ai_max_tokens", config.get("lmstudio_max_tokens", 4096))
        )

    # ------------------------------------------------------------------
    # Abstract — must implement in subclass
    # ------------------------------------------------------------------

    @abstractmethod
    def chat(
        self,
        messages: List[AIMessage],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AIResponse:
        """Send a chat request and return a single response."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the provider/server is reachable."""

    # ------------------------------------------------------------------
    # Optional override — streaming (default: non-streaming fallback)
    # ------------------------------------------------------------------

    def chat_stream(
        self,
        messages: List[AIMessage],
        temperature: Optional[float] = None,
    ) -> Iterator[str]:
        response = self.chat(messages, temperature=temperature)
        yield response.content

    # ------------------------------------------------------------------
    # Concrete task helpers — shared across all providers
    # ------------------------------------------------------------------

    def analyze_code(self, code: str, context: str = "") -> AIResponse:
        system = (
            "You are a security researcher analyzing code for vulnerabilities. "
            "Focus on memory safety, injection flaws, insecure deserialization, "
            "authentication bypass, and logic errors. Be concise and precise."
        )
        user = (
            f"{context}\n\nAnalyze this code:\n```\n{code}\n```"
            if context
            else f"Analyze this code for security vulnerabilities:\n```\n{code}\n```"
        )
        return self.chat([
            AIMessage(role="system", content=system),
            AIMessage(role="user", content=user),
        ])

    def generate_hypothesis(self, indicators: Dict[str, Any]) -> AIResponse:
        system = (
            "You are a threat intelligence analyst. Given security indicators, "
            "generate a concise threat hunting hypothesis with: threat type, "
            "attack vector, confidence (0-1), and 3 investigation steps. "
            "Respond in JSON."
        )
        user = f"Security indicators:\n{json.dumps(indicators, indent=2)}"
        return self.chat([
            AIMessage(role="system", content=system),
            AIMessage(role="user", content=user),
        ], temperature=0.1)

    def validate_vulnerability(self, vuln_data: Dict[str, Any]) -> AIResponse:
        system = (
            "You are a vulnerability researcher. Given a potential vulnerability, "
            "assess whether it is real or a false positive. "
            "Respond with: verdict (real/false_positive/needs_review), "
            "confidence (0-1), reasoning. Respond in JSON."
        )
        user = f"Potential vulnerability:\n{json.dumps(vuln_data, indent=2)}"
        return self.chat([
            AIMessage(role="system", content=system),
            AIMessage(role="user", content=user),
        ], temperature=0.0)

    def explain_cve(self, cve_id: str, description: str) -> AIResponse:
        system = (
            "You are a security expert. Explain CVEs concisely: "
            "root cause, affected versions, exploitation difficulty, mitigation."
        )
        user = f"CVE: {cve_id}\nDescription: {description}\n\nProvide a technical explanation."
        return self.chat([
            AIMessage(role="system", content=system),
            AIMessage(role="user", content=user),
        ])

    # ------------------------------------------------------------------
    # LM Studio model management stubs (no-op for cloud providers)
    # ------------------------------------------------------------------

    def list_loaded_models(self) -> List[str]:
        return [self.model] if self.model else []

    def load_model(self, model_id: str, context_length: Optional[int] = None) -> Dict[str, Any]:
        return {"status": "not_supported", "provider": self.provider_name}

    def unload_model(self, model_id: str) -> Dict[str, Any]:
        return {"status": "not_supported", "provider": self.provider_name}

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} provider={self.provider_name!r} "
            f"model={self.model!r}>"
        )
