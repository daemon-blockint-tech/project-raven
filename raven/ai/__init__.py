"""AI client layer — multi-provider LLM inference for Project Raven."""

from .base import (
    AIMessage,
    AIResponse,
    BaseAIClient,
    SUPPORTED_PROVIDERS,
    parse_provider_model,
)
from .factory import create_client_from_config
from .registry import ProviderRegistry, ProviderConfig
from .lmstudio_client import LMStudioClient  # backward compat
from .model_orchestrator import ModelOrchestrator, ModelRole

__all__ = [
    "AIMessage",
    "AIResponse",
    "BaseAIClient",
    "SUPPORTED_PROVIDERS",
    "parse_provider_model",
    "create_client_from_config",
    "ProviderRegistry",
    "ProviderConfig",
    "LMStudioClient",
    "ModelOrchestrator",
    "ModelRole",
]
