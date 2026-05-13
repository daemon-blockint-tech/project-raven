"""
Backward-compatibility shim — LMStudioClient has moved to raven.ai.providers.lmstudio.

Import from here still works:
    from raven.ai.lmstudio_client import LMStudioClient, AIMessage, AIResponse
"""

from raven.ai.base import AIMessage, AIResponse  # noqa: F401  (re-export)
from raven.ai.providers.lmstudio import LMStudioClient  # noqa: F401  (re-export)

__all__ = ["LMStudioClient", "AIMessage", "AIResponse"]
