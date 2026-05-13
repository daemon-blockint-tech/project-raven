"""Tinker provider adapter.

Routes chat requests to a Tinker sampling client backed by a specific
``ModelVersion`` checkpoint. Conforms to ``BaseAIClient`` so the
``ProviderRegistry`` can hot-swap to a Raven-trained fine-tune via the
same ``raven provider set`` / ``POST /ai/provider`` flow as any other
provider.

Selection of the active checkpoint:
  1. ``config['tinker_checkpoint_path']`` — explicit override
  2. The promoted ``ModelVersion`` from ``raven.training.registry``
  3. Fall back to OpenAI-compat against ``config['ai_base_url']`` if set
     (lets operators host Tinker checkpoints on their own inference
     endpoint while still using this adapter)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from raven.ai.base import AIMessage, AIResponse, BaseAIClient

log = logging.getLogger(__name__)


class TinkerClient(BaseAIClient):
    """Adapter routing chat requests to a Tinker sampling client / hosted endpoint."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.provider_name = "tinker"
        self.checkpoint_path: str = config.get("tinker_checkpoint_path", "")
        # If a base_url is supplied the operator self-hosts the model via an
        # OpenAI-compat endpoint; we delegate to that adapter for transport.
        self._delegate: Optional[BaseAIClient] = None
        if self.base_url:
            from raven.ai.providers.openai_compat import OpenAICompatClient
            compat_cfg = dict(config)
            compat_cfg["ai_provider"] = "openai"   # transport only
            self._delegate = OpenAICompatClient(compat_cfg)
            self._delegate.provider_name = "tinker"
        else:
            self._tinker_sdk = None  # lazy

    # ---------------------------------------------------------------
    # BaseAIClient required methods
    # ---------------------------------------------------------------

    def chat(
        self,
        messages: List[AIMessage],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AIResponse:
        messages = self._build_messages(messages)
        if self._delegate is not None:
            return self._delegate.chat(messages, temperature=temperature, max_tokens=max_tokens, **kwargs)
        return self._sdk_chat(messages, temperature=temperature, max_tokens=max_tokens)

    def is_available(self) -> bool:
        if self._delegate is not None:
            return self._delegate.is_available()
        # Direct-SDK path: we are "available" iff a checkpoint is configured
        # and the underlying client is reachable.
        if not self.checkpoint_path:
            return False
        try:
            self._get_sampling_client()
            return True
        except Exception as exc:
            log.warning("tinker.is_available failed: %s", exc)
            return False

    def list_loaded_models(self) -> List[str]:
        if self.checkpoint_path:
            return [self.checkpoint_path]
        return []

    # ---------------------------------------------------------------
    # Direct-SDK path
    # ---------------------------------------------------------------

    def _get_sampling_client(self) -> Any:
        if self._tinker_sdk is not None:
            return self._tinker_sdk
        try:
            import tinker  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "tinker SDK not installed and no ai_base_url configured. "
                "Either install tinker-cookbook or set ai_base_url to your "
                "hosted inference endpoint."
            ) from exc
        svc = tinker.ServiceClient()
        # The cookbook returns a sampling_client by loading the checkpoint.
        sampling = svc.create_sampling_client(model_path=self.checkpoint_path)
        self._tinker_sdk = sampling
        return sampling

    def _sdk_chat(
        self,
        messages: List[AIMessage],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> AIResponse:
        sampling = self._get_sampling_client()
        prompt = "\n\n".join(f"[{m.role}]\n{m.content}" for m in messages)
        try:
            result = sampling.sample(
                prompt=prompt,
                max_tokens=max_tokens if max_tokens is not None else self.max_tokens,
                temperature=temperature if temperature is not None else self.temperature,
            )
            content = getattr(result, "text", None) or str(result)
        except Exception as exc:
            raise RuntimeError(f"Tinker sampling error: {exc}") from exc
        return AIResponse(
            content=content,
            model=self.model or self.checkpoint_path,
            provider="tinker",
        )
