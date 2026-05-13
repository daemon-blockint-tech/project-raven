"""
Anthropic Claude provider adapter using the native `anthropic` SDK.

Install: pip install anthropic
Docs:    https://docs.anthropic.com/en/api/messages
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from raven.ai.base import AIMessage, AIResponse, BaseAIClient


class AnthropicClient(BaseAIClient):
    """Adapter for Anthropic's Messages API via the native `anthropic` SDK.

    Gracefully degrades: if `anthropic` is not installed, is_available()
    returns False and chat() raises ImportError with an install hint.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.provider_name = "anthropic"
        if not self.model:
            self.model = "claude-3-5-sonnet-20241022"
        self._client: Any = None
        self._import_error: Optional[str] = None
        self._try_init()

    def _try_init(self) -> None:
        try:
            import anthropic  # type: ignore
            self._client = anthropic.Anthropic(
                api_key=self.api_key or None,
                timeout=float(self.timeout),
            )
        except ImportError:
            self._import_error = (
                "anthropic package not installed. Run: pip install anthropic"
            )

    # ------------------------------------------------------------------
    # chat()
    # ------------------------------------------------------------------

    def chat(
        self,
        messages: List[AIMessage],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AIResponse:
        if self._import_error:
            raise ImportError(self._import_error)

        messages = self._build_messages(messages)
        system_parts = [m.content for m in messages if m.role == "system"]
        user_messages = [
            {"role": m.role, "content": m.content}
            for m in messages if m.role != "system"
        ]
        system_prompt = "\n\n".join(system_parts) if system_parts else None

        kwargs_msg: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
            "messages": user_messages,
        }
        if system_prompt:
            kwargs_msg["system"] = system_prompt
        t = temperature if temperature is not None else self.temperature
        if t is not None:
            kwargs_msg["temperature"] = t

        try:
            response = self._client.messages.create(**kwargs_msg)
        except Exception as e:
            raise RuntimeError(f"Anthropic API error: {e}") from e

        content = ""
        reasoning = None
        for block in response.content:
            if block.type == "text":
                content += block.text
            elif block.type == "thinking":
                reasoning = block.thinking

        return AIResponse(
            content=content,
            model=response.model,
            reasoning=reasoning,
            finish_reason=response.stop_reason or "stop",
            prompt_tokens=response.usage.input_tokens,
            completion_tokens=response.usage.output_tokens,
            provider="anthropic",
        )

    def is_available(self) -> bool:
        if self._import_error:
            return False
        if not self.api_key:
            return False
        try:
            self._client.models.list(limit=1)
            return True
        except Exception:
            return False
