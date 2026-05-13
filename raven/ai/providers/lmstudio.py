"""
LM Studio provider — native v1 REST API (LM Studio >= 0.4.0).

Primary:  POST /api/v1/chat        — stateful chat, MCP, load-streaming
Models:   GET/POST /api/v1/models  — list, load, unload
Fallback: POST /v1/chat/completions — OpenAI-compat (tool calls)
"""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional

import json
import requests

from raven.ai.base import AIMessage, AIResponse, BaseAIClient


class LMStudioClient(BaseAIClient):
    """Client for LM Studio's native v1 REST API (>= 0.4.0).

    Falls back to /v1/chat/completions when tool calls are needed.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.provider_name = "lmstudio"
        base = config.get("lmstudio_base_url", config.get("ai_base_url", "http://localhost:1234"))
        self.base_url = base.rstrip("/")
        if not self.api_key:
            self.api_key = config.get("lmstudio_api_key", "")
        if not self.model:
            self.model = config.get("lmstudio_model", "")
        self._v1_chat_url       = f"{self.base_url}/api/v1/chat"
        self._v1_models_url     = f"{self.base_url}/api/v1/models"
        self._v1_load_url       = f"{self.base_url}/api/v1/models/load"
        self._v1_unload_url     = f"{self.base_url}/api/v1/models/unload"
        self._compat_chat_url   = f"{self.base_url}/v1/chat/completions"
        self._compat_models_url = f"{self.base_url}/v1/models"

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _post(self, url: str, payload: Dict[str, Any]) -> requests.Response:
        try:
            resp = requests.post(url, json=payload, timeout=self.timeout, headers=self._headers())
            resp.raise_for_status()
            return resp
        except requests.exceptions.ConnectionError:
            raise RuntimeError(
                f"Cannot connect to LM Studio at {self.base_url}. "
                "Ensure LM Studio is running and the server is started."
            )
        except requests.exceptions.Timeout:
            raise RuntimeError(
                f"LM Studio request timed out after {self.timeout}s."
            )
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "?"
            if status == 401:
                raise RuntimeError(
                    "LM Studio returned 401 Unauthorized. Check LMSTUDIO_API_KEY."
                )
            raise RuntimeError(f"LM Studio HTTP {status}: {e}")

    # ------------------------------------------------------------------
    # chat()
    # ------------------------------------------------------------------

    def chat(
        self,
        messages: List[AIMessage],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        chat_id: Optional[str] = None,
        context_length: Optional[int] = None,
        **kwargs: Any,
    ) -> AIResponse:
        if tools:
            return self._compat_chat(messages, tools=tools,
                                     temperature=temperature, max_tokens=max_tokens)

        payload: Dict[str, Any] = {
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature if temperature is not None else self.temperature,
            "maxTokens": max_tokens if max_tokens is not None else self.max_tokens,
            "stream": False,
        }
        if self.model:
            payload["model"] = self.model
        if chat_id:
            payload["chatId"] = chat_id
        if context_length:
            payload["contextLength"] = context_length

        data = self._post(self._v1_chat_url, payload).json()
        content = data.get("content") or data.get("choices", [{}])[0].get("message", {}).get("content", "")
        stats = data.get("stats", {})
        return AIResponse(
            content=content,
            model=data.get("model", self.model),
            reasoning=data.get("reasoning_content"),
            finish_reason=data.get("stopReason", "stop"),
            prompt_tokens=stats.get("promptTokensCount", 0),
            completion_tokens=stats.get("generatedTokensCount", 0),
            provider="lmstudio",
            chat_id=data.get("chatId"),
        )

    def _compat_chat(
        self,
        messages: List[AIMessage],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> AIResponse:
        payload: Dict[str, Any] = {
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
            "stream": False,
        }
        if self.model:
            payload["model"] = self.model
        if tools:
            payload["tools"] = tools

        data = self._post(self._compat_chat_url, payload).json()
        choice = data["choices"][0]
        message = choice["message"]
        usage = data.get("usage", {})
        return AIResponse(
            content=message.get("content") or "",
            model=data.get("model", self.model),
            reasoning=message.get("reasoning_content"),
            tool_calls=message.get("tool_calls"),
            finish_reason=choice.get("finish_reason", "stop"),
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            provider="lmstudio",
        )

    def chat_stream(
        self,
        messages: List[AIMessage],
        temperature: Optional[float] = None,
    ) -> Iterator[str]:
        payload: Dict[str, Any] = {
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature if temperature is not None else self.temperature,
            "maxTokens": self.max_tokens,
            "stream": True,
        }
        if self.model:
            payload["model"] = self.model

        with requests.post(
            self._v1_chat_url, json=payload, timeout=self.timeout,
            headers=self._headers(), stream=True,
        ) as resp:
            resp.raise_for_status()
            for raw_line in resp.iter_lines():
                if not raw_line:
                    continue
                line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else raw_line
                if not line.startswith("data: "):
                    continue
                data_str = line[6:]
                if data_str.strip() == "[DONE]":
                    break
                try:
                    chunk = json.loads(data_str)
                    if chunk.get("type") == "contentChunk":
                        yield chunk.get("content", "")
                    elif "choices" in chunk:
                        token = chunk["choices"][0].get("delta", {}).get("content", "")
                        if token:
                            yield token
                except (json.JSONDecodeError, KeyError):
                    continue

    # ------------------------------------------------------------------
    # Model management
    # ------------------------------------------------------------------

    def load_model(self, model_id: str, context_length: Optional[int] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"model": model_id}
        if context_length:
            payload["contextLength"] = context_length
        return self._post(self._v1_load_url, payload).json()

    def unload_model(self, model_id: str) -> Dict[str, Any]:
        return self._post(self._v1_unload_url, {"model": model_id}).json()

    def list_loaded_models(self) -> List[str]:
        for url in (self._v1_models_url, self._compat_models_url):
            try:
                resp = requests.get(url, timeout=5, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
                items = data.get("data", data) if isinstance(data, dict) else data
                return [m["id"] for m in items if isinstance(m, dict) and "id" in m]
            except Exception:
                continue
        return []

    def is_available(self) -> bool:
        for url in (self._v1_models_url, self._compat_models_url):
            try:
                requests.get(url, timeout=3, headers=self._headers())
                return True
            except Exception:
                continue
        return False
