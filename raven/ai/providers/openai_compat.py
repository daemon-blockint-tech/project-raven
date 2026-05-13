"""
OpenAI-compatible provider adapter.

Covers all providers that speak the OpenAI /v1/chat/completions API:
  - openai    (https://api.openai.com/v1)
  - openrouter (https://openrouter.ai/api/v1)
  - ollama    (http://localhost:11434/v1)
  - opencode  (https://api.opencode.ai/v1)
  - nous      (https://portal.nousresearch.com/api/v1)
  - any custom base_url

Switch between them purely via config — no code change needed.
"""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional

import json
import requests

from raven.ai.base import AIMessage, AIResponse, BaseAIClient, SUPPORTED_PROVIDERS


_PROVIDER_DEFAULTS: Dict[str, str] = {
    p.name: p.default_base_url
    for p in SUPPORTED_PROVIDERS.values()
    if p.default_base_url and p.name != "lmstudio"
}


class OpenAICompatClient(BaseAIClient):
    """Single adapter for all OpenAI-compatible REST endpoints."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        provider = self.provider_name

        if not self.base_url:
            self.base_url = _PROVIDER_DEFAULTS.get(provider, "https://api.openai.com/v1")
        self.base_url = self.base_url.rstrip("/")

        self._chat_url   = f"{self.base_url}/chat/completions"
        self._models_url = f"{self.base_url}/models"

        self._http_referer    = config.get("openrouter_http_referer", "https://raven.local")
        self._app_title       = config.get("openrouter_title", "Project Raven")

    # ------------------------------------------------------------------
    # Auth headers
    # ------------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        if self.provider_name == "openrouter":
            h["HTTP-Referer"] = self._http_referer
            h["X-Title"] = self._app_title
        return h

    # ------------------------------------------------------------------
    # chat()
    # ------------------------------------------------------------------

    def chat(
        self,
        messages: List[AIMessage],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> AIResponse:
        messages = self._build_messages(messages)
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

        if self.provider_name == "openrouter":
            sort = kwargs.get("openrouter_sort", "")
            zdr  = kwargs.get("openrouter_zdr", False)
            if sort or zdr:
                provider_opts: Dict[str, Any] = {}
                if sort:
                    provider_opts["sort"] = sort
                if zdr:
                    provider_opts["data_collection"] = "deny"
                payload["provider"] = provider_opts

        try:
            resp = requests.post(
                self._chat_url, json=payload,
                timeout=self.timeout, headers=self._headers(),
            )
            resp.raise_for_status()
        except requests.exceptions.ConnectionError:
            raise RuntimeError(
                f"Cannot connect to {self.provider_name} at {self.base_url}."
            )
        except requests.exceptions.Timeout:
            raise RuntimeError(
                f"{self.provider_name} request timed out after {self.timeout}s."
            )
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "?"
            if status == 401:
                raise RuntimeError(
                    f"{self.provider_name} returned 401 Unauthorized. Check AI_API_KEY."
                )
            raise RuntimeError(f"{self.provider_name} HTTP {status}: {e}")

        data = resp.json()
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
            provider=self.provider_name,
        )

    def chat_stream(
        self,
        messages: List[AIMessage],
        temperature: Optional[float] = None,
    ) -> Iterator[str]:
        payload: Dict[str, Any] = {
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": self.max_tokens,
            "stream": True,
        }
        if self.model:
            payload["model"] = self.model

        with requests.post(
            self._chat_url, json=payload,
            timeout=self.timeout, headers=self._headers(), stream=True,
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
                    token = chunk["choices"][0].get("delta", {}).get("content", "")
                    if token:
                        yield token
                except (json.JSONDecodeError, KeyError):
                    continue

    def is_available(self) -> bool:
        try:
            requests.get(self._models_url, timeout=4, headers=self._headers())
            return True
        except Exception:
            return False

    def list_loaded_models(self) -> List[str]:
        try:
            resp = requests.get(self._models_url, timeout=5, headers=self._headers())
            resp.raise_for_status()
            data = resp.json()
            items = data.get("data", [])
            return [m["id"] for m in items if isinstance(m, dict) and "id" in m]
        except Exception:
            return []
