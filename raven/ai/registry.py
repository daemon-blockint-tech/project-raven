"""
ProviderRegistry — runtime-mutable AI provider state with named profiles.

Pattern: Hermes Agent's `hermes model` + `hermes provider save/load`
         applied to Raven's server-side singleton.

Profiles are persisted to ~/.raven/profiles/<name>.json (mode 600).
"""

from __future__ import annotations

import json
import logging
import re
import stat
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

from raven.ai.base import BaseAIClient, SUPPORTED_PROVIDERS
from raven.ai.factory import create_client_from_config


_PROFILES_DIR = Path.home() / ".raven" / "profiles"


@dataclass
class ProviderConfig:
    """Serialisable snapshot of the active provider configuration."""

    provider: str = "lmstudio"
    model: str = ""
    api_key: str = ""
    base_url: str = ""
    temperature: float = 0.2
    max_tokens: int = 4096
    timeout: int = 120
    system_prompt: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_client_config(self) -> Dict[str, Any]:
        return {
            "ai_provider": self.provider,
            "ai_model": self.model,
            "ai_api_key": self.api_key,
            "ai_base_url": self.base_url,
            "ai_temperature": self.temperature,
            "ai_max_tokens": self.max_tokens,
            "ai_timeout": self.timeout,
            "ai_system_prompt": self.system_prompt,
            **self.extra,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ProviderConfig":
        known = {f for f in cls.__dataclass_fields__}
        extra = {k: v for k, v in d.items() if k not in known}
        base = {k: v for k, v in d.items() if k in known and k != "extra"}
        return cls(**base, extra=extra)


class ProviderRegistry:
    """Thread-safe singleton that manages the active AI client.

    Usage:
        registry = ProviderRegistry.get_instance()
        registry.switch("openrouter", model="nous-hermes-2-mixtral-8x7b", api_key="sk-or-...")
        client = registry.get_client()

        registry.save_profile("work")
        registry.load_profile("work")
    """

    _instance: Optional["ProviderRegistry"] = None
    _lock: threading.Lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "ProviderRegistry":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def __init__(self) -> None:
        self._rw_lock = threading.RLock()
        self._config = ProviderConfig()
        self._client: Optional[BaseAIClient] = None
        _PROFILES_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public: switch provider/model at runtime
    # ------------------------------------------------------------------

    def switch(
        self,
        provider: str,
        model: str = "",
        api_key: str = "",
        base_url: str = "",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        timeout: Optional[int] = None,
        **extra: Any,
    ) -> BaseAIClient:
        """Hot-swap the active provider. Returns the new client."""
        provider = provider.lower().strip()
        if provider not in SUPPORTED_PROVIDERS:
            raise ValueError(
                f"Unknown provider: {provider!r}. "
                f"Supported: {', '.join(SUPPORTED_PROVIDERS)}"
            )
        with self._rw_lock:
            self._config = ProviderConfig(
                provider=provider,
                model=model or self._config.model,
                api_key=api_key or self._config.api_key,
                base_url=base_url or self._config.base_url,
                temperature=temperature
                if temperature is not None
                else self._config.temperature,
                max_tokens=max_tokens
                if max_tokens is not None
                else self._config.max_tokens,
                timeout=timeout if timeout is not None else self._config.timeout,
                extra=extra or self._config.extra,
            )
            self._client = create_client_from_config(self._config.to_client_config())
            return self._client

    def set_model(self, model: str) -> BaseAIClient:
        """Change only the model, keeping current provider and key."""
        with self._rw_lock:
            self._config.model = model
            self._client = create_client_from_config(self._config.to_client_config())
            return self._client

    def get_client(self) -> BaseAIClient:
        """Return the current client, creating it lazily if needed."""
        with self._rw_lock:
            if self._client is None:
                self._client = create_client_from_config(
                    self._config.to_client_config()
                )
            return self._client

    def initialise_from_config(self, config: Dict[str, Any]) -> BaseAIClient:
        """Bootstrap registry from application startup config (reads .env values)."""
        with self._rw_lock:
            self._config = ProviderConfig(
                provider=config.get("ai_provider", "lmstudio"),
                model=config.get("ai_model", config.get("lmstudio_model", "")),
                api_key=config.get("ai_api_key", config.get("lmstudio_api_key", "")),
                base_url=config.get("ai_base_url", config.get("lmstudio_base_url", "")),
                temperature=float(
                    config.get(
                        "ai_temperature", config.get("lmstudio_temperature", 0.2)
                    )
                ),
                max_tokens=int(
                    config.get("ai_max_tokens", config.get("lmstudio_max_tokens", 4096))
                ),
                timeout=int(
                    config.get("ai_timeout", config.get("lmstudio_timeout", 120))
                ),
            )
            # Auto-load system prompt from file if configured
            prompt_path = config.get("ai_system_prompt_path", "RAVEN_SYSTEM_PROMPT.md")
            if prompt_path:
                self.load_system_prompt_from_file(prompt_path, silent=True)
            self._client = create_client_from_config(self._config.to_client_config())
            return self._client

    # ------------------------------------------------------------------
    # Profiles
    # ------------------------------------------------------------------

    def save_profile(self, name: str) -> Path:
        """Persist current config as a named profile."""
        _PROFILES_DIR.mkdir(parents=True, exist_ok=True)
        path = _PROFILES_DIR / f"{name}.json"
        data = asdict(self._config)
        path.write_text(json.dumps(data, indent=2))
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return path

    def load_profile(self, name: str) -> BaseAIClient:
        """Load a named profile and hot-swap the client."""
        path = _PROFILES_DIR / f"{name}.json"
        if not path.exists():
            raise FileNotFoundError(f"Profile not found: {name!r} ({path})")
        data = json.loads(path.read_text())
        cfg = ProviderConfig.from_dict(data)
        with self._rw_lock:
            self._config = cfg
            self._client = create_client_from_config(cfg.to_client_config())
            return self._client

    def list_profiles(self) -> List[str]:
        """Return names of all saved profiles."""
        if not _PROFILES_DIR.exists():
            return []
        return sorted(p.stem for p in _PROFILES_DIR.glob("*.json"))

    def delete_profile(self, name: str) -> bool:
        path = _PROFILES_DIR / f"{name}.json"
        if path.exists():
            path.unlink()
            return True
        return False

    # ------------------------------------------------------------------
    # System prompt management
    # ------------------------------------------------------------------

    def set_system_prompt(self, prompt: str) -> None:
        """Set the system prompt and propagate to the active client."""
        with self._rw_lock:
            self._config.system_prompt = prompt
            if self._client is not None:
                self._client.system_prompt = prompt

    def get_system_prompt(self) -> str:
        """Return the currently active system prompt text."""
        return self._config.system_prompt

    def load_system_prompt_from_file(self, path: str, silent: bool = False) -> str:
        """Load system prompt from a Markdown or text file.

        For .md files the fenced code block after the '## Prompt' heading is
        extracted if present; otherwise the full file content is used.
        """
        p = Path(path)
        if not p.exists():
            if not silent:
                raise FileNotFoundError(f"System prompt file not found: {path!r}")
            return ""
        raw = p.read_text(encoding="utf-8")
        prompt = self._extract_prompt_from_md(raw) if p.suffix == ".md" else raw
        prompt = prompt.strip()
        self.set_system_prompt(prompt)
        log.info("Loaded system prompt from %s (%d chars)", path, len(prompt))
        return prompt

    @staticmethod
    def _extract_prompt_from_md(content: str) -> str:
        """Extract text from the first fenced code block (``` ... ```) in a .md file.
        Falls back to the full file content if no fence is found."""
        match = re.search(r"```[^\n]*\n(.*?)```", content, re.DOTALL)
        return match.group(1) if match else content

    # ------------------------------------------------------------------
    # Status / introspection
    # ------------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        cfg = self._config
        info = SUPPORTED_PROVIDERS.get(cfg.provider)
        prompt = cfg.system_prompt
        return {
            "provider": cfg.provider,
            "model": cfg.model or "(auto)",
            "base_url": cfg.base_url or (info.default_base_url if info else ""),
            "has_api_key": bool(cfg.api_key),
            "description": info.description if info else "",
            "profiles": self.list_profiles(),
            "available": self._client.is_available() if self._client else False,
            "system_prompt_set": bool(prompt),
            "system_prompt_len": len(prompt),
        }
