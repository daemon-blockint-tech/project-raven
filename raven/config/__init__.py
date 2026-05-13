"""Configuration management for Project Raven."""

from __future__ import annotations

import os
from typing import List, Literal, Optional

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_SECRET = "dev-secret-key-change-in-production"


class Settings(BaseSettings):
    """Application settings.

    Loaded from environment variables (uppercase) or `.env` file.
    Refuses to start in `prod` environment when critical defaults are unchanged.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -----------------------------------------------------------------
    # Deployment context
    # -----------------------------------------------------------------
    environment: Literal["dev", "staging", "prod"] = Field(
        default="dev",
        validation_alias=AliasChoices("RAVEN_ENVIRONMENT", "ENVIRONMENT", "environment"),
    )

    # -----------------------------------------------------------------
    # API
    # -----------------------------------------------------------------
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug: bool = False

    # -----------------------------------------------------------------
    # Database / cache
    # -----------------------------------------------------------------
    database_url: str = "postgresql://user:password@localhost/raven"
    redis_url: str = "redis://localhost:6379/0"

    # -----------------------------------------------------------------
    # Security & JWT
    # -----------------------------------------------------------------
    secret_key: str = os.getenv("SECRET_KEY", _DEFAULT_SECRET)
    jwt_algorithm: str = "HS256"
    jwt_access_ttl_minutes: int = 15
    jwt_refresh_ttl_days: int = 7
    jwt_issuer: str = "raven"
    jwt_audience: str = "raven-api"

    # Bootstrap admin (only used on first start if no users exist)
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = ""  # empty → no auto-create

    # -----------------------------------------------------------------
    # CORS — explicit allowlist (no wildcard in prod)
    # -----------------------------------------------------------------
    cors_origins: List[str] = ["http://localhost:3000"]

    # -----------------------------------------------------------------
    # Scan jails (closes F2: filesystem disclosure)
    # -----------------------------------------------------------------
    scan_root: str = "/var/lib/raven/repos"  # /hunt/code, /hunt/variant must stay under this

    # -----------------------------------------------------------------
    # AI provider allowlist (closes F1: base_url override exfiltration)
    # -----------------------------------------------------------------
    ai_allowed_base_urls: List[str] = []  # empty → only built-in provider defaults allowed

    # -----------------------------------------------------------------
    # Rate limiting
    # -----------------------------------------------------------------
    rate_limit_per_minute: int = 60
    rate_limit_auth_per_minute: int = 5  # login/refresh stricter

    # -----------------------------------------------------------------
    # Approval gate / YOLO (Hermes Agent-inspired)
    # -----------------------------------------------------------------
    approval_mode: Literal["manual", "smart", "off"] = "manual"
    approval_timeout_seconds: int = 60
    yolo_env_override: bool = False  # honour RAVEN_YOLO_MODE env var if true

    # -----------------------------------------------------------------
    # Jailbreak defence (always on — defensive)
    # -----------------------------------------------------------------
    jailbreak_detect_enabled: bool = True
    jailbreak_block_threshold: float = 0.8
    jailbreak_log_normalized: bool = True

    # -----------------------------------------------------------------
    # Offensive red-team (operator opt-in only)
    # Default OFF. Even when enabled, every call requires the session token.
    # -----------------------------------------------------------------
    offensive_redteam_enabled: bool = False
    offensive_redteam_session_token: str = ""

    # -----------------------------------------------------------------
    # ML
    # -----------------------------------------------------------------
    model_path: str = "./models"
    anomaly_threshold: float = 0.95
    zero_day_confidence: float = 0.85

    # -----------------------------------------------------------------
    # Shodan
    # -----------------------------------------------------------------
    shodan_api_key: str = ""
    shodan_max_results: int = 100

    # AI Provider — runtime-switchable via `raven provider set` or POST /ai/provider
    # Use "provider:model" shorthand in ai_model, e.g. "openrouter:nous-hermes-2-mixtral-8x7b"
    ai_provider: str = "lmstudio"          # lmstudio|openai|openrouter|anthropic|ollama|opencode|nous
    ai_model: str = ""                     # model name; empty = provider default / loaded model
    ai_api_key: str = ""                   # API key for cloud providers
    ai_base_url: str = ""                  # override provider base URL (optional)
    ai_timeout: int = 120
    ai_temperature: float = 0.2
    ai_max_tokens: int = 4096

    # LM Studio (local AI inference) — kept for backward compatibility
    lmstudio_base_url: str = "http://localhost:1234"
    lmstudio_model: str = ""   # empty = use whatever model is loaded in LM Studio
    lmstudio_api_key: str = ""  # required when LM Studio authentication is enabled
    lmstudio_timeout: int = 120
    lmstudio_temperature: float = 0.2
    lmstudio_max_tokens: int = 4096

    # System prompt — injected as the first message on every AI call
    # Path is resolved relative to CWD. Set to empty string to disable.
    ai_system_prompt_path: str = "RAVEN_SYSTEM_PROMPT.md"

    # OpenRouter-specific options
    openrouter_http_referer: str = "https://raven.local"
    openrouter_title: str = "Project Raven"
    
    # Tool Configuration
    ssh_timeout: int = 30
    nmap_timeout: int = 300
    metasploit_timeout: int = 600
    
    # Monitoring
    enable_metrics: bool = True
    metrics_port: int = 9090
    
    # Logging
    log_level: str = "INFO"
    log_file: str = "./logs/raven.log"

    # -----------------------------------------------------------------
    # Validators / safety guards
    # -----------------------------------------------------------------

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_cors(cls, v):
        # Accept comma-separated env var: CORS_ORIGINS="https://a.com,https://b.com"
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @field_validator("ai_allowed_base_urls", mode="before")
    @classmethod
    def _split_allowed_urls(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @model_validator(mode="after")
    def _enforce_prod_safety(self) -> "Settings":
        """Refuse to start in prod with insecure defaults."""
        if self.environment != "prod":
            return self

        errors: list[str] = []
        if self.secret_key == _DEFAULT_SECRET or len(self.secret_key) < 32:
            errors.append("SECRET_KEY must be set to a strong random value (>=32 chars) in prod")
        if self.debug:
            errors.append("DEBUG must be False in prod")
        if "*" in self.cors_origins:
            errors.append("CORS_ORIGINS must not contain '*' in prod")
        if self.cors_origins == ["http://localhost:3000"]:
            errors.append("CORS_ORIGINS must be explicitly configured in prod")
        if self.bootstrap_admin_password and len(self.bootstrap_admin_password) < 12:
            errors.append("BOOTSTRAP_ADMIN_PASSWORD must be >=12 chars or empty")
        if self.offensive_redteam_enabled and not self.offensive_redteam_session_token:
            errors.append(
                "OFFENSIVE_REDTEAM_SESSION_TOKEN must be set when "
                "OFFENSIVE_REDTEAM_ENABLED=true"
            )
        if self.approval_mode == "off":
            errors.append(
                "APPROVAL_MODE=off (YOLO) is forbidden in prod — use 'manual' or 'smart'"
            )
        if errors:
            raise ValueError(
                "Production safety check failed:\n  - " + "\n  - ".join(errors)
            )
        return self


settings = Settings()

