"""Configuration management for Project Raven"""

from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    """Application settings"""
    
    # API Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug: bool = False
    
    # Database
    database_url: str = "postgresql://user:password@localhost/raven"
    redis_url: str = "redis://localhost:6379/0"
    
    # Security
    secret_key: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    jwt_algorithm: str = "HS256"
    jwt_expiration: int = 3600
    
    # ML Configuration
    model_path: str = "./models"
    anomaly_threshold: float = 0.95
    zero_day_confidence: float = 0.85

    # Shodan
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
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
