"""Configuration settings for Release Captain."""
import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        # Do not load the analyzed repository's .env just because the CLI runs there.
        # A dotenv file is used only when the operator explicitly selects one.
        env_file=os.environ.get("RECAP_ENV_FILE") or None,
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "Release Captain"
    APP_ENV: str = "development"
    DEBUG: bool = True

    # LLM Settings (OpenRouter)
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    OPENROUTER_MODEL: str = "google/gemini-2.5-flash"

    # GitHub Settings
    GITHUB_TOKEN: str = ""
    GITHUB_API_BASE: str = "https://api.github.com"

    # Sandbox / Docker Settings
    DOCKER_ENABLED: bool = True
    SANDBOX_ALLOW_LOCAL_FALLBACK: bool = False
    SANDBOX_PYTHON_BASE_IMAGE: str = "python:3.11-slim"
    SANDBOX_TIMEOUT_SECONDS: int = 300
    SANDBOX_MEMORY_LIMIT: str = "2g"
    SANDBOX_CPU_LIMIT: float = 2.0

    # Risk Engine Default Weights
    WEIGHT_DB_MIGRATION: int = 3
    WEIGHT_AUTH_CHANGE: int = 3
    WEIGHT_PUBLIC_API_CHANGE: int = 3
    WEIGHT_LARGE_DIFF: int = 2
    WEIGHT_DEPENDENCY_UPDATE: int = 2
    WEIGHT_TEST_FAILURE: int = 5
    WEIGHT_SECRET_FOUND: int = 10
    WEIGHT_CRITICAL_CVE: int = 5
    WEIGHT_HIGH_CVE: int = 3


settings = Settings()
