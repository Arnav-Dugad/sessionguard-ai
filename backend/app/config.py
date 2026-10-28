"""Environment-driven configuration.

All values can be overridden with environment variables prefixed ``SG_`` or via ``.env``.
"""
from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SG_",
        env_file=(REPO_DIR / ".env", BACKEND_DIR / ".env"),
        extra="ignore",
    )

    app_name: str = "SessionGuard AI"
    environment: str = "development"

    database_url: str = f"sqlite:///{(BACKEND_DIR / 'data' / 'sessionguard.db').as_posix()}"

    # Pepper for HMAC-hashing session tokens at rest. Generated per process if unset,
    # which invalidates sessions on restart - set SG_TOKEN_PEPPER in .env to persist them.
    token_pepper: str = Field(default_factory=lambda: secrets.token_hex(32))

    session_cookie_name: str = "sg_session"
    csrf_cookie_name: str = "sg_csrf"
    csrf_header_name: str = "X-CSRF-Token"
    cookie_secure: bool = False  # set true when served over HTTPS
    session_idle_timeout_min: int = 30
    session_absolute_timeout_min: int = 8 * 60
    step_up_valid_min: int = 10

    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    model_dir: Path = REPO_DIR / "ml" / "artifacts"
    active_model: str = "aexgb"  # aexgb | xgboost | logreg | rules

    # The simulation lab is a demonstration feature. Disable it for anything but local demos.
    enable_simulation_lab: bool = True

    login_rate_limit_per_10min: int = 20


@lru_cache
def get_settings() -> Settings:
    return Settings()
