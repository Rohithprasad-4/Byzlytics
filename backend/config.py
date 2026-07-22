"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class DatabaseConfig:
    host: str
    port: int
    user: str
    password: str
    name: str
    min_connections: int
    max_connections: int


@dataclass(frozen=True)
class AppConfig:
    env: str
    debug: bool
    secret_key: str
    host: str
    port: int
    database: DatabaseConfig
    cors_origins: list[str]
    reports_dir: str
    openai_api_key: str | None


def _parse_cors_origins(raw: str) -> list[str]:
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def load_config() -> AppConfig:
    """Build immutable configuration from environment."""
    return AppConfig(
        env=os.getenv("FLASK_ENV", "production"),
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
        secret_key=os.getenv("SECRET_KEY", "change-me-in-production"),
        host=os.getenv("FLASK_HOST", "0.0.0.0"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        database=DatabaseConfig(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "5432")),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "postgres"),
            name=os.getenv("DB_NAME", "network_security"),
            min_connections=int(os.getenv("DB_POOL_MIN", "1")),
            max_connections=int(os.getenv("DB_POOL_MAX", "10")),
        ),
        cors_origins=_parse_cors_origins(
            os.getenv("CORS_ORIGINS", "http://localhost:5000,http://127.0.0.1:5000")
        ),
        reports_dir=os.getenv("REPORTS_DIR", "reports/output"),
        openai_api_key=os.getenv("OPENAI_API_KEY"),
    )
