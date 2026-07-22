"""Pytest fixtures for SecureGate AI API tests."""

from __future__ import annotations

import pytest

from backend.app import create_app
from backend.config import AppConfig, DatabaseConfig


@pytest.fixture
def app_config() -> AppConfig:
    return AppConfig(
        env="testing",
        debug=True,
        secret_key="test-secret",
        host="127.0.0.1",
        port=5000,
        database=DatabaseConfig(
            host="localhost",
            port=5432,
            user="postgres",
            password="postgres",
            name="network_security_test",
            min_connections=1,
            max_connections=2,
        ),
        cors_origins=["*"],
        reports_dir="reports/output",
        openai_api_key=None,
    )


@pytest.fixture
def app(app_config):
    return create_app(app_config, testing=True)


@pytest.fixture
def client(app):
    return app.test_client()
