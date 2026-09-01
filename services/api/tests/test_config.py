"""Configuration must fail closed before a production process starts."""

import pytest
from pydantic import AnyHttpUrl, SecretStr, ValidationError

from retryrail.config import Environment, Settings


def test_development_accepts_safe_local_placeholders() -> None:
    settings = Settings()

    assert settings.environment is Environment.DEVELOPMENT
    assert "local-only-password" in settings.database_dsn()
    assert "local-only-password" not in repr(settings)


@pytest.mark.parametrize(
    ("secret", "database_url", "origin", "expected_message"),
    [
        (
            "replace-with-a-random-local-test-secret",
            "postgresql+psycopg://service:value@db.internal/retryrail",
            "https://merchant.example",
            "WEBHOOK_SECRET",
        ),
        (
            "runtime-injected-production-value",
            "sqlite:///retryrail.db",
            "https://merchant.example",
            "PostgreSQL",
        ),
        (
            "runtime-injected-production-value",
            "postgresql+psycopg://service:value@db.internal/retryrail",
            "http://localhost:5173",
            "localhost",
        ),
    ],
)
def test_production_rejects_unsafe_configuration(
    secret: str,
    database_url: str,
    origin: str,
    expected_message: str,
) -> None:
    with pytest.raises(ValidationError, match=expected_message):
        Settings(
            environment=Environment.PRODUCTION,
            database_url=database_url,
            webhook_secret=SecretStr(secret),
            cors_origins=[AnyHttpUrl(origin)],
        )


def test_production_cannot_enable_synthetic_replay() -> None:
    with pytest.raises(ValidationError, match="replay"):
        Settings(
            environment=Environment.PRODUCTION,
            database_url="postgresql+psycopg://service:value@db.internal/retryrail",
            webhook_secret=SecretStr("runtime-injected-production-value"),
            cors_origins=[AnyHttpUrl("https://merchant.example")],
            replay_enabled=True,
        )
