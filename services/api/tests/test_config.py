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


def test_production_requires_distinct_non_placeholder_approval_secrets() -> None:
    with pytest.raises(ValidationError, match="approval secrets"):
        Settings(
            environment=Environment.PRODUCTION,
            database_url="postgresql+psycopg://service:value@db.internal/retryrail",
            webhook_secret=SecretStr("runtime-injected-production-value"),
            cors_origins=[AnyHttpUrl("https://merchant.example")],
        )

    shared = SecretStr("runtime-injected-shared-approval-secret")
    with pytest.raises(ValidationError, match="must be distinct"):
        Settings(
            environment=Environment.PRODUCTION,
            database_url="postgresql+psycopg://service:value@db.internal/retryrail",
            webhook_secret=SecretStr("runtime-injected-production-value"),
            merchant_approval_secret=shared,
            approval_token_hmac_key=shared,
            cors_origins=[AnyHttpUrl("https://merchant.example")],
        )


def test_production_requires_approval_secrets_distinct_from_webhook_secret() -> None:
    shared = SecretStr("runtime-injected-shared-boundary-secret")
    with pytest.raises(ValidationError, match="must be distinct"):
        Settings(
            environment=Environment.PRODUCTION,
            database_url="postgresql+psycopg://service:value@db.internal/retryrail",
            webhook_secret=shared,
            merchant_approval_secret=shared,
            approval_token_hmac_key=SecretStr(
                "runtime-injected-token-hmac-key-value"
            ),
            cors_origins=[AnyHttpUrl("https://merchant.example")],
        )

    with pytest.raises(ValidationError, match="must be distinct"):
        Settings(
            environment=Environment.PRODUCTION,
            database_url="postgresql+psycopg://service:value@db.internal/retryrail",
            webhook_secret=shared,
            merchant_approval_secret=SecretStr(
                "runtime-injected-merchant-approval-value"
            ),
            approval_token_hmac_key=shared,
            cors_origins=[AnyHttpUrl("https://merchant.example")],
        )


def test_production_accepts_separate_runtime_approval_secrets() -> None:
    settings = Settings(
        environment=Environment.PRODUCTION,
        database_url="postgresql+psycopg://service:value@db.internal/retryrail",
        webhook_secret=SecretStr("runtime-injected-production-value"),
        merchant_approval_secret=SecretStr(
            "runtime-injected-merchant-approval-value"
        ),
        approval_token_hmac_key=SecretStr(
            "runtime-injected-token-hmac-key-value"
        ),
        cors_origins=[AnyHttpUrl("https://merchant.example")],
    )

    assert settings.environment is Environment.PRODUCTION
