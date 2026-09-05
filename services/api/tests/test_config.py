"""Configuration must fail closed before a production process starts."""

from types import SimpleNamespace

import pytest
from pydantic import AnyHttpUrl, SecretStr, ValidationError

from retryrail import main as main_module
from retryrail.config import Environment, Settings
from retryrail.recovery.openai_analyst import OpenAIIncidentAnalystProvider


def test_development_accepts_safe_local_placeholders() -> None:
    settings = Settings()

    assert settings.environment is Environment.DEVELOPMENT
    assert settings.openai_incident_model == "gpt-5.4-nano-2026-03-17"
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


def test_render_postgres_url_is_normalized_at_the_driver_boundary() -> None:
    settings = Settings(database_url="postgresql://service:value@db.internal/retryrail")

    assert settings.database_dsn() == (
        "postgresql+psycopg://service:value@db.internal/retryrail"
    )


def test_review_environment_is_hardened_but_allows_bounded_synthetic_replay() -> None:
    settings = Settings(
        environment=Environment.REVIEW,
        database_url="postgresql://service:value@db.internal/retryrail",
        webhook_secret=SecretStr("review-runtime-webhook-value"),
        merchant_approval_secret=SecretStr("review-runtime-merchant-approval-value"),
        approval_token_hmac_key=SecretStr("review-runtime-token-hmac-key-value"),
        replay_enabled=True,
        replay_token=SecretStr("review-runtime-replay-value"),
        recovery_kill_switch=True,
        cors_origins=[],
    )

    assert settings.environment is Environment.REVIEW
    assert settings.replay_enabled is True
    assert settings.recovery_execution_target == "deterministic_fake"
    assert settings.incident_analyst_target == "deterministic_rules"


@pytest.mark.parametrize(
    ("overrides", "expected_message"),
    [
        ({"recovery_kill_switch": False}, "kill switch"),
        (
            {"replay_token": SecretStr("local-replay-token-not-for-production")},
            "REPLAY_TOKEN",
        ),
        (
            {
                "recovery_execution_target": "razorpay_test_mode",
                "razorpay_key_id": SecretStr("rzp_test_review_identifier"),
                "razorpay_key_secret": SecretStr("review-provider-value"),
            },
            "external recovery provider",
        ),
        (
            {
                "incident_analyst_target": "openai",
                "openai_api_key": SecretStr("sk-review-not-a-real-platform-api-key"),
            },
            "external incident analyst",
        ),
    ],
)
def test_review_environment_rejects_unbounded_external_actions(
    overrides: dict[str, object],
    expected_message: str,
) -> None:
    configuration: dict[str, object] = {
        "environment": Environment.REVIEW,
        "database_url": "postgresql://service:value@db.internal/retryrail",
        "webhook_secret": SecretStr("review-runtime-webhook-value"),
        "merchant_approval_secret": SecretStr(
            "review-runtime-merchant-approval-value"
        ),
        "approval_token_hmac_key": SecretStr(
            "review-runtime-token-hmac-key-value"
        ),
        "replay_enabled": True,
        "replay_token": SecretStr("review-runtime-replay-value"),
        "recovery_kill_switch": True,
        "cors_origins": [],
    }
    configuration.update(overrides)

    with pytest.raises(ValidationError, match=expected_message):
        Settings(**configuration)  # type: ignore[arg-type]


def test_razorpay_test_mode_requires_complete_test_credentials() -> None:
    with pytest.raises(ValidationError, match="requires an API key id and secret"):
        Settings(recovery_execution_target="razorpay_test_mode")

    with pytest.raises(ValidationError, match="configured together"):
        Settings(razorpay_key_id=SecretStr("rzp_test_example_identifier"))

    with pytest.raises(ValidationError, match="Test Mode key ids only"):
        Settings(
            razorpay_key_id=SecretStr("rzp_live_never_admitted"),
            razorpay_key_secret=SecretStr("not-a-real-secret"),
        )


def test_razorpay_test_credentials_are_redacted_and_admitted() -> None:
    key_id = "rzp_test_example_identifier"
    key_secret = "unit-test-provider-secret"
    settings = Settings(
        recovery_execution_target="razorpay_test_mode",
        razorpay_key_id=SecretStr(key_id),
        razorpay_key_secret=SecretStr(key_secret),
    )

    assert settings.recovery_execution_target == "razorpay_test_mode"
    assert settings.razorpay_key_id is not None
    assert settings.razorpay_key_secret is not None
    assert settings.razorpay_key_id.get_secret_value() == key_id
    assert settings.razorpay_key_secret.get_secret_value() == key_secret
    assert key_id not in repr(settings)
    assert key_secret not in repr(settings)


def test_openai_incident_analyst_requires_key_and_pinned_model_snapshot() -> None:
    with pytest.raises(ValidationError, match="requires an API key"):
        Settings(incident_analyst_target="openai")

    with pytest.raises(ValidationError, match="openai_incident_model"):
        Settings(
            incident_analyst_target="openai",
            openai_api_key=SecretStr("sk-unit-test-not-a-real-platform-api-key"),
            openai_incident_model="gpt-5.4-mini",
        )

    with pytest.raises(ValidationError, match="invalid shape"):
        Settings(
            incident_analyst_target="openai",
            openai_api_key=SecretStr("sk-too-short"),
        )


def test_openai_api_key_is_redacted_admitted_and_not_reusable() -> None:
    api_key = "sk-unit-test-not-a-real-platform-api-key"
    settings = Settings(
        incident_analyst_target="openai",
        openai_api_key=SecretStr(api_key),
        openai_incident_model="gpt-5.4-mini-2026-03-17",
    )

    assert settings.openai_api_key is not None
    assert settings.openai_api_key.get_secret_value() == api_key
    assert api_key not in repr(settings)

    with pytest.raises(ValidationError, match="must not be reused"):
        Settings(
            webhook_secret=SecretStr(api_key),
            incident_analyst_target="openai",
            openai_api_key=SecretStr(api_key),
        )


@pytest.mark.parametrize(
    ("report_status", "selected_model"),
    [
        ("threshold_gap", None),
        ("passed", "gpt-5.4-nano-2026-03-17"),
    ],
)
def test_openai_runtime_requires_the_exact_passing_frozen_selection(
    monkeypatch: pytest.MonkeyPatch,
    report_status: str,
    selected_model: str | None,
) -> None:
    settings = Settings(
        incident_analyst_target="openai",
        openai_api_key=SecretStr("sk-unit-test-not-a-real-platform-api-key"),
        openai_incident_model="gpt-5.4-mini-2026-03-17",
    )
    monkeypatch.setattr(
        main_module,
        "check_analyst_report",
        lambda: SimpleNamespace(status=report_status, selected_model=selected_model),
    )

    with pytest.raises(RuntimeError, match="passing frozen M6 selection"):
        main_module._configured_incident_analyst_provider(settings)  # noqa: SLF001


@pytest.mark.anyio
async def test_openai_runtime_accepts_frozen_default_selection() -> None:
    settings = Settings(
        incident_analyst_target="openai",
        openai_api_key=SecretStr("sk-unit-test-not-a-real-platform-api-key"),
    )

    provider = main_module._configured_incident_analyst_provider(settings)  # noqa: SLF001

    assert isinstance(provider, OpenAIIncidentAnalystProvider)
    assert provider.model == "gpt-5.4-nano-2026-03-17"
    await provider.aclose()
