"""Validated application configuration loaded only from safe local defaults or env."""

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AnyHttpUrl, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Supported deployment environments."""

    DEVELOPMENT = "development"
    TEST = "test"
    REVIEW = "review"
    PRODUCTION = "production"


_INSECURE_SECRET_VALUES = frozenset(
    {
        "",
        "change-me",
        "local-development-only",
        "local-replay-token-not-for-production",
        "replace-with-a-random-local-approval-secret",
        "replace-with-a-random-local-replay-token",
        "replace-with-a-random-local-token-hmac-key",
        "replace-with-a-random-local-test-secret",
    }
)
_MAX_RAZORPAY_KEY_ID_LENGTH = 80
_MIN_RAZORPAY_KEY_SECRET_LENGTH = 8
_MAX_RAZORPAY_KEY_SECRET_LENGTH = 200
_MAX_OPENAI_API_KEY_LENGTH = 300
_MIN_OPENAI_API_KEY_LENGTH = 20


class Settings(BaseSettings):
    """RetryRail settings with production fail-closed checks."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="RETRYRAIL_",
        extra="ignore",
    )

    environment: Environment = Environment.DEVELOPMENT
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    database_url: SecretStr = SecretStr(
        "postgresql+psycopg://retryrail:local-only-password@localhost:5432/retryrail"
    )
    merchant_id: str = Field(
        default="merchant_synthetic_001",
        min_length=3,
        max_length=80,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    webhook_secret: SecretStr = SecretStr("replace-with-a-random-local-test-secret")
    merchant_approval_secret: SecretStr = Field(
        default=SecretStr("replace-with-a-random-local-approval-secret"),
        min_length=32,
    )
    approval_token_hmac_key: SecretStr = Field(
        default=SecretStr("replace-with-a-random-local-token-hmac-key"),
        min_length=32,
    )
    merchant_approver_id: str = Field(
        default="merchant_operator_local",
        min_length=3,
        max_length=80,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    recovery_mode: Literal["analyze_only", "review_first"] = "review_first"
    recovery_template_enabled: bool = True
    recovery_kill_switch: bool = False
    recovery_plan_lifetime_seconds: int = Field(default=1_800, ge=60, le=86_400)
    approval_token_lifetime_seconds: int = Field(default=600, ge=30, le=900)
    recovery_maximum_attempts_per_payment: int = Field(default=1, ge=1, le=3)
    recovery_cooldown_seconds: int = Field(default=900, ge=0, le=604_800)
    recovery_execution_target: Literal["deterministic_fake", "razorpay_test_mode"] = (
        "deterministic_fake"
    )
    razorpay_key_id: SecretStr | None = None
    razorpay_key_secret: SecretStr | None = None
    razorpay_connect_timeout_seconds: float = Field(default=3.0, ge=0.1, le=10.0)
    razorpay_read_timeout_seconds: float = Field(default=8.0, ge=0.1, le=30.0)
    incident_analyst_target: Literal["deterministic_rules", "openai"] = "deterministic_rules"
    openai_api_key: SecretStr | None = None
    openai_incident_model: str = Field(
        default="gpt-5.4-nano-2026-03-17",
        min_length=3,
        max_length=80,
        pattern=r"^gpt-[A-Za-z0-9.:-]+-\d{4}-\d{2}-\d{2}$",
    )
    openai_timeout_seconds: float = Field(default=12.0, ge=1.0, le=30.0)
    openai_max_output_tokens: int = Field(default=1_600, ge=400, le=4_000)
    openai_max_schema_repairs: Literal[0, 1] = 1
    incident_analyst_prompt_version: str = Field(
        default="incident_analyst_prompt_v1",
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    incident_analyst_evaluator_version: str = Field(
        default="incident_analyst_eval_v1",
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    max_webhook_body_bytes: int = Field(default=262_144, ge=1_024, le=1_048_576)
    outbox_max_attempts: int = Field(default=5, ge=1, le=20)
    worker_batch_size: int = Field(default=50, ge=1, le=500)
    worker_poll_interval_seconds: float = Field(default=0.25, ge=0.01, le=30.0)
    worker_lease_seconds: int = Field(default=30, ge=5, le=600)
    worker_retry_base_seconds: int = Field(default=2, ge=1, le=300)
    worker_metrics_host: Literal["127.0.0.1", "0.0.0.0"] = "127.0.0.1"  # noqa: S104
    worker_metrics_port: int = Field(default=9_101, ge=1_024, le=65_535)
    replay_enabled: bool = False
    replay_token: SecretStr = SecretStr("local-replay-token-not-for-production")
    cors_origins: list[AnyHttpUrl] = [AnyHttpUrl("http://localhost:5173")]
    serve_web: bool = False
    web_dist_path: Path = Path("apps/web/dist")

    @model_validator(mode="after")
    def reject_unsafe_production_configuration(self) -> "Settings":
        """Prevent placeholder secrets and non-PostgreSQL production stores."""

        self._validate_razorpay_test_mode_configuration()
        self._validate_incident_analyst_configuration()

        if self.environment not in {Environment.PRODUCTION, Environment.REVIEW}:
            return self

        self._validate_hosted_configuration()
        if self.environment is Environment.REVIEW:
            self._validate_review_configuration()
        return self

    def _validate_hosted_configuration(self) -> None:
        """Apply the shared fail-closed boundary to review and production."""

        if self.webhook_secret.get_secret_value() in _INSECURE_SECRET_VALUES:
            msg = "RETRYRAIL_WEBHOOK_SECRET must be replaced when hosted"
            raise ValueError(msg)
        if not self.database_url.get_secret_value().startswith(
            ("postgresql://", "postgresql+psycopg://")
        ):
            msg = "hosted environments require a PostgreSQL database URL"
            raise ValueError(msg)
        if self.environment is Environment.PRODUCTION and self.replay_enabled:
            msg = "synthetic replay cannot be enabled in production"
            raise ValueError(msg)
        if (
            self.replay_enabled
            and self.replay_token.get_secret_value() in _INSECURE_SECRET_VALUES
        ):
            msg = "RETRYRAIL_REPLAY_TOKEN must be replaced when hosted"
            raise ValueError(msg)
        if any(origin.host in {"localhost", "127.0.0.1"} for origin in self.cors_origins):
            msg = "hosted CORS origins cannot target localhost"
            raise ValueError(msg)
        approval_secrets = {
            self.merchant_approval_secret.get_secret_value(),
            self.approval_token_hmac_key.get_secret_value(),
        }
        if approval_secrets & _INSECURE_SECRET_VALUES:
            msg = "approval secrets must be replaced in production"
            raise ValueError(msg)
        runtime_secret_values = (
            self.webhook_secret.get_secret_value(),
            self.merchant_approval_secret.get_secret_value(),
            self.approval_token_hmac_key.get_secret_value(),
            *((self.openai_api_key.get_secret_value(),) if self.openai_api_key is not None else ()),
            *((self.replay_token.get_secret_value(),) if self.replay_enabled else ()),
        )
        if len(set(runtime_secret_values)) != len(runtime_secret_values):
            msg = "all runtime secrets must be distinct"
            raise ValueError(msg)

    def _validate_review_configuration(self) -> None:
        """Keep the public synthetic sandbox unable to call external providers."""

        if not self.recovery_kill_switch:
            msg = "review deployments require the recovery kill switch"
            raise ValueError(msg)
        if self.recovery_execution_target != "deterministic_fake":
            msg = "review deployments cannot call an external recovery provider"
            raise ValueError(msg)
        if self.incident_analyst_target != "deterministic_rules":
            msg = "review deployments cannot call an external incident analyst"
            raise ValueError(msg)

    def _validate_incident_analyst_configuration(self) -> None:
        """Require a plausible secret and pinned snapshot for external analysis."""

        api_key = self.openai_api_key.get_secret_value() if self.openai_api_key else ""
        if self.incident_analyst_target == "openai" and not api_key:
            msg = "OpenAI incident analysis requires an API key"
            raise ValueError(msg)
        if not api_key:
            return
        if (
            not api_key.startswith("sk-")
            or len(api_key) < _MIN_OPENAI_API_KEY_LENGTH
            or len(api_key) > _MAX_OPENAI_API_KEY_LENGTH
            or any(character.isspace() for character in api_key)
        ):
            msg = "OpenAI API key has an invalid shape"
            raise ValueError(msg)
        if api_key in {
            self.webhook_secret.get_secret_value(),
            self.merchant_approval_secret.get_secret_value(),
            self.approval_token_hmac_key.get_secret_value(),
        }:
            msg = "OpenAI API key must not be reused as another runtime secret"
            raise ValueError(msg)

    def _validate_razorpay_test_mode_configuration(self) -> None:
        """Admit only a complete Test Mode credential pair at the provider boundary."""

        key_id = self.razorpay_key_id.get_secret_value() if self.razorpay_key_id else ""
        key_secret = self.razorpay_key_secret.get_secret_value() if self.razorpay_key_secret else ""
        if bool(key_id) is not bool(key_secret):
            msg = "Razorpay Test Mode key id and secret must be configured together"
            raise ValueError(msg)
        if self.recovery_execution_target == "razorpay_test_mode" and (
            not key_id or not key_secret
        ):
            msg = "Razorpay Test Mode execution requires an API key id and secret"
            raise ValueError(msg)
        if not key_id:
            return
        if not key_id.startswith("rzp_test_"):
            msg = "Razorpay execution accepts Test Mode key ids only"
            raise ValueError(msg)
        if (
            len(key_id) > _MAX_RAZORPAY_KEY_ID_LENGTH
            or len(key_secret) < _MIN_RAZORPAY_KEY_SECRET_LENGTH
            or len(key_secret) > _MAX_RAZORPAY_KEY_SECRET_LENGTH
        ):
            msg = "Razorpay Test Mode credentials have an invalid shape"
            raise ValueError(msg)

    def database_dsn(self) -> str:
        """Reveal the database URL only at the connection boundary."""

        database_url = self.database_url.get_secret_value()
        if database_url.startswith("postgresql://"):
            return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
        return database_url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return one immutable-by-convention settings object per process."""

    return Settings()
