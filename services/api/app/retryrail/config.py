"""Validated application configuration loaded only from safe local defaults or env."""

from enum import StrEnum
from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Supported deployment environments."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


_INSECURE_SECRET_VALUES = frozenset(
    {
        "",
        "change-me",
        "local-development-only",
        "replace-with-a-random-local-approval-secret",
        "replace-with-a-random-local-token-hmac-key",
        "replace-with-a-random-local-test-secret",
    }
)
_MAX_RAZORPAY_KEY_ID_LENGTH = 80
_MIN_RAZORPAY_KEY_SECRET_LENGTH = 8
_MAX_RAZORPAY_KEY_SECRET_LENGTH = 200


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
    recovery_execution_target: Literal[
        "deterministic_fake", "razorpay_test_mode"
    ] = "deterministic_fake"
    razorpay_key_id: SecretStr | None = None
    razorpay_key_secret: SecretStr | None = None
    razorpay_connect_timeout_seconds: float = Field(default=3.0, ge=0.1, le=10.0)
    razorpay_read_timeout_seconds: float = Field(default=8.0, ge=0.1, le=30.0)
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

    @model_validator(mode="after")
    def reject_unsafe_production_configuration(self) -> "Settings":
        """Prevent placeholder secrets and non-PostgreSQL production stores."""

        self._validate_razorpay_test_mode_configuration()

        if self.environment is not Environment.PRODUCTION:
            return self

        if self.webhook_secret.get_secret_value() in _INSECURE_SECRET_VALUES:
            msg = "RETRYRAIL_WEBHOOK_SECRET must be replaced in production"
            raise ValueError(msg)
        if not self.database_url.get_secret_value().startswith(
            ("postgresql://", "postgresql+psycopg://")
        ):
            msg = "production requires a PostgreSQL database URL"
            raise ValueError(msg)
        if self.replay_enabled:
            msg = "synthetic replay cannot be enabled in production"
            raise ValueError(msg)
        if any(origin.host in {"localhost", "127.0.0.1"} for origin in self.cors_origins):
            msg = "production CORS origins cannot target localhost"
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
        )
        if len(set(runtime_secret_values)) != len(runtime_secret_values):
            msg = "webhook, merchant approval and token HMAC secrets must be distinct"
            raise ValueError(msg)
        return self

    def _validate_razorpay_test_mode_configuration(self) -> None:
        """Admit only a complete Test Mode credential pair at the provider boundary."""

        key_id = self.razorpay_key_id.get_secret_value() if self.razorpay_key_id else ""
        key_secret = (
            self.razorpay_key_secret.get_secret_value() if self.razorpay_key_secret else ""
        )
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

        return self.database_url.get_secret_value()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return one immutable-by-convention settings object per process."""

    return Settings()
