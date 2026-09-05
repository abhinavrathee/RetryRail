"""Add immutable, redacted model-analysis evidence.

Revision ID: 0007_m6_model_incident_analysis
Revises: 0006_m5_provider_dispatch
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_m6_model_incident_analysis"
down_revision: str | None = "0006_m5_provider_dispatch"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json_type() -> sa.types.TypeEngine[object]:
    return postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")


def upgrade() -> None:
    """Persist only validated advisory output; raw provider output is never stored."""

    op.create_table(
        "model_incident_analyses",
        sa.Column("analysis_id", sa.String(length=80), nullable=False),
        sa.Column("incident_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("snapshot_id", sa.String(length=80), nullable=False),
        sa.Column("source_snapshot_sha256", sa.String(length=64), nullable=False),
        sa.Column("analysis_sha256", sa.String(length=64), nullable=False),
        sa.Column("analysis_document", _json_type(), nullable=False),
        sa.Column("provider", sa.String(length=16), nullable=False),
        sa.Column("model", sa.String(length=80), nullable=False),
        sa.Column("prompt_version", sa.String(length=80), nullable=False),
        sa.Column("output_schema_version", sa.String(length=16), nullable=False),
        sa.Column("evaluator_version", sa.String(length=80), nullable=False),
        sa.Column("model_status", sa.String(length=24), nullable=False),
        sa.Column("fallback_used", sa.Boolean(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column("total_tokens", sa.Integer(), nullable=False),
        sa.Column("estimated_cost_microusd", sa.Integer(), nullable=True),
        sa.Column("pricing_version", sa.String(length=48), nullable=False),
        sa.Column("schema_repair_attempts", sa.Integer(), nullable=False),
        sa.Column("provider_storage_enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(source_snapshot_sha256) = 64 AND length(analysis_sha256) = 64",
            name="ck_model_analyses_sha256",
        ),
        sa.CheckConstraint(
            "provider = 'openai' AND model_status = 'succeeded' "
            "AND fallback_used = false AND provider_storage_enabled = false",
            name="ck_model_analyses_bounded_mode",
        ),
        sa.CheckConstraint(
            "latency_ms >= 0 AND input_tokens >= 0 AND output_tokens >= 0 "
            "AND total_tokens = input_tokens + output_tokens "
            "AND (estimated_cost_microusd IS NULL OR estimated_cost_microusd >= 0) "
            "AND schema_repair_attempts >= 0 AND schema_repair_attempts <= 1",
            name="ck_model_analyses_telemetry",
        ),
        sa.CheckConstraint(
            "(pricing_version = 'unavailable_for_model' "
            "AND estimated_cost_microusd IS NULL) OR "
            "(pricing_version = 'openai_public_pricing_2026_09_05' "
            "AND estimated_cost_microusd IS NOT NULL)",
            name="ck_model_analyses_pricing",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id", "merchant_id"],
            ["incidents.incident_id", "incidents.merchant_id"],
            name="fk_model_analyses_incident_merchant",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("analysis_id"),
        sa.UniqueConstraint(
            "incident_id",
            "source_snapshot_sha256",
            "model",
            "prompt_version",
            "evaluator_version",
            name="uq_model_analyses_incident_snapshot_model_prompt_eval",
        ),
    )
    op.create_index(
        "ix_model_analyses_merchant_created",
        "model_incident_analyses",
        ["merchant_id", "created_at"],
        unique=False,
    )
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            "CREATE TRIGGER model_incident_analyses_immutable "
            "BEFORE UPDATE OR DELETE ON model_incident_analyses FOR EACH ROW "
            "EXECUTE FUNCTION retryrail_reject_recovery_evidence_mutation();"
        )
    elif bind.dialect.name == "sqlite":
        op.execute(
            "CREATE TRIGGER model_incident_analyses_immutable_update "
            "BEFORE UPDATE ON model_incident_analyses "
            "BEGIN SELECT RAISE(ABORT, 'recovery evidence is immutable'); END;"
        )
        op.execute(
            "CREATE TRIGGER model_incident_analyses_immutable_delete "
            "BEFORE DELETE ON model_incident_analyses "
            "BEGIN SELECT RAISE(ABORT, 'recovery evidence is immutable'); END;"
        )


def downgrade() -> None:
    """Remove only M6 model-analysis evidence."""

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS model_incident_analyses_immutable ON model_incident_analyses"
        )
    elif bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS model_incident_analyses_immutable_update")
        op.execute("DROP TRIGGER IF EXISTS model_incident_analyses_immutable_delete")
    op.drop_index(
        "ix_model_analyses_merchant_created",
        table_name="model_incident_analyses",
    )
    op.drop_table("model_incident_analyses")
