"""Create detector aggregates, incidents, evidence and run receipts.

Revision ID: 0002_m3_detection_incidents
Revises: 0001_m2_event_pipeline
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_m3_detection_incidents"
down_revision: str | None = "0001_m2_event_pipeline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json_type() -> sa.types.TypeEngine[object]:
    return postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")


def upgrade() -> None:
    """Create exactly reconcilable aggregate and incident-lifecycle storage."""

    op.create_table(
        "aggregate_windows",
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("detector_version", sa.String(length=80), nullable=False),
        sa.Column("cohort_key", sa.String(length=200), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cohort", _json_type(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("successes", sa.Integer(), nullable=False),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("gmv_subunits", sa.BigInteger(), nullable=False),
        sa.Column("failed_gmv_subunits", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        sa.Column("source_watermark", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "attempts > 0",
            name="ck_aggregate_windows_attempts_positive",
        ),
        sa.CheckConstraint(
            "successes >= 0 AND failures >= 0 AND successes + failures = attempts",
            name="ck_aggregate_windows_outcomes_reconcile",
        ),
        sa.CheckConstraint(
            "gmv_subunits > 0 AND failed_gmv_subunits >= 0 "
            "AND failed_gmv_subunits <= gmv_subunits",
            name="ck_aggregate_windows_money_reconcile",
        ),
        sa.CheckConstraint(
            "window_end > window_start",
            name="ck_aggregate_windows_time_order",
        ),
        sa.PrimaryKeyConstraint(
            "merchant_id",
            "detector_version",
            "cohort_key",
            "window_start",
        ),
    )
    op.create_index(
        "ix_aggregate_windows_merchant_time",
        "aggregate_windows",
        ["merchant_id", "window_start"],
        unique=False,
    )

    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("detector_version", sa.String(length=80), nullable=False),
        sa.Column("detector_config_sha256", sa.String(length=64), nullable=False),
        sa.Column("detector_cohort_key", sa.String(length=200), nullable=False),
        sa.Column("detector_cohort", _json_type(), nullable=False),
        sa.Column("affected_cohort", _json_type(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("peak_statistics", _json_type(), nullable=False),
        sa.Column("diagnosis", _json_type(), nullable=False),
        sa.Column("evidence_event_ids", _json_type(), nullable=False),
        sa.Column("gmv_at_risk_subunits", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("action_eligible", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint("status IN ('open', 'resolved')", name="ck_incidents_status"),
        sa.CheckConstraint(
            "(status = 'open' AND resolved_at IS NULL) OR "
            "(status = 'resolved' AND resolved_at IS NOT NULL)",
            name="ck_incidents_resolution_state",
        ),
        sa.CheckConstraint(
            "last_observed_at >= opened_at AND "
            "(resolved_at IS NULL OR resolved_at >= last_observed_at)",
            name="ck_incidents_time_order",
        ),
        sa.CheckConstraint(
            "gmv_at_risk_subunits >= 0",
            name="ck_incidents_at_risk_nonnegative",
        ),
        sa.CheckConstraint(
            "length(detector_config_sha256) = 64",
            name="ck_incidents_detector_config_sha256",
        ),
        sa.PrimaryKeyConstraint("incident_id"),
        sa.UniqueConstraint(
            "incident_id",
            "merchant_id",
            name="uq_incidents_identity_merchant",
        ),
    )
    op.create_index(
        "ix_incidents_merchant_opened",
        "incidents",
        ["merchant_id", "opened_at"],
        unique=False,
    )
    op.create_index(
        "uq_incidents_one_active_cohort",
        "incidents",
        ["merchant_id", "detector_cohort_key"],
        unique=True,
        postgresql_where=sa.text("status = 'open'"),
        sqlite_where=sa.text("status = 'open'"),
    )

    op.create_table(
        "incident_observations",
        sa.Column("observation_id", sa.String(length=80), nullable=False),
        sa.Column("incident_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("detector_version", sa.String(length=80), nullable=False),
        sa.Column("detector_config_sha256", sa.String(length=64), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("statistics", _json_type(), nullable=False),
        sa.Column("evidence_event_ids", _json_type(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(detector_config_sha256) = 64",
            name="ck_incident_observations_detector_config_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id", "merchant_id"],
            ["incidents.incident_id", "incidents.merchant_id"],
            name="fk_incident_observations_incident_merchant",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("observation_id"),
        sa.UniqueConstraint(
            "incident_id",
            "evaluated_at",
            name="uq_incident_observations_incident_time",
        ),
    )
    op.create_index(
        "ix_incident_observations_incident_time",
        "incident_observations",
        ["incident_id", "evaluated_at"],
        unique=False,
    )

    op.create_table(
        "detection_runs",
        sa.Column("run_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("detector_version", sa.String(length=80), nullable=False),
        sa.Column("detector_config_sha256", sa.String(length=64), nullable=False),
        sa.Column("source_events_sha256", sa.String(length=64), nullable=False),
        sa.Column("source_watermark", sa.DateTime(timezone=True), nullable=False),
        sa.Column("partition_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("partition_ended_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("aggregate_count", sa.Integer(), nullable=False),
        sa.Column("incident_count", sa.Integer(), nullable=False),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(detector_config_sha256) = 64 AND length(source_events_sha256) = 64",
            name="ck_detection_runs_sha256",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND aggregate_count >= 0 AND incident_count >= 0",
            name="ck_detection_runs_counts_nonnegative",
        ),
        sa.PrimaryKeyConstraint("run_id"),
        sa.UniqueConstraint(
            "merchant_id",
            "detector_config_sha256",
            "source_events_sha256",
            name="uq_detection_runs_source_snapshot",
        ),
    )
    op.create_index(
        "ix_detection_runs_merchant_created",
        "detection_runs",
        ["merchant_id", "created_at"],
        unique=False,
    )
    _create_immutable_evidence_triggers()


def _create_immutable_evidence_triggers() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            """
            CREATE FUNCTION retryrail_reject_detector_evidence_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'detector evidence is immutable' USING ERRCODE = '55000';
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        for table in ("incident_observations", "detection_runs"):
            op.execute(
                f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} "
                "FOR EACH ROW EXECUTE FUNCTION "
                "retryrail_reject_detector_evidence_mutation();"
            )
    elif bind.dialect.name == "sqlite":
        for table in ("incident_observations", "detection_runs"):
            op.execute(
                f"CREATE TRIGGER {table}_immutable_update BEFORE UPDATE ON {table} "
                "BEGIN SELECT RAISE(ABORT, 'detector evidence is immutable'); END;"
            )
            op.execute(
                f"CREATE TRIGGER {table}_immutable_delete BEFORE DELETE ON {table} "
                "BEGIN SELECT RAISE(ABORT, 'detector evidence is immutable'); END;"
            )


def downgrade() -> None:
    """Remove M3 storage and immutable evidence guards in dependency order."""

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in ("incident_observations", "detection_runs"):
            op.execute(f"DROP TRIGGER IF EXISTS {table}_immutable ON {table}")
        op.execute("DROP FUNCTION IF EXISTS retryrail_reject_detector_evidence_mutation()")
    elif bind.dialect.name == "sqlite":
        for table in ("incident_observations", "detection_runs"):
            op.execute(f"DROP TRIGGER IF EXISTS {table}_immutable_update")
            op.execute(f"DROP TRIGGER IF EXISTS {table}_immutable_delete")

    op.drop_index("ix_detection_runs_merchant_created", table_name="detection_runs")
    op.drop_table("detection_runs")
    op.drop_index(
        "ix_incident_observations_incident_time",
        table_name="incident_observations",
    )
    op.drop_table("incident_observations")
    op.drop_index("uq_incidents_one_active_cohort", table_name="incidents")
    op.drop_index("ix_incidents_merchant_opened", table_name="incidents")
    op.drop_table("incidents")
    op.drop_index(
        "ix_aggregate_windows_merchant_time",
        table_name="aggregate_windows",
    )
    op.drop_table("aggregate_windows")
