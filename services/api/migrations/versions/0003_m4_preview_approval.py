"""Create immutable recovery previews, policy evidence and approval facts.

Revision ID: 0003_m4_preview_approval
Revises: 0002_m3_detection_incidents
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_m4_preview_approval"
down_revision: str | None = "0002_m3_detection_incidents"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json_type() -> sa.types.TypeEngine[object]:
    return postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")


def upgrade() -> None:
    """Create the append-only M4.3 evidence and approval-token boundary."""

    op.create_table(
        "payment_recovery_controls",
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("payment_id", sa.String(length=80), nullable=False),
        sa.Column("contact_consent_verified", sa.Boolean(), nullable=False),
        sa.Column("customer_opted_out", sa.Boolean(), nullable=False),
        sa.Column("already_recovered", sa.Boolean(), nullable=False),
        sa.Column("prior_action_attempts", sa.Integer(), nullable=False),
        sa.Column("last_action_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "prior_action_attempts >= 0 AND prior_action_attempts <= 3",
            name="ck_payment_recovery_controls_attempts",
        ),
        sa.CheckConstraint(
            "version > 0",
            name="ck_payment_recovery_controls_version",
        ),
        sa.CheckConstraint(
            "source = 'synthetic_fixture_default'",
            name="ck_payment_recovery_controls_m4_source",
        ),
        sa.ForeignKeyConstraint(
            ["merchant_id", "payment_id"],
            ["payment_projections.merchant_id", "payment_projections.payment_id"],
            name="fk_payment_recovery_controls_projection",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("merchant_id", "payment_id"),
    )
    op.create_index(
        "ix_payment_recovery_controls_merchant_updated",
        "payment_recovery_controls",
        ["merchant_id", "updated_at"],
        unique=False,
    )
    op.execute(
        """
        INSERT INTO payment_recovery_controls (
            merchant_id,
            payment_id,
            contact_consent_verified,
            customer_opted_out,
            already_recovered,
            prior_action_attempts,
            last_action_at,
            source,
            version,
            updated_at
        )
        SELECT
            merchant_id,
            payment_id,
            false,
            false,
            CASE WHEN status = 'failed' THEN false ELSE true END,
            0,
            NULL,
            'synthetic_fixture_default',
            1,
            last_processed_at
        FROM payment_projections
        WHERE synthetic = true
        """
    )

    op.create_table(
        "recovery_plans",
        sa.Column("plan_id", sa.String(length=80), nullable=False),
        sa.Column("incident_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("payment_id", sa.String(length=80), nullable=False),
        sa.Column("idempotency_key", sa.String(length=80), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("plan_sha256", sa.String(length=64), nullable=False),
        sa.Column("plan_document", _json_type(), nullable=False),
        sa.Column("source_evidence_sha256", sa.String(length=64), nullable=False),
        sa.Column("source_evidence_document", _json_type(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(request_sha256) = 64 AND length(plan_sha256) = 64 "
            "AND length(source_evidence_sha256) = 64",
            name="ck_recovery_plans_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id", "merchant_id"],
            ["incidents.incident_id", "incidents.merchant_id"],
            name="fk_recovery_plans_incident_merchant",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["merchant_id", "payment_id"],
            ["payment_projections.merchant_id", "payment_projections.payment_id"],
            name="fk_recovery_plans_payment_merchant",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("plan_id"),
        sa.UniqueConstraint(
            "merchant_id",
            "idempotency_key",
            name="uq_recovery_plans_merchant_idempotency",
        ),
        sa.UniqueConstraint(
            "plan_id",
            "merchant_id",
            name="uq_recovery_plans_identity_merchant",
        ),
        sa.UniqueConstraint(
            "plan_id",
            "incident_id",
            "merchant_id",
            name="uq_recovery_plans_plan_incident_merchant",
        ),
    )
    op.create_index(
        "ix_recovery_plans_merchant_created",
        "recovery_plans",
        ["merchant_id", "created_at"],
        unique=False,
    )

    op.create_table(
        "policy_results",
        sa.Column("policy_result_id", sa.String(length=80), nullable=False),
        sa.Column("plan_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("stage", sa.String(length=16), nullable=False),
        sa.Column("policy_result_sha256", sa.String(length=64), nullable=False),
        sa.Column("result_document", _json_type(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("stage = 'preview'", name="ck_policy_results_m4_stage"),
        sa.CheckConstraint(
            "length(policy_result_sha256) = 64",
            name="ck_policy_results_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["plan_id", "merchant_id"],
            ["recovery_plans.plan_id", "recovery_plans.merchant_id"],
            name="fk_policy_results_plan_merchant",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("policy_result_id"),
        sa.UniqueConstraint(
            "plan_id",
            "stage",
            name="uq_policy_results_plan_stage",
        ),
        sa.UniqueConstraint(
            "policy_result_id",
            "plan_id",
            "merchant_id",
            name="uq_policy_results_identity_plan_merchant",
        ),
    )
    op.create_index(
        "ix_policy_results_merchant_created",
        "policy_results",
        ["merchant_id", "created_at"],
        unique=False,
    )

    op.create_table(
        "approval_decisions",
        sa.Column("approval_id", sa.String(length=80), nullable=False),
        sa.Column("plan_id", sa.String(length=80), nullable=False),
        sa.Column("incident_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("policy_result_id", sa.String(length=80), nullable=False),
        sa.Column("plan_sha256", sa.String(length=64), nullable=False),
        sa.Column("policy_result_sha256", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.String(length=80), nullable=False),
        sa.Column("actor_type", sa.String(length=16), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("initial_status", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("idempotency_key", sa.String(length=80), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(request_sha256) = 64 AND length(plan_sha256) = 64 "
            "AND length(policy_result_sha256) = 64",
            name="ck_approval_decisions_sha256",
        ),
        sa.CheckConstraint(
            "actor_type = 'merchant'",
            name="ck_approval_decisions_actor_type",
        ),
        sa.CheckConstraint(
            "(decision = 'approve' AND initial_status = 'issued' "
            "AND token_hash IS NOT NULL AND length(token_hash) = 64 "
            "AND issued_at IS NOT NULL AND expires_at IS NOT NULL "
            "AND expires_at > issued_at) OR "
            "(decision = 'reject' AND initial_status = 'rejected' "
            "AND token_hash IS NULL AND issued_at IS NULL AND expires_at IS NULL)",
            name="ck_approval_decisions_lifecycle",
        ),
        sa.ForeignKeyConstraint(
            ["plan_id", "incident_id", "merchant_id"],
            [
                "recovery_plans.plan_id",
                "recovery_plans.incident_id",
                "recovery_plans.merchant_id",
            ],
            name="fk_approval_decisions_plan_incident_merchant",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["policy_result_id", "plan_id", "merchant_id"],
            [
                "policy_results.policy_result_id",
                "policy_results.plan_id",
                "policy_results.merchant_id",
            ],
            name="fk_approval_decisions_policy_plan_merchant",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("approval_id"),
        sa.UniqueConstraint("plan_id", name="uq_approval_decisions_plan"),
        sa.UniqueConstraint(
            "merchant_id",
            "idempotency_key",
            name="uq_approval_decisions_merchant_idempotency",
        ),
        sa.UniqueConstraint(
            "token_hash",
            name="uq_approval_decisions_token_hash",
        ),
        sa.UniqueConstraint(
            "approval_id",
            "plan_id",
            "merchant_id",
            name="uq_approval_decisions_identity_plan_merchant",
        ),
    )
    op.create_index(
        "ix_approval_decisions_merchant_decided",
        "approval_decisions",
        ["merchant_id", "decided_at"],
        unique=False,
    )

    op.create_table(
        "approval_token_consumptions",
        sa.Column("consumption_id", sa.String(length=80), nullable=False),
        sa.Column("approval_id", sa.String(length=80), nullable=False),
        sa.Column("plan_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("idempotency_key", sa.String(length=80), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(request_sha256) = 64",
            name="ck_approval_consumptions_request_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["approval_id", "plan_id", "merchant_id"],
            [
                "approval_decisions.approval_id",
                "approval_decisions.plan_id",
                "approval_decisions.merchant_id",
            ],
            name="fk_approval_consumptions_approval_plan_merchant",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("consumption_id"),
        sa.UniqueConstraint(
            "approval_id",
            name="uq_approval_consumptions_approval",
        ),
        sa.UniqueConstraint(
            "merchant_id",
            "idempotency_key",
            name="uq_approval_consumptions_merchant_idempotency",
        ),
    )
    op.create_index(
        "ix_approval_consumptions_merchant_time",
        "approval_token_consumptions",
        ["merchant_id", "consumed_at"],
        unique=False,
    )
    _create_immutable_recovery_evidence_triggers()


def _create_immutable_recovery_evidence_triggers() -> None:
    tables = (
        "recovery_plans",
        "policy_results",
        "approval_decisions",
        "approval_token_consumptions",
    )
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            """
            CREATE FUNCTION retryrail_reject_recovery_evidence_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'recovery evidence is immutable' USING ERRCODE = '55000';
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        for table in tables:
            op.execute(
                f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} "
                "FOR EACH ROW EXECUTE FUNCTION "
                "retryrail_reject_recovery_evidence_mutation();"
            )
    elif bind.dialect.name == "sqlite":
        for table in tables:
            op.execute(
                f"CREATE TRIGGER {table}_immutable_update BEFORE UPDATE ON {table} "
                "BEGIN SELECT RAISE(ABORT, 'recovery evidence is immutable'); END;"
            )
            op.execute(
                f"CREATE TRIGGER {table}_immutable_delete BEFORE DELETE ON {table} "
                "BEGIN SELECT RAISE(ABORT, 'recovery evidence is immutable'); END;"
            )


def downgrade() -> None:
    """Remove M4.3 records and immutable-evidence guards in dependency order."""

    tables = (
        "approval_token_consumptions",
        "approval_decisions",
        "policy_results",
        "recovery_plans",
    )
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in tables:
            op.execute(f"DROP TRIGGER IF EXISTS {table}_immutable ON {table}")
        op.execute("DROP FUNCTION IF EXISTS retryrail_reject_recovery_evidence_mutation()")
    elif bind.dialect.name == "sqlite":
        for table in tables:
            op.execute(f"DROP TRIGGER IF EXISTS {table}_immutable_update")
            op.execute(f"DROP TRIGGER IF EXISTS {table}_immutable_delete")

    op.drop_index(
        "ix_approval_consumptions_merchant_time",
        table_name="approval_token_consumptions",
    )
    op.drop_table("approval_token_consumptions")
    op.drop_index(
        "ix_approval_decisions_merchant_decided",
        table_name="approval_decisions",
    )
    op.drop_table("approval_decisions")
    op.drop_index("ix_policy_results_merchant_created", table_name="policy_results")
    op.drop_table("policy_results")
    op.drop_index("ix_recovery_plans_merchant_created", table_name="recovery_plans")
    op.drop_table("recovery_plans")
    op.drop_index(
        "ix_payment_recovery_controls_merchant_updated",
        table_name="payment_recovery_controls",
    )
    op.drop_table("payment_recovery_controls")
