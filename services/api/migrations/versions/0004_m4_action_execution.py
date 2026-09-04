"""Create execute-once actions and append-only transition receipts.

Revision ID: 0004_m4_action_execution
Revises: 0003_m4_preview_approval
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_m4_action_execution"
down_revision: str | None = "0003_m4_preview_approval"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json_type() -> sa.types.TypeEngine[object]:
    return postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")


def upgrade() -> None:
    """Admit execution policy evidence and create the M4.4 action ledger."""

    _widen_policy_stage_constraint()
    op.create_table(
        "recovery_actions",
        sa.Column("action_id", sa.String(length=80), nullable=False),
        sa.Column("plan_id", sa.String(length=80), nullable=False),
        sa.Column("incident_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("payment_id", sa.String(length=80), nullable=False),
        sa.Column("approval_id", sa.String(length=80), nullable=False),
        sa.Column("preview_policy_result_id", sa.String(length=80), nullable=False),
        sa.Column("execution_policy_result_id", sa.String(length=80), nullable=True),
        sa.Column("plan_sha256", sa.String(length=64), nullable=False),
        sa.Column("template", sa.String(length=40), nullable=False),
        sa.Column("template_version", sa.String(length=40), nullable=False),
        sa.Column("execution_target", sa.String(length=32), nullable=False),
        sa.Column("execution_side_effect", sa.String(length=40), nullable=False),
        sa.Column("amount_subunits", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("reference_id", sa.String(length=80), nullable=False),
        sa.Column("idempotency_key", sa.String(length=80), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("request_document", _json_type(), nullable=False),
        sa.Column("external_notifications_enabled", sa.Boolean(), nullable=False),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(plan_sha256) = 64 AND length(request_sha256) = 64",
            name="ck_recovery_actions_sha256",
        ),
        sa.CheckConstraint(
            "template = 'standard_payment_link' AND template_version = 'standard_payment_link_v1'",
            name="ck_recovery_actions_template",
        ),
        sa.CheckConstraint(
            "execution_target = 'deterministic_fake' "
            "AND execution_side_effect = 'simulated_external_mutation' "
            "AND synthetic = true",
            name="ck_recovery_actions_m4_fake_only",
        ),
        sa.CheckConstraint(
            "amount_subunits > 0 AND external_notifications_enabled = false",
            name="ck_recovery_actions_bounded_effect",
        ),
        sa.ForeignKeyConstraint(
            ["plan_id", "incident_id", "merchant_id"],
            [
                "recovery_plans.plan_id",
                "recovery_plans.incident_id",
                "recovery_plans.merchant_id",
            ],
            name="fk_recovery_actions_plan_incident_merchant",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["approval_id", "plan_id", "merchant_id"],
            [
                "approval_decisions.approval_id",
                "approval_decisions.plan_id",
                "approval_decisions.merchant_id",
            ],
            name="fk_recovery_actions_approval_plan_merchant",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["preview_policy_result_id", "plan_id", "merchant_id"],
            [
                "policy_results.policy_result_id",
                "policy_results.plan_id",
                "policy_results.merchant_id",
            ],
            name="fk_recovery_actions_preview_policy_plan_merchant",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["execution_policy_result_id", "plan_id", "merchant_id"],
            [
                "policy_results.policy_result_id",
                "policy_results.plan_id",
                "policy_results.merchant_id",
            ],
            name="fk_recovery_actions_execution_policy_plan_merchant",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("action_id"),
        sa.UniqueConstraint("plan_id", name="uq_recovery_actions_plan"),
        sa.UniqueConstraint("approval_id", name="uq_recovery_actions_approval"),
        sa.UniqueConstraint(
            "merchant_id",
            "idempotency_key",
            name="uq_recovery_actions_merchant_idempotency",
        ),
        sa.UniqueConstraint(
            "merchant_id",
            "reference_id",
            name="uq_recovery_actions_merchant_reference",
        ),
        sa.UniqueConstraint(
            "action_id",
            "plan_id",
            "incident_id",
            "merchant_id",
            name="uq_recovery_actions_identity_scope",
        ),
    )
    op.create_index(
        "ix_recovery_actions_merchant_created",
        "recovery_actions",
        ["merchant_id", "created_at"],
        unique=False,
    )

    op.create_table(
        "recovery_action_transitions",
        sa.Column("transition_id", sa.String(length=80), nullable=False),
        sa.Column("action_id", sa.String(length=80), nullable=False),
        sa.Column("plan_id", sa.String(length=80), nullable=False),
        sa.Column("incident_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("prior_state", sa.String(length=32), nullable=True),
        sa.Column("new_state", sa.String(length=32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=32), nullable=False),
        sa.Column("reason_code", sa.String(length=80), nullable=False),
        sa.Column("provider_action_id", sa.String(length=80), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_document", _json_type(), nullable=True),
        sa.Column("response_document", _json_type(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("sequence > 0", name="ck_action_transitions_sequence"),
        sa.CheckConstraint(
            "new_state IN ('previewed', 'awaiting_approval', 'approved', 'rejected', "
            "'expired', 'executing', 'succeeded', 'failed', "
            "'reconciliation_required')",
            name="ck_action_transitions_new_state",
        ),
        sa.CheckConstraint(
            "prior_state IS NULL OR prior_state IN ('previewed', 'awaiting_approval', "
            "'approved', 'rejected', 'expired', 'executing', 'succeeded', 'failed', "
            "'reconciliation_required')",
            name="ck_action_transitions_prior_state",
        ),
        sa.ForeignKeyConstraint(
            ["action_id", "plan_id", "incident_id", "merchant_id"],
            [
                "recovery_actions.action_id",
                "recovery_actions.plan_id",
                "recovery_actions.incident_id",
                "recovery_actions.merchant_id",
            ],
            name="fk_action_transitions_action_scope",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("transition_id"),
        sa.UniqueConstraint(
            "action_id",
            "sequence",
            name="uq_action_transitions_action_sequence",
        ),
    )
    op.create_index(
        "ix_action_transitions_merchant_time",
        "recovery_action_transitions",
        ["merchant_id", "occurred_at"],
        unique=False,
    )

    op.create_table(
        "recovery_reconciliations",
        sa.Column("reconciliation_id", sa.String(length=80), nullable=False),
        sa.Column("action_id", sa.String(length=80), nullable=False),
        sa.Column("plan_id", sa.String(length=80), nullable=False),
        sa.Column("incident_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("idempotency_key", sa.String(length=80), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(request_sha256) = 64",
            name="ck_recovery_reconciliations_request_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["action_id", "plan_id", "incident_id", "merchant_id"],
            [
                "recovery_actions.action_id",
                "recovery_actions.plan_id",
                "recovery_actions.incident_id",
                "recovery_actions.merchant_id",
            ],
            name="fk_recovery_reconciliations_action_scope",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("reconciliation_id"),
        sa.UniqueConstraint(
            "action_id",
            name="uq_recovery_reconciliations_action",
        ),
        sa.UniqueConstraint(
            "merchant_id",
            "idempotency_key",
            name="uq_recovery_reconciliations_merchant_idempotency",
        ),
    )
    op.create_index(
        "ix_recovery_reconciliations_merchant_time",
        "recovery_reconciliations",
        ["merchant_id", "created_at"],
        unique=False,
    )
    _create_immutable_triggers(
        (
            "recovery_actions",
            "recovery_action_transitions",
            "recovery_reconciliations",
        )
    )


def _widen_policy_stage_constraint() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        _drop_immutable_triggers(("policy_results",))
    with op.batch_alter_table("policy_results") as batch:
        batch.drop_constraint("ck_policy_results_m4_stage", type_="check")
        batch.create_check_constraint(
            "ck_policy_results_m4_stage",
            "stage IN ('preview', 'execution')",
        )
    if bind.dialect.name == "sqlite":
        _create_immutable_triggers(("policy_results",))


def _create_immutable_triggers(tables: tuple[str, ...]) -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
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


def _drop_immutable_triggers(tables: tuple[str, ...]) -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in tables:
            op.execute(f"DROP TRIGGER IF EXISTS {table}_immutable ON {table}")
    elif bind.dialect.name == "sqlite":
        for table in tables:
            op.execute(f"DROP TRIGGER IF EXISTS {table}_immutable_update")
            op.execute(f"DROP TRIGGER IF EXISTS {table}_immutable_delete")


def downgrade() -> None:
    """Remove M4.4 action evidence and restore the preview-only policy stage."""

    action_tables = (
        "recovery_reconciliations",
        "recovery_action_transitions",
        "recovery_actions",
    )
    _drop_immutable_triggers(action_tables)
    op.drop_index(
        "ix_recovery_reconciliations_merchant_time",
        table_name="recovery_reconciliations",
    )
    op.drop_table("recovery_reconciliations")
    op.drop_index(
        "ix_action_transitions_merchant_time",
        table_name="recovery_action_transitions",
    )
    op.drop_table("recovery_action_transitions")
    op.drop_index(
        "ix_recovery_actions_merchant_created",
        table_name="recovery_actions",
    )
    op.drop_table("recovery_actions")

    _drop_immutable_triggers(("policy_results",))
    op.execute("DELETE FROM policy_results WHERE stage = 'execution'")
    with op.batch_alter_table("policy_results") as batch:
        batch.drop_constraint("ck_policy_results_m4_stage", type_="check")
        batch.create_check_constraint(
            "ck_policy_results_m4_stage",
            "stage = 'preview'",
        )
    _create_immutable_triggers(("policy_results",))
