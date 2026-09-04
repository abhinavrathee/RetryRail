"""Add crash-safe provider dispatch and sanitized Test Mode receipts.

Revision ID: 0006_m5_provider_dispatch
Revises: 0005_m4_rules_fallback
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_m5_provider_dispatch"
down_revision: str | None = "0005_m4_rules_fallback"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json_type() -> sa.types.TypeEngine[object]:
    return postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")


def upgrade() -> None:
    """Admit synthetic Test Mode actions and persist intent before network I/O."""

    _widen_action_target_constraint()
    op.create_table(
        "recovery_provider_dispatches",
        sa.Column("dispatch_id", sa.String(length=80), nullable=False),
        sa.Column("action_id", sa.String(length=80), nullable=False),
        sa.Column("plan_id", sa.String(length=80), nullable=False),
        sa.Column("incident_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("provider_target", sa.String(length=32), nullable=False),
        sa.Column("reference_id", sa.String(length=40), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("request_document", _json_type(), nullable=False),
        sa.Column("external_notifications_enabled", sa.Boolean(), nullable=False),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "provider_target IN ('deterministic_fake', 'razorpay_test_mode')",
            name="ck_provider_dispatches_target",
        ),
        sa.CheckConstraint(
            "length(request_sha256) = 64 AND external_notifications_enabled = false "
            "AND synthetic = true",
            name="ck_provider_dispatches_bounded_request",
        ),
        sa.ForeignKeyConstraint(
            ["action_id", "plan_id", "incident_id", "merchant_id"],
            [
                "recovery_actions.action_id",
                "recovery_actions.plan_id",
                "recovery_actions.incident_id",
                "recovery_actions.merchant_id",
            ],
            name="fk_provider_dispatches_action_scope",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("dispatch_id"),
        sa.UniqueConstraint("action_id", name="uq_provider_dispatches_action"),
        sa.UniqueConstraint(
            "provider_target",
            "reference_id",
            name="uq_provider_dispatches_target_reference",
        ),
        sa.UniqueConstraint(
            "dispatch_id",
            "action_id",
            name="uq_provider_dispatches_identity_action",
        ),
    )
    op.create_index(
        "ix_provider_dispatches_merchant_time",
        "recovery_provider_dispatches",
        ["merchant_id", "prepared_at"],
        unique=False,
    )

    op.create_table(
        "recovery_provider_receipts",
        sa.Column("provider_receipt_id", sa.String(length=80), nullable=False),
        sa.Column("dispatch_id", sa.String(length=80), nullable=False),
        sa.Column("action_id", sa.String(length=80), nullable=False),
        sa.Column("plan_id", sa.String(length=80), nullable=False),
        sa.Column("incident_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("provider_target", sa.String(length=32), nullable=False),
        sa.Column("provider_action_id", sa.String(length=80), nullable=False),
        sa.Column("reference_id", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("amount_subunits", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("short_url", sa.String(length=500), nullable=True),
        sa.Column("provider_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verification_source", sa.String(length=32), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("response_sha256", sa.String(length=64), nullable=False),
        sa.Column("response_document", _json_type(), nullable=False),
        sa.Column("external_notifications_enabled", sa.Boolean(), nullable=False),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "provider_target IN ('deterministic_fake', 'razorpay_test_mode')",
            name="ck_provider_receipts_target",
        ),
        sa.CheckConstraint(
            "status IN ('created', 'partially_paid', 'paid', 'expired', 'cancelled')",
            name="ck_provider_receipts_status",
        ),
        sa.CheckConstraint(
            "verification_source IN ('create_response', 'reference_lookup')",
            name="ck_provider_receipts_verification_source",
        ),
        sa.CheckConstraint(
            "length(request_sha256) = 64 AND length(response_sha256) = 64 "
            "AND amount_subunits > 0 AND external_notifications_enabled = false "
            "AND synthetic = true",
            name="ck_provider_receipts_evidence",
        ),
        sa.CheckConstraint(
            "provider_created_at <= verified_at",
            name="ck_provider_receipts_time_order",
        ),
        sa.CheckConstraint(
            "provider_target != 'razorpay_test_mode' "
            "OR (short_url IS NOT NULL AND short_url LIKE 'https://%')",
            name="ck_provider_receipts_test_mode_url",
        ),
        sa.ForeignKeyConstraint(
            ["dispatch_id", "action_id"],
            [
                "recovery_provider_dispatches.dispatch_id",
                "recovery_provider_dispatches.action_id",
            ],
            name="fk_provider_receipts_dispatch_action",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["action_id", "plan_id", "incident_id", "merchant_id"],
            [
                "recovery_actions.action_id",
                "recovery_actions.plan_id",
                "recovery_actions.incident_id",
                "recovery_actions.merchant_id",
            ],
            name="fk_provider_receipts_action_scope",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("provider_receipt_id"),
        sa.UniqueConstraint("action_id", name="uq_provider_receipts_action"),
        sa.UniqueConstraint(
            "provider_target",
            "provider_action_id",
            name="uq_provider_receipts_provider_action",
        ),
    )
    op.create_index(
        "ix_provider_receipts_merchant_time",
        "recovery_provider_receipts",
        ["merchant_id", "verified_at"],
        unique=False,
    )
    _create_immutable_triggers(
        ("recovery_provider_dispatches", "recovery_provider_receipts")
    )


def _widen_action_target_constraint() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        _drop_immutable_triggers(("recovery_actions",))
    with op.batch_alter_table("recovery_actions") as batch:
        batch.drop_constraint("ck_recovery_actions_m4_fake_only", type_="check")
        batch.create_check_constraint(
            "ck_recovery_actions_execution_target",
            "((execution_target = 'deterministic_fake' "
            "AND execution_side_effect = 'simulated_external_mutation') OR "
            "(execution_target = 'razorpay_test_mode' "
            "AND execution_side_effect = 'razorpay_test_mode_mutation')) "
            "AND synthetic = true",
        )
    if bind.dialect.name == "sqlite":
        _create_immutable_triggers(("recovery_actions",))


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
    """Remove M5 provider evidence only when no Test Mode action would be lost."""

    bind = op.get_bind()
    real_action_count = int(
        bind.execute(
            sa.text(
                "SELECT COUNT(*) FROM recovery_actions "
                "WHERE execution_target = 'razorpay_test_mode'"
            )
        ).scalar_one()
    )
    if real_action_count:
        msg = "cannot downgrade M5 while Razorpay Test Mode action evidence exists"
        raise RuntimeError(msg)

    provider_tables = ("recovery_provider_receipts", "recovery_provider_dispatches")
    _drop_immutable_triggers(provider_tables)
    op.drop_index(
        "ix_provider_receipts_merchant_time",
        table_name="recovery_provider_receipts",
    )
    op.drop_table("recovery_provider_receipts")
    op.drop_index(
        "ix_provider_dispatches_merchant_time",
        table_name="recovery_provider_dispatches",
    )
    op.drop_table("recovery_provider_dispatches")

    if bind.dialect.name == "sqlite":
        _drop_immutable_triggers(("recovery_actions",))
    with op.batch_alter_table("recovery_actions") as batch:
        batch.drop_constraint("ck_recovery_actions_execution_target", type_="check")
        batch.create_check_constraint(
            "ck_recovery_actions_m4_fake_only",
            "execution_target = 'deterministic_fake' "
            "AND execution_side_effect = 'simulated_external_mutation' "
            "AND synthetic = true",
        )
    if bind.dialect.name == "sqlite":
        _create_immutable_triggers(("recovery_actions",))
