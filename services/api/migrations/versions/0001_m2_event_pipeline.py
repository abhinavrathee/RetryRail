"""Create the durable authenticated event pipeline.

Revision ID: 0001_m2_event_pipeline
Revises:
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_m2_event_pipeline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json_type() -> sa.types.TypeEngine[object]:
    return postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")


def upgrade() -> None:
    """Create immutable events, a transactional outbox and payment projections."""

    op.create_table(
        "payment_events",
        sa.Column("internal_id", sa.String(length=36), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("razorpay_event_id", sa.String(length=80), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("signature_status", sa.String(length=16), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("payment_id", sa.String(length=80), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("sanitized_payload", _json_type(), nullable=False),
        sa.Column("normalized_event", _json_type(), nullable=False),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(payload_sha256) = 64",
            name="ck_payment_events_payload_sha256",
        ),
        sa.CheckConstraint(
            "schema_version = '1.0.0'",
            name="ck_payment_events_schema_version",
        ),
        sa.CheckConstraint(
            "signature_status = 'verified'",
            name="ck_payment_events_signature_verified",
        ),
        sa.CheckConstraint(
            "event_type IN ('payment.failed', 'payment.authorized', 'payment.captured')",
            name="ck_payment_events_event_type",
        ),
        sa.PrimaryKeyConstraint("internal_id"),
        sa.UniqueConstraint(
            "merchant_id",
            "razorpay_event_id",
            name="uq_payment_events_merchant_event",
        ),
    )
    op.create_index(
        "ix_payment_events_merchant_received",
        "payment_events",
        ["merchant_id", "received_at"],
        unique=False,
    )

    op.create_table(
        "outbox_messages",
        sa.Column("outbox_id", sa.String(length=36), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("event_internal_id", sa.String(length=36), nullable=False),
        sa.Column("topic", sa.String(length=80), nullable=False),
        sa.Column("payload", _json_type(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=24), server_default="pending", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("max_attempts", sa.Integer(), server_default="5", nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed_by", sa.String(length=80), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=80), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "attempts >= 0",
            name="ck_outbox_messages_attempts_nonnegative",
        ),
        sa.CheckConstraint(
            "max_attempts > 0",
            name="ck_outbox_messages_max_attempts_positive",
        ),
        sa.CheckConstraint(
            "attempts <= max_attempts",
            name="ck_outbox_messages_attempts_bounded",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'retry', 'completed', 'dead_letter')",
            name="ck_outbox_messages_status",
        ),
        sa.ForeignKeyConstraint(
            ["event_internal_id"],
            ["payment_events.internal_id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("outbox_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_outbox_messages_idempotency_key"),
        sa.UniqueConstraint(
            "event_internal_id",
            "topic",
            name="uq_outbox_messages_event_topic",
        ),
    )
    op.create_index(
        "ix_outbox_messages_claim",
        "outbox_messages",
        ["status", "available_at", "created_at"],
        unique=False,
    )

    op.create_table(
        "payment_projections",
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("payment_id", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("state_rank", sa.Integer(), nullable=False),
        sa.Column("amount_subunits", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("method", sa.String(length=24), nullable=False),
        sa.Column("issuer", sa.String(length=80), nullable=True),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        sa.Column("last_event_internal_id", sa.String(length=36), nullable=False),
        sa.Column("state_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_processed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.CheckConstraint(
            "amount_subunits > 0",
            name="ck_payment_projections_amount_positive",
        ),
        sa.CheckConstraint(
            "(status = 'failed' AND state_rank = 1) OR "
            "(status = 'authorized' AND state_rank = 2) OR "
            "(status = 'captured' AND state_rank = 3)",
            name="ck_payment_projections_status_rank",
        ),
        sa.ForeignKeyConstraint(
            ["last_event_internal_id"],
            ["payment_events.internal_id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("merchant_id", "payment_id"),
    )
    op.create_index(
        "ix_payment_projections_merchant_status",
        "payment_projections",
        ["merchant_id", "status"],
        unique=False,
    )

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            """
            CREATE FUNCTION retryrail_reject_payment_event_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'payment_events are immutable' USING ERRCODE = '55000';
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        op.execute(
            """
            CREATE TRIGGER payment_events_immutable
            BEFORE UPDATE OR DELETE ON payment_events
            FOR EACH ROW EXECUTE FUNCTION retryrail_reject_payment_event_mutation();
            """
        )
    elif bind.dialect.name == "sqlite":
        op.execute(
            """
            CREATE TRIGGER payment_events_immutable_update
            BEFORE UPDATE ON payment_events
            BEGIN SELECT RAISE(ABORT, 'payment_events are immutable'); END;
            """
        )
        op.execute(
            """
            CREATE TRIGGER payment_events_immutable_delete
            BEFORE DELETE ON payment_events
            BEGIN SELECT RAISE(ABORT, 'payment_events are immutable'); END;
            """
        )


def downgrade() -> None:
    """Remove the M2 pipeline in dependency order."""

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS payment_events_immutable ON payment_events")
        op.execute("DROP FUNCTION IF EXISTS retryrail_reject_payment_event_mutation()")
    elif bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS payment_events_immutable_update")
        op.execute("DROP TRIGGER IF EXISTS payment_events_immutable_delete")

    op.drop_index("ix_payment_projections_merchant_status", table_name="payment_projections")
    op.drop_table("payment_projections")
    op.drop_index("ix_outbox_messages_claim", table_name="outbox_messages")
    op.drop_table("outbox_messages")
    op.drop_index("ix_payment_events_merchant_received", table_name="payment_events")
    op.drop_table("payment_events")
