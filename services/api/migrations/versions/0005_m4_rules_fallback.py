"""Persist immutable deterministic incident briefs.

Revision ID: 0005_m4_rules_fallback
Revises: 0004_m4_action_execution
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_m4_rules_fallback"
down_revision: str | None = "0004_m4_action_execution"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json_type() -> sa.types.TypeEngine[object]:
    return postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")


def upgrade() -> None:
    """Create the content-addressed, append-only rules-fallback evidence."""

    op.create_table(
        "rules_based_incident_briefs",
        sa.Column("brief_id", sa.String(length=80), nullable=False),
        sa.Column("incident_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("source_snapshot_sha256", sa.String(length=64), nullable=False),
        sa.Column("brief_sha256", sa.String(length=64), nullable=False),
        sa.Column("brief_document", _json_type(), nullable=False),
        sa.Column("analyst_mode", sa.String(length=32), nullable=False),
        sa.Column("model_status", sa.String(length=16), nullable=False),
        sa.Column("fallback_used", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(source_snapshot_sha256) = 64 AND length(brief_sha256) = 64",
            name="ck_rules_briefs_sha256",
        ),
        sa.CheckConstraint(
            "analyst_mode = 'deterministic_rules' AND model_status = 'unavailable' "
            "AND fallback_used = true",
            name="ck_rules_briefs_fallback_mode",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id", "merchant_id"],
            ["incidents.incident_id", "incidents.merchant_id"],
            name="fk_rules_briefs_incident_merchant",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("brief_id"),
        sa.UniqueConstraint(
            "incident_id",
            "source_snapshot_sha256",
            name="uq_rules_briefs_incident_snapshot",
        ),
    )
    op.create_index(
        "ix_rules_briefs_merchant_created",
        "rules_based_incident_briefs",
        ["merchant_id", "created_at"],
        unique=False,
    )
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            "CREATE TRIGGER rules_based_incident_briefs_immutable "
            "BEFORE UPDATE OR DELETE ON rules_based_incident_briefs FOR EACH ROW "
            "EXECUTE FUNCTION retryrail_reject_recovery_evidence_mutation();"
        )
    elif bind.dialect.name == "sqlite":
        op.execute(
            "CREATE TRIGGER rules_based_incident_briefs_immutable_update "
            "BEFORE UPDATE ON rules_based_incident_briefs "
            "BEGIN SELECT RAISE(ABORT, 'recovery evidence is immutable'); END;"
        )
        op.execute(
            "CREATE TRIGGER rules_based_incident_briefs_immutable_delete "
            "BEFORE DELETE ON rules_based_incident_briefs "
            "BEGIN SELECT RAISE(ABORT, 'recovery evidence is immutable'); END;"
        )


def downgrade() -> None:
    """Remove only M4.5 deterministic brief evidence."""

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS rules_based_incident_briefs_immutable "
            "ON rules_based_incident_briefs"
        )
    elif bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS rules_based_incident_briefs_immutable_update")
        op.execute("DROP TRIGGER IF EXISTS rules_based_incident_briefs_immutable_delete")
    op.drop_index(
        "ix_rules_briefs_merchant_created",
        table_name="rules_based_incident_briefs",
    )
    op.drop_table("rules_based_incident_briefs")
