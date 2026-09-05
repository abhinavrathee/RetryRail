"""Add immutable identifier-only trace lineage.

Revision ID: 0008_m8_trace_lineage
Revises: 0007_m6_model_incident_analysis
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import sqlalchemy as sa
from alembic import op

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

revision: str = "0008_m8_trace_lineage"
down_revision: str | None = "0007_m6_model_incident_analysis"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the append-only trace ledger and backfill all existing core entities."""

    op.create_table(
        "trace_links",
        sa.Column("trace_link_id", sa.String(length=80), nullable=False),
        sa.Column("trace_id", sa.String(length=32), nullable=False),
        sa.Column("span_id", sa.String(length=16), nullable=False),
        sa.Column("parent_span_id", sa.String(length=16), nullable=True),
        sa.Column("entity_type", sa.String(length=16), nullable=False),
        sa.Column("entity_id", sa.String(length=80), nullable=False),
        sa.Column("merchant_id", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(trace_id) = 32", name="ck_trace_links_trace_id"),
        sa.CheckConstraint("length(span_id) = 16", name="ck_trace_links_span_id"),
        sa.CheckConstraint(
            "parent_span_id IS NULL OR length(parent_span_id) = 16",
            name="ck_trace_links_parent_span_id",
        ),
        sa.CheckConstraint(
            "entity_type IN ('event', 'outbox', 'incident', 'plan', 'action')",
            name="ck_trace_links_entity_type",
        ),
        sa.PrimaryKeyConstraint("trace_link_id"),
        sa.UniqueConstraint("entity_type", "entity_id", name="uq_trace_links_entity"),
        sa.UniqueConstraint("trace_id", "span_id", name="uq_trace_links_trace_span"),
    )
    op.create_index(
        "ix_trace_links_merchant_trace",
        "trace_links",
        ["merchant_id", "trace_id"],
        unique=False,
    )
    _backfill()
    _create_immutable_trigger()


def downgrade() -> None:
    """Remove only the M8 correlation ledger."""

    _drop_immutable_trigger()
    op.drop_index("ix_trace_links_merchant_trace", table_name="trace_links")
    op.drop_table("trace_links")


def _backfill() -> None:
    bind = op.get_bind()
    links: list[dict[str, Any]] = []
    by_entity: dict[tuple[str, str], dict[str, Any]] = {}
    event_by_external_id: dict[tuple[str, str], dict[str, Any]] = {}

    events = bind.execute(
        sa.text(
            "SELECT internal_id, merchant_id, razorpay_event_id, created_at "
            "FROM payment_events ORDER BY created_at, internal_id"
        )
    ).mappings()
    for event in events:
        link = _link(
            entity_type="event",
            entity_id=str(event["internal_id"]),
            merchant_id=str(event["merchant_id"]),
            created_at=event["created_at"],
        )
        _remember(links, by_entity, link)
        event_by_external_id[(str(event["merchant_id"]), str(event["razorpay_event_id"]))] = link

    outbox_rows = bind.execute(
        sa.text(
            "SELECT outbox_id, event_internal_id, merchant_id, created_at "
            "FROM outbox_messages ORDER BY created_at, outbox_id"
        )
    ).mappings()
    for outbox in outbox_rows:
        parent = by_entity.get(("event", str(outbox["event_internal_id"])))
        _remember(
            links,
            by_entity,
            _link(
                entity_type="outbox",
                entity_id=str(outbox["outbox_id"]),
                merchant_id=str(outbox["merchant_id"]),
                created_at=outbox["created_at"],
                parent=parent,
            ),
        )

    incident_rows = bind.execute(
        sa.text(
            "SELECT incident_id, merchant_id, evidence_event_ids, created_at "
            "FROM incidents ORDER BY created_at, incident_id"
        )
    ).mappings()
    for incident in incident_rows:
        merchant_id = str(incident["merchant_id"])
        evidence_ids = _json_array(incident["evidence_event_ids"])
        parent = next(
            (
                event_by_external_id[(merchant_id, event_id)]
                for event_id in evidence_ids
                if (merchant_id, event_id) in event_by_external_id
            ),
            None,
        )
        _remember(
            links,
            by_entity,
            _link(
                entity_type="incident",
                entity_id=str(incident["incident_id"]),
                merchant_id=merchant_id,
                created_at=incident["created_at"],
                parent=parent,
            ),
        )

    plan_rows = bind.execute(
        sa.text(
            "SELECT plan_id, incident_id, merchant_id, created_at "
            "FROM recovery_plans ORDER BY created_at, plan_id"
        )
    ).mappings()
    for plan in plan_rows:
        parent = by_entity.get(("incident", str(plan["incident_id"])))
        _remember(
            links,
            by_entity,
            _link(
                entity_type="plan",
                entity_id=str(plan["plan_id"]),
                merchant_id=str(plan["merchant_id"]),
                created_at=plan["created_at"],
                parent=parent,
            ),
        )

    action_rows = bind.execute(
        sa.text(
            "SELECT action_id, plan_id, merchant_id, created_at "
            "FROM recovery_actions ORDER BY created_at, action_id"
        )
    ).mappings()
    for action in action_rows:
        parent = by_entity.get(("plan", str(action["plan_id"])))
        _remember(
            links,
            by_entity,
            _link(
                entity_type="action",
                entity_id=str(action["action_id"]),
                merchant_id=str(action["merchant_id"]),
                created_at=action["created_at"],
                parent=parent,
            ),
        )

    if links:
        trace_links = sa.table(
            "trace_links",
            sa.column("trace_link_id", sa.String()),
            sa.column("trace_id", sa.String()),
            sa.column("span_id", sa.String()),
            sa.column("parent_span_id", sa.String()),
            sa.column("entity_type", sa.String()),
            sa.column("entity_id", sa.String()),
            sa.column("merchant_id", sa.String()),
            sa.column("created_at", sa.DateTime(timezone=True)),
        )
        op.bulk_insert(trace_links, links)


def _link(
    *,
    entity_type: str,
    entity_id: str,
    merchant_id: str,
    created_at: datetime | str,
    parent: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "trace_link_id": _digest("link", entity_type, entity_id)[:80],
        "trace_id": (
            str(parent["trace_id"])
            if parent is not None
            else _digest("trace", merchant_id, entity_type, entity_id)[:32]
        ),
        "span_id": _digest("span", entity_type, entity_id)[:16],
        "parent_span_id": str(parent["span_id"]) if parent is not None else None,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "merchant_id": merchant_id,
        "created_at": _datetime(created_at),
    }


def _remember(
    links: list[dict[str, Any]],
    by_entity: dict[tuple[str, str], dict[str, Any]],
    link: dict[str, Any],
) -> None:
    links.append(link)
    by_entity[(str(link["entity_type"]), str(link["entity_id"]))] = link


def _json_array(value: object) -> tuple[str, ...]:
    decoded = json.loads(value) if isinstance(value, str) else value
    if not isinstance(decoded, list):
        return ()
    return tuple(item for item in decoded if isinstance(item, str))


def _datetime(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        return value
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _digest(*parts: str) -> str:
    material = "\x1f".join(("retryrail-trace-v1", *parts)).encode()
    return hashlib.sha256(material).hexdigest()


def _create_immutable_trigger() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            "CREATE TRIGGER trace_links_immutable BEFORE UPDATE OR DELETE ON trace_links "
            "FOR EACH ROW EXECUTE FUNCTION retryrail_reject_recovery_evidence_mutation();"
        )
    elif bind.dialect.name == "sqlite":
        op.execute(
            "CREATE TRIGGER trace_links_immutable_update BEFORE UPDATE ON trace_links "
            "BEGIN SELECT RAISE(ABORT, 'trace lineage is immutable'); END;"
        )
        op.execute(
            "CREATE TRIGGER trace_links_immutable_delete BEFORE DELETE ON trace_links "
            "BEGIN SELECT RAISE(ABORT, 'trace lineage is immutable'); END;"
        )


def _drop_immutable_trigger() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS trace_links_immutable ON trace_links")
    elif bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS trace_links_immutable_update")
        op.execute("DROP TRIGGER IF EXISTS trace_links_immutable_delete")
