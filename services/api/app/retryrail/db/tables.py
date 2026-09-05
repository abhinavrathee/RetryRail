"""SQLAlchemy tables for durable event, incident and recovery evidence."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def utc_now() -> datetime:
    """Return an aware UTC timestamp for application-generated writes."""

    return datetime.now(tz=UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Store UTC timestamps and restore SQLite's otherwise-naive results."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        """Reject naive timestamps and normalize aware values to UTC."""

        del dialect
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            msg = "database timestamps must be timezone-aware"
            raise ValueError(msg)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        """Return an aware UTC value for every supported dialect."""

        del dialect
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


JSON_DOCUMENT = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    """Declarative metadata root used by Alembic and repositories."""


class TraceLinkRecord(Base):
    """Immutable, identifier-only lineage across asynchronous domain stages."""

    __tablename__ = "trace_links"
    __table_args__ = (
        CheckConstraint("length(trace_id) = 32", name="ck_trace_links_trace_id"),
        CheckConstraint("length(span_id) = 16", name="ck_trace_links_span_id"),
        CheckConstraint(
            "parent_span_id IS NULL OR length(parent_span_id) = 16",
            name="ck_trace_links_parent_span_id",
        ),
        CheckConstraint(
            "entity_type IN ('event', 'outbox', 'incident', 'plan', 'action')",
            name="ck_trace_links_entity_type",
        ),
        UniqueConstraint(
            "entity_type",
            "entity_id",
            name="uq_trace_links_entity",
        ),
        UniqueConstraint(
            "trace_id",
            "span_id",
            name="uq_trace_links_trace_span",
        ),
        Index("ix_trace_links_merchant_trace", "merchant_id", "trace_id"),
    )

    trace_link_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(32), nullable=False)
    span_id: Mapped[str] = mapped_column(String(16), nullable=False)
    parent_span_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    entity_type: Mapped[str] = mapped_column(String(16), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(80), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)


class PaymentEventRecord(Base):
    """Immutable authenticated event with sanitized and normalized forms."""

    __tablename__ = "payment_events"
    __table_args__ = (
        UniqueConstraint(
            "merchant_id",
            "razorpay_event_id",
            name="uq_payment_events_merchant_event",
        ),
        CheckConstraint("length(payload_sha256) = 64", name="ck_payment_events_payload_sha256"),
        CheckConstraint("schema_version = '1.0.0'", name="ck_payment_events_schema_version"),
        CheckConstraint(
            "signature_status = 'verified'",
            name="ck_payment_events_signature_verified",
        ),
        CheckConstraint(
            "event_type IN ('payment.failed', 'payment.authorized', 'payment.captured')",
            name="ck_payment_events_event_type",
        ),
        Index("ix_payment_events_merchant_received", "merchant_id", "received_at"),
    )

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    razorpay_event_id: Mapped[str] = mapped_column(String(80), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    signature_status: Mapped[str] = mapped_column(String(16), nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    payment_id: Mapped[str] = mapped_column(String(80), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sanitized_payload: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    normalized_event: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)


class OutboxMessageRecord(Base):
    """Durable process request committed atomically with its source event."""

    __tablename__ = "outbox_messages"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_outbox_messages_idempotency_key"),
        UniqueConstraint(
            "event_internal_id",
            "topic",
            name="uq_outbox_messages_event_topic",
        ),
        CheckConstraint("attempts >= 0", name="ck_outbox_messages_attempts_nonnegative"),
        CheckConstraint("max_attempts > 0", name="ck_outbox_messages_max_attempts_positive"),
        CheckConstraint(
            "attempts <= max_attempts",
            name="ck_outbox_messages_attempts_bounded",
        ),
        CheckConstraint(
            "status IN ('pending', 'processing', 'retry', 'completed', 'dead_letter')",
            name="ck_outbox_messages_status",
        ),
        Index("ix_outbox_messages_claim", "status", "available_at", "created_at"),
    )

    outbox_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    event_internal_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("payment_events.internal_id", ondelete="RESTRICT"),
        nullable=False,
    )
    topic: Mapped[str] = mapped_column(String(80), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    available_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    claimed_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)


class PaymentProjectionRecord(Base):
    """Latest monotonic payment state derived only from immutable events."""

    __tablename__ = "payment_projections"
    __table_args__ = (
        CheckConstraint("amount_subunits > 0", name="ck_payment_projections_amount_positive"),
        CheckConstraint(
            "(status = 'failed' AND state_rank = 1) OR "
            "(status = 'authorized' AND state_rank = 2) OR "
            "(status = 'captured' AND state_rank = 3)",
            name="ck_payment_projections_status_rank",
        ),
        Index("ix_payment_projections_merchant_status", "merchant_id", "status"),
    )

    merchant_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    payment_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    state_rank: Mapped[int] = mapped_column(Integer, nullable=False)
    amount_subunits: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    method: Mapped[str] = mapped_column(String(24), nullable=False)
    issuer: Mapped[str | None] = mapped_column(String(80), nullable=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    last_event_internal_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("payment_events.internal_id", ondelete="RESTRICT"),
        nullable=False,
    )
    state_changed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    last_processed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AggregateWindowRecord(Base):
    """Materialized, exactly reconcilable detector cohort window."""

    __tablename__ = "aggregate_windows"
    __table_args__ = (
        CheckConstraint("attempts > 0", name="ck_aggregate_windows_attempts_positive"),
        CheckConstraint(
            "successes >= 0 AND failures >= 0 AND successes + failures = attempts",
            name="ck_aggregate_windows_outcomes_reconcile",
        ),
        CheckConstraint(
            "gmv_subunits > 0 AND failed_gmv_subunits >= 0 AND failed_gmv_subunits <= gmv_subunits",
            name="ck_aggregate_windows_money_reconcile",
        ),
        CheckConstraint(
            "window_end > window_start",
            name="ck_aggregate_windows_time_order",
        ),
        Index(
            "ix_aggregate_windows_merchant_time",
            "merchant_id",
            "window_start",
        ),
    )

    merchant_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    detector_version: Mapped[str] = mapped_column(String(80), primary_key=True)
    cohort_key: Mapped[str] = mapped_column(String(200), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(UTCDateTime(), primary_key=True)
    window_end: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    cohort: Mapped[list[dict[str, Any]]] = mapped_column(JSON_DOCUMENT, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    successes: Mapped[int] = mapped_column(Integer, nullable=False)
    failures: Mapped[int] = mapped_column(Integer, nullable=False)
    gmv_subunits: Mapped[int] = mapped_column(BigInteger, nullable=False)
    failed_gmv_subunits: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    source_watermark: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)


class IncidentRecord(Base):
    """Durable merged degradation episode with its peak evidence snapshot."""

    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'resolved')",
            name="ck_incidents_status",
        ),
        CheckConstraint(
            "(status = 'open' AND resolved_at IS NULL) OR "
            "(status = 'resolved' AND resolved_at IS NOT NULL)",
            name="ck_incidents_resolution_state",
        ),
        CheckConstraint(
            "last_observed_at >= opened_at AND "
            "(resolved_at IS NULL OR resolved_at >= last_observed_at)",
            name="ck_incidents_time_order",
        ),
        CheckConstraint(
            "gmv_at_risk_subunits >= 0",
            name="ck_incidents_at_risk_nonnegative",
        ),
        CheckConstraint(
            "length(detector_config_sha256) = 64",
            name="ck_incidents_detector_config_sha256",
        ),
        Index("ix_incidents_merchant_opened", "merchant_id", "opened_at"),
        UniqueConstraint(
            "incident_id",
            "merchant_id",
            name="uq_incidents_identity_merchant",
        ),
        Index(
            "uq_incidents_one_active_cohort",
            "merchant_id",
            "detector_cohort_key",
            unique=True,
            postgresql_where=text("status = 'open'"),
            sqlite_where=text("status = 'open'"),
        ),
    )

    incident_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(80), nullable=False)
    detector_config_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    detector_cohort_key: Mapped[str] = mapped_column(String(200), nullable=False)
    detector_cohort: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON_DOCUMENT,
        nullable=False,
    )
    affected_cohort: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON_DOCUMENT,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    opened_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    peak_statistics: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    diagnosis: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    evidence_event_ids: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, nullable=False)
    gmv_at_risk_subunits: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    action_eligible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)


class IncidentObservationRecord(Base):
    """Append-only passing detector observation linked to one incident."""

    __tablename__ = "incident_observations"
    __table_args__ = (
        ForeignKeyConstraint(
            ("incident_id", "merchant_id"),
            ("incidents.incident_id", "incidents.merchant_id"),
            name="fk_incident_observations_incident_merchant",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "incident_id",
            "evaluated_at",
            name="uq_incident_observations_incident_time",
        ),
        CheckConstraint(
            "length(detector_config_sha256) = 64",
            name="ck_incident_observations_detector_config_sha256",
        ),
        Index(
            "ix_incident_observations_incident_time",
            "incident_id",
            "evaluated_at",
        ),
    )

    observation_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(80), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(80), nullable=False)
    detector_config_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    statistics: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    evidence_event_ids: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)


class DetectionRunRecord(Base):
    """Append-only idempotent receipt for one source-event/config snapshot."""

    __tablename__ = "detection_runs"
    __table_args__ = (
        UniqueConstraint(
            "merchant_id",
            "detector_config_sha256",
            "source_events_sha256",
            name="uq_detection_runs_source_snapshot",
        ),
        CheckConstraint(
            "length(detector_config_sha256) = 64 AND length(source_events_sha256) = 64",
            name="ck_detection_runs_sha256",
        ),
        CheckConstraint(
            "attempt_count >= 0 AND aggregate_count >= 0 AND incident_count >= 0",
            name="ck_detection_runs_counts_nonnegative",
        ),
        Index("ix_detection_runs_merchant_created", "merchant_id", "created_at"),
    )

    run_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(80), nullable=False)
    detector_config_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    source_events_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    source_watermark: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    partition_started_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    partition_ended_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False)
    aggregate_count: Mapped[int] = mapped_column(Integer, nullable=False)
    incident_count: Mapped[int] = mapped_column(Integer, nullable=False)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)


class PaymentRecoveryControlRecord(Base):
    """Current first-party safety facts used to assemble recovery policy context."""

    __tablename__ = "payment_recovery_controls"
    __table_args__ = (
        ForeignKeyConstraint(
            ("merchant_id", "payment_id"),
            ("payment_projections.merchant_id", "payment_projections.payment_id"),
            name="fk_payment_recovery_controls_projection",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "prior_action_attempts >= 0 AND prior_action_attempts <= 3",
            name="ck_payment_recovery_controls_attempts",
        ),
        CheckConstraint("version > 0", name="ck_payment_recovery_controls_version"),
        CheckConstraint(
            "source = 'synthetic_fixture_default'",
            name="ck_payment_recovery_controls_m4_source",
        ),
        Index(
            "ix_payment_recovery_controls_merchant_updated",
            "merchant_id",
            "updated_at",
        ),
    )

    merchant_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    payment_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    contact_consent_verified: Mapped[bool] = mapped_column(Boolean, nullable=False)
    customer_opted_out: Mapped[bool] = mapped_column(Boolean, nullable=False)
    already_recovered: Mapped[bool] = mapped_column(Boolean, nullable=False)
    prior_action_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    last_action_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class RecoveryPlanRecord(Base):
    """Immutable merchant-scoped recovery plan and its canonical preview."""

    __tablename__ = "recovery_plans"
    __table_args__ = (
        ForeignKeyConstraint(
            ("incident_id", "merchant_id"),
            ("incidents.incident_id", "incidents.merchant_id"),
            name="fk_recovery_plans_incident_merchant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ("merchant_id", "payment_id"),
            ("payment_projections.merchant_id", "payment_projections.payment_id"),
            name="fk_recovery_plans_payment_merchant",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "merchant_id",
            "idempotency_key",
            name="uq_recovery_plans_merchant_idempotency",
        ),
        UniqueConstraint(
            "plan_id",
            "merchant_id",
            name="uq_recovery_plans_identity_merchant",
        ),
        UniqueConstraint(
            "plan_id",
            "incident_id",
            "merchant_id",
            name="uq_recovery_plans_plan_incident_merchant",
        ),
        CheckConstraint(
            "length(request_sha256) = 64 AND length(plan_sha256) = 64 "
            "AND length(source_evidence_sha256) = 64",
            name="ck_recovery_plans_sha256",
        ),
        Index("ix_recovery_plans_merchant_created", "merchant_id", "created_at"),
    )

    plan_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(80), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    payment_id: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(80), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    plan_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    plan_document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    source_evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    source_evidence_document: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class PolicyResultRecord(Base):
    """Immutable complete policy decision recorded for one preview stage."""

    __tablename__ = "policy_results"
    __table_args__ = (
        ForeignKeyConstraint(
            ("plan_id", "merchant_id"),
            ("recovery_plans.plan_id", "recovery_plans.merchant_id"),
            name="fk_policy_results_plan_merchant",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "plan_id",
            "stage",
            name="uq_policy_results_plan_stage",
        ),
        UniqueConstraint(
            "policy_result_id",
            "plan_id",
            "merchant_id",
            name="uq_policy_results_identity_plan_merchant",
        ),
        CheckConstraint(
            "stage IN ('preview', 'execution')",
            name="ck_policy_results_m4_stage",
        ),
        CheckConstraint(
            "length(policy_result_sha256) = 64",
            name="ck_policy_results_sha256",
        ),
        Index("ix_policy_results_merchant_created", "merchant_id", "created_at"),
    )

    policy_result_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    plan_id: Mapped[str] = mapped_column(String(80), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    stage: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_result_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    result_document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class ApprovalDecisionRecord(Base):
    """Immutable merchant decision; approved rows contain only a keyed token hash."""

    __tablename__ = "approval_decisions"
    __table_args__ = (
        ForeignKeyConstraint(
            ("plan_id", "incident_id", "merchant_id"),
            (
                "recovery_plans.plan_id",
                "recovery_plans.incident_id",
                "recovery_plans.merchant_id",
            ),
            name="fk_approval_decisions_plan_incident_merchant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ("policy_result_id", "plan_id", "merchant_id"),
            (
                "policy_results.policy_result_id",
                "policy_results.plan_id",
                "policy_results.merchant_id",
            ),
            name="fk_approval_decisions_policy_plan_merchant",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("plan_id", name="uq_approval_decisions_plan"),
        UniqueConstraint(
            "merchant_id",
            "idempotency_key",
            name="uq_approval_decisions_merchant_idempotency",
        ),
        UniqueConstraint("token_hash", name="uq_approval_decisions_token_hash"),
        UniqueConstraint(
            "approval_id",
            "plan_id",
            "merchant_id",
            name="uq_approval_decisions_identity_plan_merchant",
        ),
        CheckConstraint(
            "length(request_sha256) = 64 AND length(plan_sha256) = 64 "
            "AND length(policy_result_sha256) = 64",
            name="ck_approval_decisions_sha256",
        ),
        CheckConstraint("actor_type = 'merchant'", name="ck_approval_decisions_actor_type"),
        CheckConstraint(
            "(decision = 'approve' AND initial_status = 'issued' "
            "AND token_hash IS NOT NULL AND length(token_hash) = 64 "
            "AND issued_at IS NOT NULL AND expires_at IS NOT NULL "
            "AND expires_at > issued_at) OR "
            "(decision = 'reject' AND initial_status = 'rejected' "
            "AND token_hash IS NULL AND issued_at IS NULL AND expires_at IS NULL)",
            name="ck_approval_decisions_lifecycle",
        ),
        Index("ix_approval_decisions_merchant_decided", "merchant_id", "decided_at"),
    )

    approval_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    plan_id: Mapped[str] = mapped_column(String(80), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(80), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    policy_result_id: Mapped[str] = mapped_column(String(80), nullable=False)
    plan_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_result_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(80), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    initial_status: Mapped[str] = mapped_column(String(16), nullable=False)
    token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decided_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    issued_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(80), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class ApprovalTokenConsumptionRecord(Base):
    """Append-only winner of the atomic single-use token consumption race."""

    __tablename__ = "approval_token_consumptions"
    __table_args__ = (
        ForeignKeyConstraint(
            ("approval_id", "plan_id", "merchant_id"),
            (
                "approval_decisions.approval_id",
                "approval_decisions.plan_id",
                "approval_decisions.merchant_id",
            ),
            name="fk_approval_consumptions_approval_plan_merchant",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("approval_id", name="uq_approval_consumptions_approval"),
        UniqueConstraint(
            "merchant_id",
            "idempotency_key",
            name="uq_approval_consumptions_merchant_idempotency",
        ),
        CheckConstraint(
            "length(request_sha256) = 64",
            name="ck_approval_consumptions_request_sha256",
        ),
        Index("ix_approval_consumptions_merchant_time", "merchant_id", "consumed_at"),
    )

    consumption_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    approval_id: Mapped[str] = mapped_column(String(80), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(80), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(80), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    consumed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class RecoveryActionRecord(Base):
    """Immutable execute-once action identity and allowlisted provider request."""

    __tablename__ = "recovery_actions"
    __table_args__ = (
        ForeignKeyConstraint(
            ("plan_id", "incident_id", "merchant_id"),
            (
                "recovery_plans.plan_id",
                "recovery_plans.incident_id",
                "recovery_plans.merchant_id",
            ),
            name="fk_recovery_actions_plan_incident_merchant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ("approval_id", "plan_id", "merchant_id"),
            (
                "approval_decisions.approval_id",
                "approval_decisions.plan_id",
                "approval_decisions.merchant_id",
            ),
            name="fk_recovery_actions_approval_plan_merchant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ("preview_policy_result_id", "plan_id", "merchant_id"),
            (
                "policy_results.policy_result_id",
                "policy_results.plan_id",
                "policy_results.merchant_id",
            ),
            name="fk_recovery_actions_preview_policy_plan_merchant",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ("execution_policy_result_id", "plan_id", "merchant_id"),
            (
                "policy_results.policy_result_id",
                "policy_results.plan_id",
                "policy_results.merchant_id",
            ),
            name="fk_recovery_actions_execution_policy_plan_merchant",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("plan_id", name="uq_recovery_actions_plan"),
        UniqueConstraint("approval_id", name="uq_recovery_actions_approval"),
        UniqueConstraint(
            "merchant_id",
            "idempotency_key",
            name="uq_recovery_actions_merchant_idempotency",
        ),
        UniqueConstraint(
            "merchant_id",
            "reference_id",
            name="uq_recovery_actions_merchant_reference",
        ),
        UniqueConstraint(
            "action_id",
            "plan_id",
            "incident_id",
            "merchant_id",
            name="uq_recovery_actions_identity_scope",
        ),
        CheckConstraint(
            "length(plan_sha256) = 64 AND length(request_sha256) = 64",
            name="ck_recovery_actions_sha256",
        ),
        CheckConstraint(
            "template = 'standard_payment_link' AND template_version = 'standard_payment_link_v1'",
            name="ck_recovery_actions_template",
        ),
        CheckConstraint(
            "((execution_target = 'deterministic_fake' "
            "AND execution_side_effect = 'simulated_external_mutation') OR "
            "(execution_target = 'razorpay_test_mode' "
            "AND execution_side_effect = 'razorpay_test_mode_mutation')) "
            "AND synthetic = true",
            name="ck_recovery_actions_execution_target",
        ),
        CheckConstraint(
            "amount_subunits > 0 AND external_notifications_enabled = false",
            name="ck_recovery_actions_bounded_effect",
        ),
        Index("ix_recovery_actions_merchant_created", "merchant_id", "created_at"),
    )

    action_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    plan_id: Mapped[str] = mapped_column(String(80), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(80), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    payment_id: Mapped[str] = mapped_column(String(80), nullable=False)
    approval_id: Mapped[str] = mapped_column(String(80), nullable=False)
    preview_policy_result_id: Mapped[str] = mapped_column(String(80), nullable=False)
    execution_policy_result_id: Mapped[str | None] = mapped_column(
        String(80),
        nullable=True,
    )
    plan_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    template: Mapped[str] = mapped_column(String(40), nullable=False)
    template_version: Mapped[str] = mapped_column(String(40), nullable=False)
    execution_target: Mapped[str] = mapped_column(String(32), nullable=False)
    execution_side_effect: Mapped[str] = mapped_column(String(40), nullable=False)
    amount_subunits: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    reference_id: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(80), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    request_document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    external_notifications_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class RecoveryProviderDispatchRecord(Base):
    """Immutable provider intent committed before any external network I/O."""

    __tablename__ = "recovery_provider_dispatches"
    __table_args__ = (
        ForeignKeyConstraint(
            ("action_id", "plan_id", "incident_id", "merchant_id"),
            (
                "recovery_actions.action_id",
                "recovery_actions.plan_id",
                "recovery_actions.incident_id",
                "recovery_actions.merchant_id",
            ),
            name="fk_provider_dispatches_action_scope",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("action_id", name="uq_provider_dispatches_action"),
        UniqueConstraint(
            "provider_target",
            "reference_id",
            name="uq_provider_dispatches_target_reference",
        ),
        UniqueConstraint(
            "dispatch_id",
            "action_id",
            name="uq_provider_dispatches_identity_action",
        ),
        CheckConstraint(
            "provider_target IN ('deterministic_fake', 'razorpay_test_mode')",
            name="ck_provider_dispatches_target",
        ),
        CheckConstraint(
            "length(request_sha256) = 64 AND external_notifications_enabled = false "
            "AND synthetic = true",
            name="ck_provider_dispatches_bounded_request",
        ),
        Index("ix_provider_dispatches_merchant_time", "merchant_id", "prepared_at"),
    )

    dispatch_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(80), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(80), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(80), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    provider_target: Mapped[str] = mapped_column(String(32), nullable=False)
    reference_id: Mapped[str] = mapped_column(String(40), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    request_document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    external_notifications_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    prepared_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class RecoveryProviderReceiptRecord(Base):
    """Sanitized immutable provider response or lookup verification evidence."""

    __tablename__ = "recovery_provider_receipts"
    __table_args__ = (
        ForeignKeyConstraint(
            ("dispatch_id", "action_id"),
            (
                "recovery_provider_dispatches.dispatch_id",
                "recovery_provider_dispatches.action_id",
            ),
            name="fk_provider_receipts_dispatch_action",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ("action_id", "plan_id", "incident_id", "merchant_id"),
            (
                "recovery_actions.action_id",
                "recovery_actions.plan_id",
                "recovery_actions.incident_id",
                "recovery_actions.merchant_id",
            ),
            name="fk_provider_receipts_action_scope",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("action_id", name="uq_provider_receipts_action"),
        UniqueConstraint(
            "provider_target",
            "provider_action_id",
            name="uq_provider_receipts_provider_action",
        ),
        CheckConstraint(
            "provider_target IN ('deterministic_fake', 'razorpay_test_mode')",
            name="ck_provider_receipts_target",
        ),
        CheckConstraint(
            "status IN ('created', 'partially_paid', 'paid', 'expired', 'cancelled')",
            name="ck_provider_receipts_status",
        ),
        CheckConstraint(
            "verification_source IN ('create_response', 'reference_lookup')",
            name="ck_provider_receipts_verification_source",
        ),
        CheckConstraint(
            "length(request_sha256) = 64 AND length(response_sha256) = 64 "
            "AND amount_subunits > 0 AND external_notifications_enabled = false "
            "AND synthetic = true",
            name="ck_provider_receipts_evidence",
        ),
        CheckConstraint(
            "provider_created_at <= verified_at",
            name="ck_provider_receipts_time_order",
        ),
        CheckConstraint(
            "provider_target != 'razorpay_test_mode' "
            "OR (short_url IS NOT NULL AND short_url LIKE 'https://%')",
            name="ck_provider_receipts_test_mode_url",
        ),
        Index("ix_provider_receipts_merchant_time", "merchant_id", "verified_at"),
    )

    provider_receipt_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    dispatch_id: Mapped[str] = mapped_column(String(80), nullable=False)
    action_id: Mapped[str] = mapped_column(String(80), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(80), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(80), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    provider_target: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_action_id: Mapped[str] = mapped_column(String(80), nullable=False)
    reference_id: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    amount_subunits: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    short_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    provider_created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    verification_source: Mapped[str] = mapped_column(String(32), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    response_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    response_document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    external_notifications_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class RecoveryActionTransitionRecord(Base):
    """Append-only action state transition with optional redacted outcome evidence."""

    __tablename__ = "recovery_action_transitions"
    __table_args__ = (
        ForeignKeyConstraint(
            ("action_id", "plan_id", "incident_id", "merchant_id"),
            (
                "recovery_actions.action_id",
                "recovery_actions.plan_id",
                "recovery_actions.incident_id",
                "recovery_actions.merchant_id",
            ),
            name="fk_action_transitions_action_scope",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "action_id",
            "sequence",
            name="uq_action_transitions_action_sequence",
        ),
        CheckConstraint("sequence > 0", name="ck_action_transitions_sequence"),
        CheckConstraint(
            "new_state IN ('previewed', 'awaiting_approval', 'approved', 'rejected', "
            "'expired', 'executing', 'succeeded', 'failed', "
            "'reconciliation_required')",
            name="ck_action_transitions_new_state",
        ),
        CheckConstraint(
            "prior_state IS NULL OR prior_state IN ('previewed', 'awaiting_approval', "
            "'approved', 'rejected', 'expired', 'executing', 'succeeded', 'failed', "
            "'reconciliation_required')",
            name="ck_action_transitions_prior_state",
        ),
        Index(
            "ix_action_transitions_merchant_time",
            "merchant_id",
            "occurred_at",
        ),
    )

    transition_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(80), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(80), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(80), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    prior_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    new_state: Mapped[str] = mapped_column(String(32), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    actor: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(80), nullable=False)
    provider_action_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    error_document: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_DOCUMENT,
        nullable=True,
    )
    response_document: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_DOCUMENT,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class RecoveryReconciliationRecord(Base):
    """Immutable idempotency receipt for the sole reconciliation of an action."""

    __tablename__ = "recovery_reconciliations"
    __table_args__ = (
        ForeignKeyConstraint(
            ("action_id", "plan_id", "incident_id", "merchant_id"),
            (
                "recovery_actions.action_id",
                "recovery_actions.plan_id",
                "recovery_actions.incident_id",
                "recovery_actions.merchant_id",
            ),
            name="fk_recovery_reconciliations_action_scope",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("action_id", name="uq_recovery_reconciliations_action"),
        UniqueConstraint(
            "merchant_id",
            "idempotency_key",
            name="uq_recovery_reconciliations_merchant_idempotency",
        ),
        CheckConstraint(
            "length(request_sha256) = 64",
            name="ck_recovery_reconciliations_request_sha256",
        ),
        Index(
            "ix_recovery_reconciliations_merchant_time",
            "merchant_id",
            "created_at",
        ),
    )

    reconciliation_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(80), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(80), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(80), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(80), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class RulesBasedIncidentBriefRecord(Base):
    """Immutable deterministic fallback brief bound to an incident snapshot."""

    __tablename__ = "rules_based_incident_briefs"
    __table_args__ = (
        ForeignKeyConstraint(
            ("incident_id", "merchant_id"),
            ("incidents.incident_id", "incidents.merchant_id"),
            name="fk_rules_briefs_incident_merchant",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "incident_id",
            "source_snapshot_sha256",
            name="uq_rules_briefs_incident_snapshot",
        ),
        CheckConstraint(
            "length(source_snapshot_sha256) = 64 AND length(brief_sha256) = 64",
            name="ck_rules_briefs_sha256",
        ),
        CheckConstraint(
            "analyst_mode = 'deterministic_rules' AND model_status = 'unavailable' "
            "AND fallback_used = true",
            name="ck_rules_briefs_fallback_mode",
        ),
        Index("ix_rules_briefs_merchant_created", "merchant_id", "created_at"),
    )

    brief_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(80), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    source_snapshot_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    brief_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    brief_document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    analyst_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    model_status: Mapped[str] = mapped_column(String(16), nullable=False)
    fallback_used: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class ModelIncidentAnalysisRecord(Base):
    """Immutable successful model analysis bound to one redacted snapshot."""

    __tablename__ = "model_incident_analyses"
    __table_args__ = (
        ForeignKeyConstraint(
            ("incident_id", "merchant_id"),
            ("incidents.incident_id", "incidents.merchant_id"),
            name="fk_model_analyses_incident_merchant",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "incident_id",
            "source_snapshot_sha256",
            "model",
            "prompt_version",
            "evaluator_version",
            name="uq_model_analyses_incident_snapshot_model_prompt_eval",
        ),
        CheckConstraint(
            "length(source_snapshot_sha256) = 64 AND length(analysis_sha256) = 64",
            name="ck_model_analyses_sha256",
        ),
        CheckConstraint(
            "provider = 'openai' AND model_status = 'succeeded' "
            "AND fallback_used = false AND provider_storage_enabled = false",
            name="ck_model_analyses_bounded_mode",
        ),
        CheckConstraint(
            "latency_ms >= 0 AND input_tokens >= 0 AND output_tokens >= 0 "
            "AND total_tokens = input_tokens + output_tokens "
            "AND (estimated_cost_microusd IS NULL OR estimated_cost_microusd >= 0) "
            "AND schema_repair_attempts >= 0 AND schema_repair_attempts <= 1",
            name="ck_model_analyses_telemetry",
        ),
        CheckConstraint(
            "(pricing_version = 'unavailable_for_model' "
            "AND estimated_cost_microusd IS NULL) OR "
            "(pricing_version = 'openai_public_pricing_2026_09_05' "
            "AND estimated_cost_microusd IS NOT NULL)",
            name="ck_model_analyses_pricing",
        ),
        Index("ix_model_analyses_merchant_created", "merchant_id", "created_at"),
    )

    analysis_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(80), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(80), nullable=False)
    snapshot_id: Mapped[str] = mapped_column(String(80), nullable=False)
    source_snapshot_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    analysis_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    analysis_document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    model: Mapped[str] = mapped_column(String(80), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(80), nullable=False)
    output_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    evaluator_version: Mapped[str] = mapped_column(String(80), nullable=False)
    model_status: Mapped[str] = mapped_column(String(24), nullable=False)
    fallback_used: Mapped[bool] = mapped_column(Boolean, nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    total_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    estimated_cost_microusd: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pricing_version: Mapped[str] = mapped_column(String(48), nullable=False)
    schema_repair_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    provider_storage_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
