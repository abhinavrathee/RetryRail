"""Database-backed detector refresh and durable incident persistence."""

import hashlib
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal

import structlog
from pydantic import ValidationError
from sqlalchemy import func, select, update

from retryrail.db.session import Database
from retryrail.db.tables import (
    AggregateWindowRecord,
    DetectionRunRecord,
    IncidentObservationRecord,
    IncidentRecord,
    OutboxMessageRecord,
    PaymentEventRecord,
)
from retryrail.detection.config import (
    DetectorArtifactMismatchError,
    detector_config_sha256,
    load_detector_config,
    load_detector_release_decision,
)
from retryrail.detection.engine import DetectorEngine, cohort_key, reconstruct_attempts
from retryrail.detection.models import DetectedIncident, DetectorConfig, DetectorRunResult
from retryrail.detection.runtime_activation import (
    load_activated_detector_v4_config,
    load_detector_v4_activation,
)
from retryrail.detection.v2_models import V2DetectedIncident
from retryrail.detection.v4_engine import DetectorV4Engine
from retryrail.detection.v4_models import DetectorV4Config, V4DetectorRunResult
from retryrail.events.ingestion import PROJECT_PAYMENT_TOPIC
from retryrail.events.models import NormalizedPaymentEvent
from retryrail.observability.metrics import PipelineMetrics

LOGGER = structlog.get_logger(__name__)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

type RuntimeDetectorConfig = DetectorConfig | DetectorV4Config
type RuntimeDetectorRunResult = DetectorRunResult | V4DetectorRunResult
type RuntimeDetectedIncident = DetectedIncident | V2DetectedIncident


@dataclass(frozen=True, slots=True)
class DetectionRefreshResult:
    """Bounded operational result with no raw event or customer payload data."""

    run_id: str | None
    reused: bool
    source_events: int
    attempts: int
    aggregates: int
    incidents: int
    active_incidents: int
    at_risk_gmv_subunits: int


class DetectionPersistenceError(RuntimeError):
    """Persisted events could not be safely interpreted by the detector."""

    reason_code = "DETECTOR_PERSISTED_EVENT_INVALID"


class DetectionService:
    """Refresh one merchant from completed outbox facts with idempotent receipts."""

    def __init__(
        self,
        database: Database,
        metrics: PipelineMetrics,
        config: DetectorConfig | None = None,
        *,
        runtime_version: Literal["v1", "v4"] = "v1",
    ) -> None:
        self._database = database
        self._metrics = metrics
        self._runtime_version = runtime_version
        self._config: RuntimeDetectorConfig
        self._engine: DetectorEngine | DetectorV4Engine
        self._release_status: str
        self._runtime_action_eligible: bool
        if runtime_version == "v4":
            if config is not None:
                raise DetectorArtifactMismatchError
            v4_config = load_activated_detector_v4_config()
            activation = load_detector_v4_activation()
            self._config = v4_config
            self._config_sha256 = activation.detector_config_sha256
            if (
                activation.detector_version != v4_config.detector_version
                or activation.detector_config_sha256 != self._config_sha256
                or not activation.action_eligible
            ):
                raise DetectorArtifactMismatchError
            self._release_status = activation.status.value
            self._runtime_action_eligible = activation.action_eligible
            self._engine = DetectorV4Engine(v4_config)
        else:
            v1_config = config or load_detector_config()
            release = load_detector_release_decision()
            self._config = v1_config
            self._config_sha256 = detector_config_sha256()
            if (
                v1_config != load_detector_config()
                or release.detector_version != v1_config.detector_version
                or release.detector_config_sha256 != self._config_sha256
            ):
                raise DetectorArtifactMismatchError
            self._release_status = release.status.value
            self._runtime_action_eligible = release.action_eligible
            self._engine = DetectorEngine(v1_config)

    async def refresh(self, merchant_id: str) -> DetectionRefreshResult:
        """Compute outside a write transaction, then persist one snapshot atomically."""

        started = time.perf_counter()
        records = await self._load_completed_events(merchant_id)
        if not records:
            self._metrics.detector_runs.labels(result="empty").inc()
            return DetectionRefreshResult(
                run_id=None,
                reused=False,
                source_events=0,
                attempts=0,
                aggregates=0,
                incidents=0,
                active_incidents=0,
                at_risk_gmv_subunits=0,
            )
        events = self._validate_records(records, merchant_id)
        source_sha256 = _source_events_sha256(records)
        source_watermark = max(item.received_at for item in records)
        attempts = reconstruct_attempts(events)
        if not attempts:
            self._metrics.detector_runs.labels(result="pending_only").inc()
            return DetectionRefreshResult(
                run_id=None,
                reused=False,
                source_events=len(records),
                attempts=0,
                aggregates=0,
                incidents=0,
                active_incidents=0,
                at_risk_gmv_subunits=0,
            )
        attempt_times = tuple(item.occurred_at for item in attempts)
        partition_start = _floor_time(min(attempt_times), self._config.step_minutes)
        partition_end = _floor_time(max(attempt_times), self._config.step_minutes) + timedelta(
            minutes=self._config.step_minutes
        )
        run = self._engine.run_attempts(
            attempts,
            partition_started_at=partition_start,
            partition_ended_at=partition_end,
        )
        run_identity = (
            f"{merchant_id}\x1f{self._config_sha256}\x1f{source_sha256}"
        ).encode()
        run_id = f"det_run_{hashlib.sha256(run_identity).hexdigest()}"
        result = await self._persist(
            run,
            run_id=run_id,
            merchant_id=merchant_id,
            source_sha256=source_sha256,
            source_watermark=source_watermark,
            source_event_count=len(records),
        )
        self._metrics.incident_detection_latency.observe(time.perf_counter() - started)
        self._metrics.detector_runs.labels(
            result="reused" if result.reused else "persisted"
        ).inc()
        self._metrics.active_incidents.set(result.active_incidents)
        self._metrics.incident_at_risk_gmv.set(result.at_risk_gmv_subunits)
        LOGGER.info(
            "detector_refresh_completed",
            active_incidents=result.active_incidents,
            detector_version=self._config.detector_version,
            incident_count=result.incidents,
            merchant_id=merchant_id,
            reused=result.reused,
            run_id=result.run_id,
            release_status=self._release_status,
        )
        return result

    async def _load_completed_events(
        self,
        merchant_id: str,
    ) -> tuple[PaymentEventRecord, ...]:
        statement = (
            select(PaymentEventRecord)
            .join(
                OutboxMessageRecord,
                OutboxMessageRecord.event_internal_id == PaymentEventRecord.internal_id,
            )
            .where(
                PaymentEventRecord.merchant_id == merchant_id,
                OutboxMessageRecord.merchant_id == merchant_id,
                OutboxMessageRecord.topic == PROJECT_PAYMENT_TOPIC,
                OutboxMessageRecord.status == "completed",
            )
            .order_by(
                PaymentEventRecord.occurred_at,
                PaymentEventRecord.razorpay_event_id,
            )
        )
        async with self._database.sessions() as session:
            return tuple((await session.scalars(statement)).all())

    @staticmethod
    def _validate_records(
        records: tuple[PaymentEventRecord, ...],
        merchant_id: str,
    ) -> tuple[NormalizedPaymentEvent, ...]:
        events: list[NormalizedPaymentEvent] = []
        for record in records:
            try:
                event = NormalizedPaymentEvent.model_validate(record.normalized_event)
            except ValidationError as error:
                raise DetectionPersistenceError from error
            if (
                record.signature_status != "verified"
                or record.merchant_id != merchant_id
                or event.merchant_id != merchant_id
                or event.razorpay_event_id != record.razorpay_event_id
                or event.payment.payment_id != record.payment_id
                or event.event_type.value != record.event_type
                or event.occurred_at != record.occurred_at
                or event.received_at != record.received_at
                or event.synthetic is not record.synthetic
            ):
                raise DetectionPersistenceError
            events.append(event)
        return tuple(events)

    async def _persist(
        self,
        run: RuntimeDetectorRunResult,
        *,
        run_id: str,
        merchant_id: str,
        source_sha256: str,
        source_watermark: datetime,
        source_event_count: int,
    ) -> DetectionRefreshResult:
        now = datetime.now(tz=UTC)
        reused = False
        opened = 0
        resolved = 0
        async with self._database.sessions() as session, session.begin():
            existing_run = await session.get(DetectionRunRecord, run_id)
            if existing_run is not None:
                reused = True
            else:
                await self._upsert_aggregates(
                    session,
                    run,
                    source_watermark=source_watermark,
                    updated_at=now,
                )
                opened, resolved = await self._upsert_incidents(
                    session,
                    run,
                    updated_at=now,
                )
                session.add(
                    DetectionRunRecord(
                        run_id=run_id,
                        merchant_id=merchant_id,
                        detector_version=self._config.detector_version,
                        detector_config_sha256=self._config_sha256,
                        source_events_sha256=source_sha256,
                        source_watermark=source_watermark,
                        partition_started_at=run.partition_started_at,
                        partition_ended_at=run.partition_ended_at,
                        attempt_count=len(run.attempts),
                        aggregate_count=len(run.aggregates),
                        incident_count=len(run.incidents),
                        synthetic=all(item.synthetic for item in run.attempts),
                        created_at=now,
                    )
                )
            if not self._runtime_action_eligible:
                await session.execute(
                    update(IncidentRecord)
                    .where(
                        IncidentRecord.merchant_id == merchant_id,
                        IncidentRecord.detector_version
                        == self._config.detector_version,
                        IncidentRecord.action_eligible.is_(True),
                    )
                    .values(action_eligible=False, updated_at=now)
                )
            active_count = int(
                await session.scalar(
                    select(func.count())
                    .select_from(IncidentRecord)
                    .where(
                        IncidentRecord.merchant_id == merchant_id,
                        IncidentRecord.status == "open",
                    )
                )
                or 0
            )
            at_risk = int(
                await session.scalar(
                    select(func.coalesce(func.sum(IncidentRecord.gmv_at_risk_subunits), 0))
                    .where(
                        IncidentRecord.merchant_id == merchant_id,
                        IncidentRecord.status == "open",
                    )
                )
                or 0
            )
        if opened:
            self._metrics.incident_transitions.labels(transition="opened").inc(opened)
        if resolved:
            self._metrics.incident_transitions.labels(transition="resolved").inc(resolved)
        return DetectionRefreshResult(
            run_id=run_id,
            reused=reused,
            source_events=source_event_count,
            attempts=len(run.attempts),
            aggregates=len(run.aggregates),
            incidents=len(run.incidents),
            active_incidents=active_count,
            at_risk_gmv_subunits=at_risk,
        )

    async def _upsert_aggregates(
        self,
        session: "AsyncSession",
        run: RuntimeDetectorRunResult,
        *,
        source_watermark: datetime,
        updated_at: datetime,
    ) -> None:
        merchant_id = run.attempts[0].merchant_id if run.attempts else ""
        existing = tuple(
            (
                await session.scalars(
                    select(AggregateWindowRecord).where(
                        AggregateWindowRecord.merchant_id == merchant_id,
                        AggregateWindowRecord.detector_version
                        == self._config.detector_version,
                    )
                )
            ).all()
        )
        by_key = {
            (item.cohort_key, item.window_start): item for item in existing
        }
        for aggregate in run.aggregates:
            key = (aggregate.cohort_key, aggregate.window_start)
            record = by_key.get(key)
            if record is None:
                record = AggregateWindowRecord(
                    merchant_id=aggregate.merchant_id,
                    detector_version=self._config.detector_version,
                    cohort_key=aggregate.cohort_key,
                    window_start=aggregate.window_start,
                )
                session.add(record)
            record.window_end = aggregate.window_end
            record.cohort = [
                item.model_dump(mode="json") for item in aggregate.cohort
            ]
            record.attempts = aggregate.attempts
            record.successes = aggregate.successes
            record.failures = aggregate.failures
            record.gmv_subunits = aggregate.gmv_subunits
            record.failed_gmv_subunits = aggregate.failed_gmv_subunits
            record.currency = aggregate.currency
            record.synthetic = aggregate.synthetic
            record.source_watermark = source_watermark
            record.updated_at = updated_at

    async def _upsert_incidents(
        self,
        session: "AsyncSession",
        run: RuntimeDetectorRunResult,
        *,
        updated_at: datetime,
    ) -> tuple[int, int]:
        ids = tuple(item.incident_id for item in run.incidents)
        existing = {}
        if ids:
            records = tuple(
                (
                    await session.scalars(
                        select(IncidentRecord).where(IncidentRecord.incident_id.in_(ids))
                    )
                ).all()
            )
            existing = {item.incident_id: item for item in records}
        observation_keys: set[tuple[str, datetime]] = set()
        if ids:
            observation_rows = (
                await session.execute(
                    select(
                        IncidentObservationRecord.incident_id,
                        IncidentObservationRecord.evaluated_at,
                    ).where(IncidentObservationRecord.incident_id.in_(ids))
                )
            ).all()
            observation_keys = {
                (row.incident_id, row.evaluated_at) for row in observation_rows
            }
        opened = 0
        resolved = 0
        for incident in run.incidents:
            record = existing.get(incident.incident_id)
            prior_status = record.status if record is not None else None
            if record is None:
                record = IncidentRecord(
                    incident_id=incident.incident_id,
                    merchant_id=incident.merchant_id,
                    detector_version=incident.detector_version,
                    detector_config_sha256=self._config_sha256,
                    detector_cohort_key=cohort_key(incident.detector_cohort),
                    created_at=updated_at,
                )
                session.add(record)
                opened += 1
            _update_incident_record(
                record,
                incident,
                action_eligible=self._runtime_action_eligible and incident.synthetic,
                updated_at=updated_at,
            )
            if prior_status == "open" and incident.status.value == "resolved":
                resolved += 1
        # SQLAlchemy has no ORM relationship on this deliberately narrow table model;
        # flush parents explicitly so SQLite and PostgreSQL enforce the same FK order.
        await session.flush()
        for incident in run.incidents:
            for observation in incident.observations:
                observation_key = (incident.incident_id, observation.statistics.evaluated_at)
                if observation_key in observation_keys:
                    continue
                identity = (
                    f"{incident.incident_id}\x1f"
                    f"{observation.statistics.evaluated_at.isoformat()}"
                )
                observation_id = (
                    f"obs_{hashlib.sha256(identity.encode()).hexdigest()[:24]}"
                )
                session.add(
                    IncidentObservationRecord(
                        observation_id=observation_id,
                        incident_id=incident.incident_id,
                        merchant_id=incident.merchant_id,
                        detector_version=incident.detector_version,
                        detector_config_sha256=self._config_sha256,
                        evaluated_at=observation.statistics.evaluated_at,
                        statistics=observation.statistics.model_dump(mode="json"),
                        evidence_event_ids=list(observation.evidence_event_ids),
                        created_at=updated_at,
                    )
                )
                observation_keys.add(observation_key)
        return opened, resolved


def _update_incident_record(
    record: IncidentRecord,
    incident: RuntimeDetectedIncident,
    *,
    action_eligible: bool,
    updated_at: datetime,
) -> None:
    record.detector_cohort = [
        item.model_dump(mode="json") for item in incident.detector_cohort
    ]
    record.affected_cohort = [
        item.model_dump(mode="json") for item in incident.affected_cohort
    ]
    record.status = incident.status.value
    record.opened_at = incident.opened_at
    record.last_observed_at = incident.last_observed_at
    record.resolved_at = incident.resolved_at
    record.peak_statistics = incident.peak_signal.statistics.model_dump(mode="json")
    record.diagnosis = incident.diagnosis.model_dump(mode="json")
    record.evidence_event_ids = list(incident.peak_signal.evidence_event_ids)
    record.gmv_at_risk_subunits = (
        incident.peak_signal.statistics.at_risk_gmv_subunits
    )
    record.currency = incident.peak_signal.statistics.currency
    record.action_eligible = action_eligible
    record.synthetic = incident.synthetic
    record.updated_at = updated_at


def _source_events_sha256(records: tuple[PaymentEventRecord, ...]) -> str:
    material = "\n".join(
        f"{item.internal_id}:{item.payload_sha256}" for item in records
    ).encode()
    return hashlib.sha256(material).hexdigest()


def _floor_time(value: datetime, minutes: int) -> datetime:
    aware = value.astimezone(UTC)
    seconds = minutes * 60
    timestamp = int(aware.timestamp())
    return datetime.fromtimestamp(timestamp - (timestamp % seconds), tz=UTC)
