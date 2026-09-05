"""Migration, immutable-event, replay and operational evidence tests."""

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import SQLAlchemyError

from retryrail.config import Environment, Settings
from retryrail.db.migrate import (
    check_database_schema,
    downgrade_database,
    upgrade_database,
)
from retryrail.db.session import MIGRATION_HEAD, Database
from retryrail.db.tables import (
    OutboxMessageRecord,
    PaymentEventRecord,
    PaymentProjectionRecord,
    PaymentRecoveryControlRecord,
    TraceLinkRecord,
)
from retryrail.events.ingestion import EventIngestionService
from retryrail.events.models import NormalizedPaymentEvent
from retryrail.events.outbox import OutboxWorker
from retryrail.main import create_app
from retryrail.observability.metrics import PipelineMetrics
from retryrail.replay import ReplayMode, ReplayRunner


def test_migration_round_trip_and_immutable_event_trigger(settings: Settings) -> None:
    async def assert_revision(expected: str | None) -> None:
        database = Database(settings.database_dsn())
        try:
            async with database.engine.connect() as connection:
                if expected is None:
                    table_names = await connection.run_sync(
                        lambda sync_connection: inspect(sync_connection).get_table_names()
                    )
                    assert "payment_events" not in table_names
                else:
                    revision = await connection.scalar(
                        text("SELECT version_num FROM alembic_version")
                    )
                    assert revision == expected
        finally:
            await database.dispose()

    asyncio.run(assert_revision(MIGRATION_HEAD))
    downgrade_database(settings.database_dsn())
    asyncio.run(assert_revision(None))
    upgrade_database(settings.database_dsn())
    asyncio.run(assert_revision(MIGRATION_HEAD))
    check_database_schema(settings.database_dsn())

    async def assert_immutable() -> None:
        database = Database(settings.database_dsn())
        now = datetime.now(tz=UTC)
        try:
            async with database.sessions() as session, session.begin():
                session.add(
                    PaymentEventRecord(
                        internal_id="00000000-0000-0000-0000-000000000001",
                        merchant_id="merchant_synthetic_001",
                        razorpay_event_id="event_immutable_001",
                        schema_version="1.0.0",
                        signature_status="verified",
                        event_type="payment.captured",
                        payment_id="pay_immutable_001",
                        occurred_at=now,
                        received_at=now,
                        payload_sha256="0" * 64,
                        sanitized_payload={"synthetic": True},
                        normalized_event={"synthetic": True},
                        synthetic=True,
                        created_at=now,
                    )
                )
                session.add(
                    TraceLinkRecord(
                        trace_link_id="1" * 64,
                        trace_id="2" * 32,
                        span_id="3" * 16,
                        parent_span_id=None,
                        entity_type="event",
                        entity_id="00000000-0000-0000-0000-000000000001",
                        merchant_id="merchant_synthetic_001",
                        created_at=now,
                    )
                )
            async with database.sessions() as session:
                with pytest.raises(SQLAlchemyError, match="immutable"):
                    await session.execute(
                        text(
                            "UPDATE payment_events SET payment_id='pay_mutated_001' "
                            "WHERE razorpay_event_id='event_immutable_001'"
                        )
                    )
                await session.rollback()
                with pytest.raises(SQLAlchemyError, match="immutable"):
                    await session.execute(
                        text(
                            "UPDATE trace_links SET trace_id='44444444444444444444444444444444' "
                            "WHERE trace_link_id="
                            "'11111111111111111111111111111111"
                            "11111111111111111111111111111111'"
                        )
                    )
                await session.rollback()
                with pytest.raises(SQLAlchemyError, match="immutable"):
                    await session.execute(
                        text(
                            "DELETE FROM payment_events "
                            "WHERE razorpay_event_id='event_immutable_001'"
                        )
                    )
        finally:
            await database.dispose()

    asyncio.run(assert_immutable())


def test_m8_upgrade_backfills_event_to_outbox_trace_lineage(settings: Settings) -> None:
    downgrade_database(settings.database_dsn(), "0007_m6_model_incident_analysis")
    now = datetime.now(tz=UTC)

    async def seed_pre_m8() -> None:
        database = Database(settings.database_dsn())
        try:
            async with database.sessions() as session, session.begin():
                session.add(
                    PaymentEventRecord(
                        internal_id="00000000-0000-0000-0000-000000000008",
                        merchant_id=settings.merchant_id,
                        razorpay_event_id="event_pre_m8_001",
                        schema_version="1.0.0",
                        signature_status="verified",
                        event_type="payment.captured",
                        payment_id="pay_pre_m8_001",
                        occurred_at=now,
                        received_at=now,
                        payload_sha256="8" * 64,
                        sanitized_payload={"synthetic": True},
                        normalized_event={"synthetic": True},
                        synthetic=True,
                        created_at=now,
                    )
                )
                await session.flush()
                session.add(
                    OutboxMessageRecord(
                        outbox_id="00000000-0000-0000-0000-000000000009",
                        merchant_id=settings.merchant_id,
                        event_internal_id="00000000-0000-0000-0000-000000000008",
                        topic="payment.project.v1",
                        payload={"schema_version": "1.0.0"},
                        idempotency_key="pre-m8-trace-backfill",
                        status="completed",
                        attempts=1,
                        max_attempts=5,
                        available_at=now,
                        completed_at=now,
                        created_at=now,
                    )
                )
        finally:
            await database.dispose()

    asyncio.run(seed_pre_m8())
    upgrade_database(settings.database_dsn())

    async def assert_backfill() -> None:
        database = Database(settings.database_dsn())
        try:
            async with database.sessions() as session:
                links = tuple(
                    (
                        await session.scalars(
                            select(TraceLinkRecord).order_by(TraceLinkRecord.entity_type)
                        )
                    ).all()
                )
            assert [link.entity_type for link in links] == ["event", "outbox"]
            assert links[0].trace_id == links[1].trace_id
            assert links[1].parent_span_id == links[0].span_id
        finally:
            await database.dispose()

    asyncio.run(assert_backfill())


def test_protected_replay_is_repeat_safe_and_metrics_are_redacted(
    client: TestClient,
    settings: Settings,
) -> None:
    request = {"mode": "required_cases", "limit": 10}

    missing = client.post("/v1/demo/replay", json=request)
    wrong = client.post(
        "/v1/demo/replay",
        json=request,
        headers={"X-RetryRail-Replay-Token": "wrong-token"},
    )
    heldout = client.post(
        "/v1/demo/replay",
        json={"mode": "heldout", "limit": 1},
        headers={"X-RetryRail-Replay-Token": "unit-test-replay-token"},
    )
    first = client.post(
        "/v1/demo/replay",
        json=request,
        headers={"X-RetryRail-Replay-Token": "unit-test-replay-token"},
    )
    second = client.post(
        "/v1/demo/replay",
        json=request,
        headers={"X-RetryRail-Replay-Token": "unit-test-replay-token"},
    )

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert heldout.status_code == 422
    assert first.status_code == 200
    assert first.json()["synthetic"] is True
    assert first.json()["selected_deliveries"] == 10
    assert first.json()["expectation_mismatches"] == 0
    assert second.status_code == 200
    assert second.json()["expectation_mismatches"] == 0

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "retryrail_webhook_requests_total" in metrics.text
    assert settings.merchant_id not in metrics.text
    assert "event_synthetic_" not in metrics.text


def test_bounded_demo_run_projects_then_refreshes_the_detector(
    client: TestClient,
) -> None:
    request = {"mode": "required_cases", "limit": 10}
    headers = {"X-RetryRail-Replay-Token": "unit-test-replay-token"}

    first = client.post("/v1/demo/run", json=request, headers=headers)
    replayed = client.post("/v1/demo/run", json=request, headers=headers)

    assert first.status_code == replayed.status_code == 200
    body = first.json()
    assert body["synthetic"] is True
    assert body["replay"]["selected_deliveries"] == 10
    assert body["replay"]["expectation_mismatches"] == 0
    assert body["projected"] == body["replay"]["accepted"]
    assert body["retried"] == body["dead_lettered"] == 0
    assert body["detector_run_id"] is not None
    assert body["source_events"] == body["replay"]["accepted"]
    assert body["attempts"] >= 0
    assert body["at_risk_gmv_subunits"] >= 0

    replayed_body = replayed.json()
    assert replayed_body["replay"]["accepted"] == 0
    assert replayed_body["projected"] == 0
    assert replayed_body["detector_reused"] is True


def test_required_replay_reconciles_every_projection(settings: Settings) -> None:
    async def exercise() -> None:
        database = Database(settings.database_dsn())
        metrics = PipelineMetrics()
        service = EventIngestionService(
            database,
            settings.webhook_secret,
            metrics,
            outbox_max_attempts=settings.outbox_max_attempts,
        )
        try:
            report = await ReplayRunner(service, settings).run(ReplayMode.REQUIRED_CASES)
            worker = OutboxWorker(
                database,
                metrics,
                worker_id="worker-replay-reconciliation",
                batch_size=50,
                lease_seconds=5,
                retry_base_seconds=1,
                clock=lambda: datetime.now(tz=UTC) + timedelta(seconds=1),
            )
            while (await worker.run_once()).claimed:
                pass

            async with database.sessions() as session:
                events = list((await session.scalars(select(PaymentEventRecord))).all())
                outbox = list((await session.scalars(select(OutboxMessageRecord))).all())
                projections = list(
                    (await session.scalars(select(PaymentProjectionRecord))).all()
                )
                recovery_controls = list(
                    (await session.scalars(select(PaymentRecoveryControlRecord))).all()
                )
                event_count = await session.scalar(
                    select(func.count()).select_from(PaymentEventRecord)
                )

            ranks = {"failed": 1, "authorized": 2, "captured": 3}
            expected: dict[str, str] = {}
            for record in events:
                event = NormalizedPaymentEvent.model_validate(record.normalized_event)
                prior = expected.get(event.payment.payment_id)
                if prior is None or ranks[event.payment.status.value] > ranks[prior]:
                    expected[event.payment.payment_id] = event.payment.status.value

            assert report.expectation_mismatches == 0
            assert report.accepted == event_count == len(events)
            assert len(outbox) == len(events)
            assert {message.status for message in outbox} == {"completed"}
            assert {item.payment_id: item.status for item in projections} == expected
            assert all(item.synthetic for item in projections)
            assert any(item.status == "captured" and item.version == 1 for item in projections)
            assert len(recovery_controls) == len(projections)
            assert all(
                item.source == "synthetic_fixture_default" for item in recovery_controls
            )
            assert {
                item.payment_id: item.already_recovered for item in recovery_controls
            } == {
                item.payment_id: item.status != "failed" for item in projections
            }
        finally:
            await database.dispose()

    asyncio.run(exercise())


def test_replay_disabled_and_unmigrated_database_fail_closed(
    settings: Settings,
    tmp_path: Path,
) -> None:
    disabled = settings.model_copy(update={"replay_enabled": False})
    with TestClient(create_app(disabled)) as client:
        response = client.post(
            "/v1/demo/replay",
            json={"mode": "required_cases", "limit": 1},
            headers={"X-RetryRail-Replay-Token": "unit-test-replay-token"},
        )
        assert response.status_code == 404

    empty_path = (tmp_path / "unmigrated.sqlite3").resolve().as_posix()
    unmigrated = Settings(
        environment=Environment.TEST,
        database_url=f"sqlite+aiosqlite:///{empty_path}",
        webhook_secret=settings.webhook_secret,
    )
    with TestClient(create_app(unmigrated)) as client:
        readiness = client.get("/health/ready")
        assert readiness.status_code == 503
        assert readiness.json()["detail"]["reason_code"] == "DATABASE_MIGRATION_MISSING"
