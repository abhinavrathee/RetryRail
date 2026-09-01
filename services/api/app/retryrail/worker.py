"""Dedicated lease-based transactional-outbox worker process."""

import asyncio
import contextlib
import signal
import uuid

import structlog
from prometheus_client import start_http_server
from sqlalchemy.exc import SQLAlchemyError

from retryrail.config import Settings, get_settings
from retryrail.db.session import Database
from retryrail.events.outbox import OutboxWorker
from retryrail.observability.logging import configure_logging
from retryrail.observability.metrics import PipelineMetrics

LOGGER = structlog.get_logger(__name__)


async def serve(
    stop_event: asyncio.Event | None = None,
    *,
    settings: Settings | None = None,
    database: Database | None = None,
    metrics: PipelineMetrics | None = None,
    worker_id: str | None = None,
) -> None:
    """Process finite batches until shutdown, recovering from database outages."""

    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings.log_level)
    owned_database = database is None
    resolved_database = database or Database(resolved_settings.database_dsn())
    resolved_metrics = metrics or PipelineMetrics()
    worker = OutboxWorker(
        resolved_database,
        resolved_metrics,
        worker_id=worker_id or f"worker-{uuid.uuid4()}",
        batch_size=resolved_settings.worker_batch_size,
        lease_seconds=resolved_settings.worker_lease_seconds,
        retry_base_seconds=resolved_settings.worker_retry_base_seconds,
    )

    stop = stop_event or asyncio.Event()
    loop = asyncio.get_running_loop()
    if stop_event is None:
        for stop_signal in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(stop_signal, stop.set)

    metrics_server = None
    metrics_thread = None
    if not stop.is_set():
        metrics_server, metrics_thread = start_http_server(
            addr=resolved_settings.worker_metrics_host,
            port=resolved_settings.worker_metrics_port,
            registry=resolved_metrics.registry,
        )
    try:
        while not stop.is_set():
            try:
                cycle = await worker.run_once()
            except SQLAlchemyError:
                LOGGER.warning(
                    "outbox_database_operation_failed",
                    reason_code="OUTBOX_DATABASE_UNAVAILABLE",
                )
                cycle_claimed = 0
            else:
                cycle_claimed = cycle.claimed
            if cycle_claimed == 0:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(
                        stop.wait(),
                        timeout=resolved_settings.worker_poll_interval_seconds,
                    )
    finally:
        if metrics_server is not None and metrics_thread is not None:
            metrics_server.shutdown()
            metrics_server.server_close()
            metrics_thread.join(timeout=2)
        if owned_database:
            await resolved_database.dispose()


def main() -> None:
    """Start the durable worker boundary."""

    asyncio.run(serve())


if __name__ == "__main__":  # pragma: no cover
    main()
