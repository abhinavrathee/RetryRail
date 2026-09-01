"""M0 worker boundary behavior."""

import asyncio
import socket

from retryrail.config import Settings
from retryrail.worker import serve


def test_worker_exits_cleanly_when_shutdown_is_already_requested() -> None:
    async def exercise() -> None:
        stop = asyncio.Event()
        stop.set()
        await serve(stop)

    asyncio.run(exercise())


def test_worker_exposes_redacted_metrics_and_shuts_down(settings: Settings) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        metrics_port = int(probe.getsockname()[1])

    async def exercise() -> None:
        stop = asyncio.Event()
        configured = settings.model_copy(update={"worker_metrics_port": metrics_port})
        task = asyncio.create_task(
            serve(
                stop,
                settings=configured,
                worker_id="worker-metrics-test",
            )
        )
        response = b""
        try:
            for _attempt in range(50):
                try:
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1",
                        metrics_port,
                    )
                except OSError:
                    await asyncio.sleep(0.01)
                    continue
                writer.write(
                    b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                )
                await writer.drain()
                response = await reader.read()
                writer.close()
                await writer.wait_closed()
                break
            assert b"200 OK" in response
            assert b"retryrail_outbox_results_total" in response
            assert settings.merchant_id.encode() not in response
        finally:
            stop.set()
            await task

    asyncio.run(exercise())
