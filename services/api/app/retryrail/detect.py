"""Explicit one-shot detector refresh for local operations and evidence checks."""

import asyncio
import sys

from sqlalchemy.exc import SQLAlchemyError

from retryrail.config import get_settings
from retryrail.db.session import Database
from retryrail.detection.engine import DetectorInputError
from retryrail.detection.service import DetectionPersistenceError, DetectionService
from retryrail.observability.logging import configure_logging
from retryrail.observability.metrics import PipelineMetrics


async def _run() -> str:
    settings = get_settings()
    database = Database(settings.database_dsn())
    try:
        result = await DetectionService(database, PipelineMetrics()).refresh(
            settings.merchant_id
        )
    finally:
        await database.dispose()
    return (
        "detector refresh complete: "
        f"events={result.source_events} attempts={result.attempts} "
        f"aggregates={result.aggregates} incidents={result.incidents} "
        f"active={result.active_incidents} reused={str(result.reused).lower()}"
    )


def main() -> None:
    """Run one refresh and expose only bounded machine-safe failure codes."""

    settings = get_settings()
    configure_logging(settings.log_level)
    try:
        message = asyncio.run(_run())
    except (DetectionPersistenceError, DetectorInputError) as error:
        sys.stderr.write(f"detector refresh failed: {error.reason_code}\n")
        raise SystemExit(1) from None
    except SQLAlchemyError:
        sys.stderr.write("detector refresh failed: DETECTOR_DATABASE_UNAVAILABLE\n")
        raise SystemExit(1) from None
    sys.stdout.write(message + "\n")


if __name__ == "__main__":  # pragma: no cover
    main()
