"""Protected deterministic replay runner and command-line boundary."""

import argparse
import asyncio
import sys
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache

from retryrail.config import Settings, get_settings
from retryrail.contracts.domain import DatasetSplit
from retryrail.db.session import Database
from retryrail.events.ingestion import (
    EventIdentityConflictError,
    EventIngestionService,
    EventPersistenceError,
    IngestionDisposition,
)
from retryrail.events.models import NormalizedPaymentEvent
from retryrail.observability.logging import configure_logging
from retryrail.observability.metrics import PipelineMetrics
from retryrail.synthetic.generator import build_dataset
from retryrail.synthetic.models import (
    BodyMode,
    ExpectedDeliveryDisposition,
    SignatureMode,
    WebhookDeliveryInstruction,
)
from retryrail.webhooks.serialization import serialize_razorpay_webhook
from retryrail.webhooks.signatures import WebhookSignatureError, compute_webhook_signature

_MAX_REPLAY_DELIVERIES = 10_000


class ReplayMode(StrEnum):
    """Bounded replay partitions exposed by CLI and protected demo API."""

    REQUIRED_CASES = "required_cases"
    TUNING = "tuning"
    HELDOUT = "heldout"
    ALL = "all"


@dataclass(frozen=True, slots=True)
class ReplayReport:
    """Aggregate-only replay evidence that contains no evaluation truth labels."""

    dataset_sha256: str
    selected_deliveries: int
    accepted: int
    duplicates: int
    rejected_signatures: int
    expectation_mismatches: int


@lru_cache(maxsize=1)
def _load_dataset() -> tuple[
    str,
    dict[str, NormalizedPaymentEvent],
    tuple[WebhookDeliveryInstruction, ...],
    dict[DatasetSplit, frozenset[str]],
]:
    dataset = build_dataset()
    events: dict[str, NormalizedPaymentEvent] = {}
    split_ids: dict[DatasetSplit, frozenset[str]] = {}
    for split in DatasetSplit:
        suffix = f"{split.value}.normalized_events.v1.jsonl"
        artifact = next(item for item in dataset.artifacts if item.path.endswith(suffix))
        partition = tuple(
            NormalizedPaymentEvent.model_validate_json(line)
            for line in artifact.content.splitlines()
        )
        events.update((event.razorpay_event_id, event) for event in partition)
        split_ids[split] = frozenset(event.razorpay_event_id for event in partition)
    delivery_artifact = next(
        item for item in dataset.artifacts if item.path.endswith("webhook_deliveries.v1.jsonl")
    )
    deliveries = tuple(
        WebhookDeliveryInstruction.model_validate_json(line)
        for line in delivery_artifact.content.splitlines()
    )
    return dataset.manifest_sha256, events, deliveries, split_ids


class ReplayRunner:
    """Replay synthetic raw bodies through the same verified ingestion service."""

    def __init__(self, service: EventIngestionService, settings: Settings) -> None:
        self._service = service
        self._settings = settings

    async def run(self, mode: ReplayMode, *, limit: int | None = None) -> ReplayReport:
        dataset_sha256, events, deliveries, split_ids = await asyncio.to_thread(_load_dataset)
        selected = self._select(deliveries, split_ids, mode)
        if limit is not None:
            selected = selected[:limit]

        accepted = 0
        duplicates = 0
        rejected_signatures = 0
        expectation_mismatches = 0
        for instruction in selected:
            event = events[instruction.razorpay_event_id]
            original_body = serialize_razorpay_webhook(event)
            signature = self._signature(instruction, original_body)
            delivered_body = (
                original_body + b"\n"
                if instruction.body_mode is BodyMode.MODIFIED_AFTER_SIGNING
                else original_body
            )
            try:
                result = await self._service.ingest(
                    merchant_id=instruction.merchant_id,
                    razorpay_event_id=instruction.razorpay_event_id,
                    raw_body=delivered_body,
                    signature=signature,
                    received_at=instruction.delivered_at,
                )
            except WebhookSignatureError:
                actual = ExpectedDeliveryDisposition.REJECTED_SIGNATURE
                rejected_signatures += 1
            else:
                if result.disposition is IngestionDisposition.ACCEPTED:
                    actual = ExpectedDeliveryDisposition.ACCEPTED
                    accepted += 1
                else:
                    actual = ExpectedDeliveryDisposition.DUPLICATE
                    duplicates += 1
            expected = instruction.expected_disposition
            repeat_safe = (
                expected is ExpectedDeliveryDisposition.ACCEPTED
                and actual is ExpectedDeliveryDisposition.DUPLICATE
            )
            if actual is not expected and not repeat_safe:
                expectation_mismatches += 1

        return ReplayReport(
            dataset_sha256=dataset_sha256,
            selected_deliveries=len(selected),
            accepted=accepted,
            duplicates=duplicates,
            rejected_signatures=rejected_signatures,
            expectation_mismatches=expectation_mismatches,
        )

    def _signature(
        self,
        instruction: WebhookDeliveryInstruction,
        raw_body: bytes,
    ) -> str | None:
        if instruction.signature_mode is SignatureMode.MISSING:
            return None
        if instruction.signature_mode is SignatureMode.INVALID:
            return "0" * 64
        return compute_webhook_signature(raw_body, self._settings.webhook_secret)

    @staticmethod
    def _select(
        deliveries: tuple[WebhookDeliveryInstruction, ...],
        split_ids: dict[DatasetSplit, frozenset[str]],
        mode: ReplayMode,
    ) -> tuple[WebhookDeliveryInstruction, ...]:
        if mode is ReplayMode.REQUIRED_CASES:
            return tuple(item for item in deliveries if item.reliability_case is not None)
        if mode is ReplayMode.ALL:
            return deliveries
        split = DatasetSplit(mode.value)
        return tuple(item for item in deliveries if item.razorpay_event_id in split_ids[split])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=tuple(ReplayMode), default=ReplayMode.REQUIRED_CASES)
    parser.add_argument("--limit", type=int, default=None)
    return parser


async def _run_cli(settings: Settings, mode: ReplayMode, limit: int | None) -> ReplayReport:
    database = Database(settings.database_dsn())
    metrics = PipelineMetrics()
    service = EventIngestionService(
        database,
        settings.webhook_secret,
        metrics,
        outbox_max_attempts=settings.outbox_max_attempts,
    )
    try:
        return await ReplayRunner(service, settings).run(mode, limit=limit)
    finally:
        await database.dispose()


def main() -> None:
    """Replay a deterministic partition into a migrated local database."""

    arguments = _parser().parse_args()
    if arguments.limit is not None and not 1 <= arguments.limit <= _MAX_REPLAY_DELIVERIES:
        sys.stderr.write("--limit must be between 1 and 10000\n")
        raise SystemExit(2)
    settings = get_settings()
    configure_logging(settings.log_level)
    if settings.environment.value == "production" or not settings.replay_enabled:
        sys.stderr.write("synthetic replay is disabled by configuration\n")
        raise SystemExit(1)
    try:
        report = asyncio.run(
            _run_cli(settings, ReplayMode(arguments.mode), arguments.limit)
        )
    except EventIdentityConflictError:
        sys.stderr.write("replay failed: WEBHOOK_EVENT_IDENTITY_CONFLICT\n")
        raise SystemExit(1) from None
    except EventPersistenceError:
        sys.stderr.write("replay failed: WEBHOOK_PERSISTENCE_UNAVAILABLE\n")
        raise SystemExit(1) from None
    sys.stdout.write(
        "replay complete: "
        f"selected={report.selected_deliveries} accepted={report.accepted} "
        f"duplicates={report.duplicates} rejected={report.rejected_signatures} "
        f"mismatches={report.expectation_mismatches}\n"
    )


if __name__ == "__main__":  # pragma: no cover
    main()
