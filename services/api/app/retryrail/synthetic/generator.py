"""Cross-platform deterministic generator for the M1 synthetic truth set."""

import argparse
import hashlib
import json
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel

from retryrail.contracts.domain import CohortDimension, CohortPredicate, DatasetSplit
from retryrail.events.models import (
    ErrorEvidence,
    NormalizedPaymentEvent,
    PaymentEventType,
    PaymentMethod,
    PaymentSnapshot,
    PaymentStatus,
)
from retryrail.synthetic.models import (
    ArtifactDigest,
    AttemptGroundTruth,
    BodyMode,
    DatasetPartition,
    DeliveryCaseSummary,
    ExpectedDeliveryDisposition,
    ExperimentDesign,
    ReliabilityCase,
    ScenarioDefinition,
    ScenarioKind,
    ScenarioSeverity,
    SignatureMode,
    SyntheticDatasetManifest,
    WebhookDeliveryInstruction,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_MANIFEST_PATH = "fixtures/manifests/default.v1.json"
_MANIFEST_DIGEST_PATH = "fixtures/manifests/default.v1.sha256"
_GENERATOR_VERSION = "generator_v1_0_0"
_DATASET_ID = "retryrail_default_v1"
_SEED = "retryrail_m1_seed_v1"
_MERCHANT_ID = "merchant_synthetic_001"
_CURRENCY = "INR"
_ATTEMPTS_PER_PARTITION = 1_440
_TUNING_START = datetime(2026, 9, 1, tzinfo=UTC)
_HELDOUT_START = datetime(2026, 9, 8, tzinfo=UTC)
_UNRESOLVED_WEIGHTED_CHOICE = "weighted choice target must resolve"


@dataclass(frozen=True, slots=True)
class ScenarioTemplate:
    """Generator-only seed parameters later materialized with actual counts."""

    scenario_id: str
    split: DatasetSplit
    kind: ScenarioKind
    severity: ScenarioSeverity
    starts_at: datetime
    ends_at: datetime
    cohort: tuple[CohortPredicate, ...]
    baseline_failure_rate_bps: int
    seeded_failure_rate_bps: int
    root_cause: ErrorEvidence
    gate_reason: str


@dataclass(frozen=True, slots=True)
class PartitionBuild:
    """In-memory unique events and isolated evaluator truth for one split."""

    split: DatasetSplit
    starts_at: datetime
    ends_at: datetime
    events: tuple[NormalizedPaymentEvent, ...]
    truth: tuple[AttemptGroundTruth, ...]


@dataclass(frozen=True, slots=True)
class GeneratedArtifact:
    """One deterministic generated file before it is written to disk."""

    path: str
    content: bytes
    records: int

    @property
    def sha256(self) -> str:
        """Return the stable lowercase SHA-256 identity."""

        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True, slots=True)
class GeneratedDataset:
    """Complete generated output plus its committed manifest identity."""

    artifacts: tuple[GeneratedArtifact, ...]
    manifest: SyntheticDatasetManifest
    manifest_content: bytes
    manifest_sha256: str


def _scenario_templates() -> tuple[ScenarioTemplate, ...]:
    return (
        ScenarioTemplate(
            scenario_id="incident_tuning_card_issuer_alpha",
            split=DatasetSplit.TUNING,
            kind=ScenarioKind.TRUE_INCIDENT,
            severity=ScenarioSeverity.HIGH,
            starts_at=_TUNING_START + timedelta(hours=4),
            ends_at=_TUNING_START + timedelta(hours=7),
            cohort=(
                CohortPredicate(dimension=CohortDimension.METHOD, value="card"),
                CohortPredicate(
                    dimension=CohortDimension.ISSUER,
                    value="issuer_synthetic_alpha",
                ),
            ),
            baseline_failure_rate_bps=700,
            seeded_failure_rate_bps=5_800,
            root_cause=ErrorEvidence(
                code="GATEWAY_ERROR",
                source="bank",
                step="payment_authorization",
                reason="issuer_unavailable",
            ),
            gate_reason="statistical_and_business_gates_pass",
        ),
        ScenarioTemplate(
            scenario_id="incident_tuning_upi_gateway",
            split=DatasetSplit.TUNING,
            kind=ScenarioKind.TRUE_INCIDENT,
            severity=ScenarioSeverity.MEDIUM,
            starts_at=_TUNING_START + timedelta(hours=10),
            ends_at=_TUNING_START + timedelta(hours=13),
            cohort=(CohortPredicate(dimension=CohortDimension.METHOD, value="upi"),),
            baseline_failure_rate_bps=900,
            seeded_failure_rate_bps=4_900,
            root_cause=ErrorEvidence(
                code="SERVER_ERROR",
                source="gateway",
                step="payment_processing",
                reason="payment_timed_out",
            ),
            gate_reason="statistical_and_business_gates_pass",
        ),
        ScenarioTemplate(
            scenario_id="incident_heldout_netbanking_beta",
            split=DatasetSplit.HELDOUT,
            kind=ScenarioKind.TRUE_INCIDENT,
            severity=ScenarioSeverity.HIGH,
            starts_at=_HELDOUT_START + timedelta(hours=4),
            ends_at=_HELDOUT_START + timedelta(hours=10),
            cohort=(
                CohortPredicate(dimension=CohortDimension.METHOD, value="netbanking"),
                CohortPredicate(
                    dimension=CohortDimension.ISSUER,
                    value="issuer_synthetic_beta",
                ),
            ),
            baseline_failure_rate_bps=1_100,
            seeded_failure_rate_bps=6_200,
            root_cause=ErrorEvidence(
                code="GATEWAY_ERROR",
                source="bank",
                step="payment_authentication",
                reason="issuer_unavailable",
            ),
            gate_reason="statistical_and_business_gates_pass",
        ),
        ScenarioTemplate(
            scenario_id="hard_negative_heldout_wallet_low_volume",
            split=DatasetSplit.HELDOUT,
            kind=ScenarioKind.HARD_NEGATIVE,
            severity=ScenarioSeverity.HIGH,
            starts_at=_HELDOUT_START + timedelta(hours=13),
            ends_at=_HELDOUT_START + timedelta(hours=14),
            cohort=(CohortPredicate(dimension=CohortDimension.METHOD, value="wallet"),),
            baseline_failure_rate_bps=1_000,
            seeded_failure_rate_bps=9_000,
            root_cause=ErrorEvidence(
                code="GATEWAY_ERROR",
                source="wallet",
                step="payment_processing",
                reason="payment_timed_out",
            ),
            gate_reason="blocked_by_minimum_sample_gate",
        ),
    )


def _bucket(namespace: str, modulo: int, *parts: object) -> int:
    """Produce a stable pseudo-random bucket without mutable RNG state."""

    if modulo <= 0:
        msg = "modulo must be positive"
        raise ValueError(msg)
    material = "\x1f".join((_SEED, namespace, *(str(part) for part in parts))).encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big") % modulo


def _weighted_choice[ChoiceT](
    namespace: str,
    choices: Sequence[tuple[ChoiceT, int]],
    *parts: object,
) -> ChoiceT:
    """Choose from positive integer weights using the stable hash bucket."""

    total_weight = sum(weight for _, weight in choices)
    if total_weight <= 0 or any(weight <= 0 for _, weight in choices):
        msg = "weighted choices require positive weights"
        raise ValueError(msg)
    target = _bucket(namespace, total_weight, *parts)
    cumulative = 0
    for choice, weight in choices:
        cumulative += weight
        if target < cumulative:
            return choice
    raise AssertionError(_UNRESOLVED_WEIGHTED_CHOICE)


def _method(split: DatasetSplit, index: int) -> PaymentMethod:
    return _weighted_choice(
        "method",
        (
            (PaymentMethod.CARD, 40),
            (PaymentMethod.UPI, 35),
            (PaymentMethod.NETBANKING, 20),
            (PaymentMethod.WALLET, 5),
        ),
        split.value,
        index,
    )


def _issuer(split: DatasetSplit, index: int, method: PaymentMethod) -> str:
    choices: Sequence[tuple[str, int]]
    if method is PaymentMethod.WALLET:
        choices = (("wallet_synthetic_amber", 50), ("wallet_synthetic_blue", 50))
    else:
        choices = (
            ("issuer_synthetic_alpha", 45),
            ("issuer_synthetic_beta", 35),
            ("issuer_synthetic_gamma", 20),
        )
    return _weighted_choice("issuer", choices, split.value, index, method.value)


def _amount_subunits(split: DatasetSplit, index: int) -> int:
    return _weighted_choice(
        "amount",
        ((49_900, 15), (99_900, 30), (149_900, 25), (249_900, 20), (499_900, 10)),
        split.value,
        index,
    )


def _base_failure_rate(method: PaymentMethod) -> int:
    return {
        PaymentMethod.CARD: 700,
        PaymentMethod.UPI: 900,
        PaymentMethod.NETBANKING: 1_100,
        PaymentMethod.WALLET: 1_000,
    }[method]


def _normal_error(method: PaymentMethod) -> ErrorEvidence:
    return {
        PaymentMethod.CARD: ErrorEvidence(
            code="BAD_REQUEST_ERROR",
            source="customer",
            step="payment_authentication",
            reason="incorrect_otp",
        ),
        PaymentMethod.UPI: ErrorEvidence(
            code="BAD_REQUEST_ERROR",
            source="customer",
            step="payment_authentication",
            reason="payment_cancelled",
        ),
        PaymentMethod.NETBANKING: ErrorEvidence(
            code="GATEWAY_ERROR",
            source="bank",
            step="payment_processing",
            reason="payment_timed_out",
        ),
        PaymentMethod.WALLET: ErrorEvidence(
            code="BAD_REQUEST_ERROR",
            source="customer",
            step="payment_authentication",
            reason="payment_cancelled",
        ),
    }[method]


def _matches_scenario(
    template: ScenarioTemplate,
    *,
    split: DatasetSplit,
    occurred_at: datetime,
    method: PaymentMethod,
    issuer: str,
) -> bool:
    if template.split is not split or not (template.starts_at <= occurred_at < template.ends_at):
        return False
    values = {
        CohortDimension.METHOD: method.value,
        CohortDimension.ISSUER: issuer,
    }
    return all(values.get(predicate.dimension) == predicate.value for predicate in template.cohort)


def _event_identifier(split: DatasetSplit, index: int, suffix: str) -> str:
    prefix = "tune" if split is DatasetSplit.TUNING else "hold"
    return f"evt_syn_{prefix}_{index:04d}_{suffix}"


def _build_partition(
    split: DatasetSplit,
    starts_at: datetime,
    templates: Sequence[ScenarioTemplate],
) -> PartitionBuild:
    events: list[NormalizedPaymentEvent] = []
    truth: list[AttemptGroundTruth] = []
    split_prefix = "tune" if split is DatasetSplit.TUNING else "hold"

    for index in range(_ATTEMPTS_PER_PARTITION):
        occurred_at = starts_at + timedelta(minutes=index)
        method = _method(split, index)
        issuer = _issuer(split, index, method)
        amount_subunits = _amount_subunits(split, index)
        scenario = next(
            (
                template
                for template in templates
                if _matches_scenario(
                    template,
                    split=split,
                    occurred_at=occurred_at,
                    method=method,
                    issuer=issuer,
                )
            ),
            None,
        )
        failure_rate = (
            scenario.seeded_failure_rate_bps if scenario is not None else _base_failure_rate(method)
        )
        failed = _bucket("failure", 10_000, split.value, index) < failure_rate
        attempt_id = f"attempt_syn_{split_prefix}_{index:04d}"
        payment_id = f"pay_syn_{split_prefix}_{index:04d}"
        event_ids: list[str] = []

        if failed:
            event_id = _event_identifier(split, index, "failed")
            event_ids.append(event_id)
            events.append(
                NormalizedPaymentEvent(
                    merchant_id=_MERCHANT_ID,
                    razorpay_event_id=event_id,
                    event_type=PaymentEventType.FAILED,
                    occurred_at=occurred_at,
                    received_at=occurred_at
                    + timedelta(seconds=1 + _bucket("receive", 5, split.value, index, "failed")),
                    synthetic=True,
                    payment=PaymentSnapshot(
                        payment_id=payment_id,
                        status=PaymentStatus.FAILED,
                        amount_subunits=amount_subunits,
                        currency=_CURRENCY,
                        method=method,
                        issuer=issuer,
                        error=(
                            scenario.root_cause
                            if scenario is not None
                            else _normal_error(method)
                        ),
                    ),
                )
            )
            final_status = PaymentStatus.FAILED
        else:
            authorized_id = _event_identifier(split, index, "authorized")
            captured_id = _event_identifier(split, index, "captured")
            capture_delay = 10 + _bucket("capture_delay", 111, split.value, index)
            captured_at = occurred_at + timedelta(seconds=capture_delay)
            event_ids.extend((authorized_id, captured_id))
            events.extend(
                (
                    NormalizedPaymentEvent(
                        merchant_id=_MERCHANT_ID,
                        razorpay_event_id=authorized_id,
                        event_type=PaymentEventType.AUTHORIZED,
                        occurred_at=occurred_at,
                        received_at=occurred_at
                        + timedelta(
                            seconds=1 + _bucket("receive", 5, split.value, index, "authorized")
                        ),
                        synthetic=True,
                        payment=PaymentSnapshot(
                            payment_id=payment_id,
                            status=PaymentStatus.AUTHORIZED,
                            amount_subunits=amount_subunits,
                            currency=_CURRENCY,
                            method=method,
                            issuer=issuer,
                        ),
                    ),
                    NormalizedPaymentEvent(
                        merchant_id=_MERCHANT_ID,
                        razorpay_event_id=captured_id,
                        event_type=PaymentEventType.CAPTURED,
                        occurred_at=captured_at,
                        received_at=captured_at
                        + timedelta(
                            seconds=1 + _bucket("receive", 5, split.value, index, "captured")
                        ),
                        synthetic=True,
                        payment=PaymentSnapshot(
                            payment_id=payment_id,
                            status=PaymentStatus.CAPTURED,
                            amount_subunits=amount_subunits,
                            currency=_CURRENCY,
                            method=method,
                            issuer=issuer,
                        ),
                    ),
                )
            )
            final_status = PaymentStatus.CAPTURED

        truth.append(
            AttemptGroundTruth(
                attempt_id=attempt_id,
                payment_id=payment_id,
                split=split,
                occurred_at=occurred_at,
                amount_subunits=amount_subunits,
                currency=_CURRENCY,
                method=method,
                issuer=issuer,
                final_status=final_status,
                normalized_event_ids=tuple(event_ids),
                scenario_id=scenario.scenario_id if scenario is not None else None,
                expected_incident_member=(
                    scenario is not None and scenario.kind is ScenarioKind.TRUE_INCIDENT
                ),
            )
        )

    return PartitionBuild(
        split=split,
        starts_at=starts_at,
        ends_at=starts_at + timedelta(minutes=_ATTEMPTS_PER_PARTITION),
        events=tuple(events),
        truth=tuple(truth),
    )


def _choose_truth(
    partition: PartitionBuild,
    predicate: Callable[[AttemptGroundTruth], bool],
    *,
    excluded_payments: set[str] | None = None,
) -> AttemptGroundTruth:
    excluded = excluded_payments or set()
    return next(
        item
        for item in partition.truth
        if item.payment_id not in excluded and predicate(item)
    )


def _replace_received_at(
    events: dict[str, NormalizedPaymentEvent],
    event_id: str,
    received_at: datetime,
) -> None:
    events[event_id] = events[event_id].model_copy(update={"received_at": received_at})


def _apply_reliability_timing(
    tuning: PartitionBuild,
    heldout: PartitionBuild,
) -> tuple[
    dict[str, NormalizedPaymentEvent],
    str,
    str,
    tuple[str, str],
    dict[ReliabilityCase, str],
]:
    events = {event.razorpay_event_id: event for event in (*tuning.events, *heldout.events)}
    used_payments: set[str] = set()

    duplicate_truth = _choose_truth(
        tuning,
        lambda item: item.final_status is PaymentStatus.FAILED and item.scenario_id is None,
    )
    used_payments.add(duplicate_truth.payment_id)
    duplicate_event_id = duplicate_truth.normalized_event_ids[0]

    delayed_truth = _choose_truth(
        heldout,
        lambda item: item.final_status is PaymentStatus.FAILED and item.scenario_id is None,
    )
    used_payments.add(delayed_truth.payment_id)
    delayed_event_id = delayed_truth.normalized_event_ids[0]
    delayed_event = events[delayed_event_id]
    _replace_received_at(
        events,
        delayed_event_id,
        delayed_event.occurred_at + timedelta(hours=2),
    )

    out_of_order_truth = _choose_truth(
        heldout,
        lambda item: item.final_status is PaymentStatus.CAPTURED and item.scenario_id is None,
        excluded_payments=used_payments,
    )
    used_payments.add(out_of_order_truth.payment_id)
    authorized_id, captured_id = out_of_order_truth.normalized_event_ids
    captured_received_at = events[captured_id].occurred_at + timedelta(seconds=2)
    _replace_received_at(events, captured_id, captured_received_at)
    _replace_received_at(events, authorized_id, captured_received_at + timedelta(seconds=90))

    security_targets: dict[ReliabilityCase, str] = {}
    security_choices = (
        (ReliabilityCase.INVALID_SIGNATURE, tuning),
        (ReliabilityCase.MISSING_SIGNATURE, heldout),
        (ReliabilityCase.MODIFIED_BODY, tuning),
    )
    for reliability_case, partition in security_choices:
        selected = _choose_truth(
            partition,
            lambda item: item.final_status is PaymentStatus.CAPTURED
            and item.scenario_id is None,
            excluded_payments=used_payments,
        )
        used_payments.add(selected.payment_id)
        event_id = selected.normalized_event_ids[0]
        security_targets[reliability_case] = event_id
        event = events[event_id]
        _replace_received_at(events, event_id, event.occurred_at + timedelta(seconds=60))

    return (
        events,
        duplicate_event_id,
        delayed_event_id,
        (authorized_id, captured_id),
        security_targets,
    )


def _delivery_id(event_id: str, attempt: int) -> str:
    return f"delivery_{event_id}_{attempt}"


def _build_delivery_schedule(
    events: dict[str, NormalizedPaymentEvent],
    duplicate_event_id: str,
    delayed_event_id: str,
    out_of_order_event_ids: tuple[str, str],
    security_targets: dict[ReliabilityCase, str],
) -> tuple[WebhookDeliveryInstruction, ...]:
    instructions: list[WebhookDeliveryInstruction] = []
    security_by_event = {event_id: case for case, event_id in security_targets.items()}

    for event in events.values():
        security_case = security_by_event.get(event.razorpay_event_id)
        delivery_attempt = 2 if security_case is not None else 1
        reliability_case = None
        if event.razorpay_event_id == duplicate_event_id:
            reliability_case = ReliabilityCase.DUPLICATE
        elif event.razorpay_event_id == delayed_event_id:
            reliability_case = ReliabilityCase.DELAYED
        elif event.razorpay_event_id in out_of_order_event_ids:
            reliability_case = ReliabilityCase.OUT_OF_ORDER
        instructions.append(
            WebhookDeliveryInstruction(
                sequence=1,
                delivery_id=_delivery_id(event.razorpay_event_id, delivery_attempt),
                merchant_id=event.merchant_id,
                razorpay_event_id=event.razorpay_event_id,
                delivery_attempt=delivery_attempt,
                delivered_at=event.received_at,
                signature_mode=SignatureMode.VALID,
                body_mode=BodyMode.UNMODIFIED,
                expected_disposition=ExpectedDeliveryDisposition.ACCEPTED,
                reliability_case=reliability_case,
            )
        )

    duplicate_event = events[duplicate_event_id]
    for attempt, seconds in ((2, 5), (3, 15), (4, 60)):
        instructions.append(
            WebhookDeliveryInstruction(
                sequence=1,
                delivery_id=_delivery_id(duplicate_event_id, attempt),
                merchant_id=duplicate_event.merchant_id,
                razorpay_event_id=duplicate_event_id,
                delivery_attempt=attempt,
                delivered_at=duplicate_event.received_at + timedelta(seconds=seconds),
                signature_mode=SignatureMode.VALID,
                body_mode=BodyMode.UNMODIFIED,
                expected_disposition=ExpectedDeliveryDisposition.DUPLICATE,
                reliability_case=ReliabilityCase.DUPLICATE,
            )
        )

    security_conditions = {
        ReliabilityCase.INVALID_SIGNATURE: (SignatureMode.INVALID, BodyMode.UNMODIFIED),
        ReliabilityCase.MISSING_SIGNATURE: (SignatureMode.MISSING, BodyMode.UNMODIFIED),
        ReliabilityCase.MODIFIED_BODY: (
            SignatureMode.VALID,
            BodyMode.MODIFIED_AFTER_SIGNING,
        ),
    }
    for reliability_case, event_id in security_targets.items():
        event = events[event_id]
        signature_mode, body_mode = security_conditions[reliability_case]
        instructions.append(
            WebhookDeliveryInstruction(
                sequence=1,
                delivery_id=_delivery_id(event_id, 1),
                merchant_id=event.merchant_id,
                razorpay_event_id=event_id,
                delivery_attempt=1,
                delivered_at=event.occurred_at + timedelta(seconds=5),
                signature_mode=signature_mode,
                body_mode=body_mode,
                expected_disposition=ExpectedDeliveryDisposition.REJECTED_SIGNATURE,
                reliability_case=reliability_case,
            )
        )

    ordered = sorted(
        instructions,
        key=lambda item: (item.delivered_at, item.delivery_id),
    )
    return tuple(
        instruction.model_copy(update={"sequence": sequence})
        for sequence, instruction in enumerate(ordered, start=1)
    )


def _canonical_json(value: BaseModel) -> bytes:
    payload = value.model_dump(mode="json", exclude_none=True)
    return (
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True, separators=(",", ": "))
        + "\n"
    ).encode()


def _json_lines(values: Iterable[BaseModel]) -> bytes:
    return "".join(
        json.dumps(
            value.model_dump(mode="json", exclude_none=True),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for value in values
    ).encode()


def _artifact(path: str, values: Sequence[BaseModel]) -> GeneratedArtifact:
    return GeneratedArtifact(path=path, content=_json_lines(values), records=len(values))


def _materialize_scenarios(
    templates: Sequence[ScenarioTemplate],
    truth: Sequence[AttemptGroundTruth],
) -> tuple[ScenarioDefinition, ...]:
    return tuple(
        ScenarioDefinition(
            scenario_id=template.scenario_id,
            split=template.split,
            kind=template.kind,
            severity=template.severity,
            starts_at=template.starts_at,
            ends_at=template.ends_at,
            affected_cohort=template.cohort,
            baseline_failure_rate_bps=template.baseline_failure_rate_bps,
            seeded_failure_rate_bps=template.seeded_failure_rate_bps,
            expected_root_cause=template.root_cause,
            should_open_incident=template.kind is ScenarioKind.TRUE_INCIDENT,
            expected_gate_reason=template.gate_reason,
            actual_attempt_count=sum(item.scenario_id == template.scenario_id for item in truth),
            actual_failure_count=sum(
                item.scenario_id == template.scenario_id
                and item.final_status is PaymentStatus.FAILED
                for item in truth
            ),
        )
        for template in templates
    )


def _delivery_summaries(
    deliveries: Sequence[WebhookDeliveryInstruction],
) -> tuple[DeliveryCaseSummary, ...]:
    return tuple(
        DeliveryCaseSummary(
            reliability_case=reliability_case,
            delivery_attempts=sum(
                delivery.reliability_case is reliability_case for delivery in deliveries
            ),
            expected_rejections=sum(
                delivery.reliability_case is reliability_case
                and delivery.expected_disposition
                is ExpectedDeliveryDisposition.REJECTED_SIGNATURE
                for delivery in deliveries
            ),
            expected_duplicates=sum(
                delivery.reliability_case is reliability_case
                and delivery.expected_disposition is ExpectedDeliveryDisposition.DUPLICATE
                for delivery in deliveries
            ),
        )
        for reliability_case in ReliabilityCase
    )


def _experiment_design() -> ExperimentDesign:
    return ExperimentDesign(
        design_id="experiment_design_v1",
        frozen_at=datetime(2026, 8, 31, tzinfo=UTC),
        assignment_namespace="assignment_v1",
        outcome_namespace="outcome_v1",
        treatment_allocation_bps=8_000,
        control_allocation_bps=2_000,
        strata=("method", "issuer", "amount_band"),
        control_recovery_rate_bps=1_500,
        treatment_recovery_rate_bps=4_500,
        attribution_window_seconds=86_400,
    )


def build_dataset() -> GeneratedDataset:
    """Build all truth artifacts in memory with no filesystem or clock dependency."""

    templates = _scenario_templates()
    tuning = _build_partition(DatasetSplit.TUNING, _TUNING_START, templates)
    heldout = _build_partition(DatasetSplit.HELDOUT, _HELDOUT_START, templates)
    (
        event_map,
        duplicate_event_id,
        delayed_event_id,
        out_of_order_event_ids,
        security_targets,
    ) = _apply_reliability_timing(tuning, heldout)
    deliveries = _build_delivery_schedule(
        event_map,
        duplicate_event_id,
        delayed_event_id,
        out_of_order_event_ids,
        security_targets,
    )

    event_paths = {
        DatasetSplit.TUNING: "fixtures/generated/tuning.normalized_events.v1.jsonl",
        DatasetSplit.HELDOUT: "fixtures/generated/heldout.normalized_events.v1.jsonl",
    }
    truth_paths = {
        DatasetSplit.TUNING: "fixtures/generated/tuning.attempt_truth.v1.jsonl",
        DatasetSplit.HELDOUT: "fixtures/generated/heldout.attempt_truth.v1.jsonl",
    }
    partition_events = {
        DatasetSplit.TUNING: tuple(
            sorted(
                (event_map[event.razorpay_event_id] for event in tuning.events),
                key=lambda event: (event.received_at, event.razorpay_event_id),
            )
        ),
        DatasetSplit.HELDOUT: tuple(
            sorted(
                (event_map[event.razorpay_event_id] for event in heldout.events),
                key=lambda event: (event.received_at, event.razorpay_event_id),
            )
        ),
    }
    artifacts = (
        _artifact(event_paths[DatasetSplit.TUNING], partition_events[DatasetSplit.TUNING]),
        _artifact(truth_paths[DatasetSplit.TUNING], tuning.truth),
        _artifact(event_paths[DatasetSplit.HELDOUT], partition_events[DatasetSplit.HELDOUT]),
        _artifact(truth_paths[DatasetSplit.HELDOUT], heldout.truth),
        _artifact("fixtures/generated/webhook_deliveries.v1.jsonl", deliveries),
    )
    artifact_digests = tuple(
        ArtifactDigest(
            path=artifact.path,
            sha256=artifact.sha256,
            bytes=len(artifact.content),
            records=artifact.records,
        )
        for artifact in artifacts
    )
    all_truth = (*tuning.truth, *heldout.truth)
    partitions = (
        DatasetPartition(
            split=DatasetSplit.TUNING,
            starts_at=tuning.starts_at,
            ends_at=tuning.ends_at,
            payment_attempts=len(tuning.truth),
            normalized_events=len(tuning.events),
            event_artifact=event_paths[DatasetSplit.TUNING],
            truth_artifact=truth_paths[DatasetSplit.TUNING],
        ),
        DatasetPartition(
            split=DatasetSplit.HELDOUT,
            starts_at=heldout.starts_at,
            ends_at=heldout.ends_at,
            payment_attempts=len(heldout.truth),
            normalized_events=len(heldout.events),
            event_artifact=event_paths[DatasetSplit.HELDOUT],
            truth_artifact=truth_paths[DatasetSplit.HELDOUT],
        ),
    )
    manifest = SyntheticDatasetManifest(
        dataset_id=_DATASET_ID,
        generator_version=_GENERATOR_VERSION,
        deterministic_seed=_SEED,
        merchant_id=_MERCHANT_ID,
        currency=_CURRENCY,
        total_payment_attempts=len(all_truth),
        total_normalized_events=len(event_map),
        partitions=partitions,
        scenarios=_materialize_scenarios(templates, all_truth),
        delivery_cases=_delivery_summaries(deliveries),
        experiment_design=_experiment_design(),
        artifacts=artifact_digests,
    )
    manifest_content = _canonical_json(manifest)
    return GeneratedDataset(
        artifacts=artifacts,
        manifest=manifest,
        manifest_content=manifest_content,
        manifest_sha256=hashlib.sha256(manifest_content).hexdigest(),
    )


def _write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    temporary_path.write_bytes(content)
    temporary_path.replace(path)


def write_dataset(root: Path = _REPOSITORY_ROOT) -> GeneratedDataset:
    """Write deterministic generated artifacts and their committed manifest."""

    dataset = build_dataset()
    for artifact in dataset.artifacts:
        _write_atomic(root / artifact.path, artifact.content)
    _write_atomic(root / _MANIFEST_PATH, dataset.manifest_content)
    _write_atomic(
        root / _MANIFEST_DIGEST_PATH,
        f"{dataset.manifest_sha256}  default.v1.json\n".encode(),
    )
    return dataset


def check_dataset(root: Path = _REPOSITORY_ROOT) -> list[str]:
    """Return drift findings without requiring generated JSONL files to be committed."""

    dataset = build_dataset()
    findings: list[str] = []
    expected_files = {
        _MANIFEST_PATH: dataset.manifest_content,
        _MANIFEST_DIGEST_PATH: f"{dataset.manifest_sha256}  default.v1.json\n".encode(),
    }
    for relative_path, expected_content in expected_files.items():
        path = root / relative_path
        if not path.is_file():
            findings.append(f"missing {relative_path}")
        elif path.read_bytes() != expected_content:
            findings.append(f"stale {relative_path}")

    for artifact in dataset.artifacts:
        path = root / artifact.path
        if path.exists() and path.read_bytes() != artifact.content:
            findings.append(f"stale {artifact.path}")
    return findings


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed manifest and any locally generated artifacts",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=_REPOSITORY_ROOT,
        help="repository root used for generated output or verification",
    )
    return parser


def main() -> None:
    """Generate the default data set or fail when its identity has drifted."""

    arguments = _parser().parse_args()
    root = arguments.output_root.resolve()
    if arguments.check:
        findings = check_dataset(root)
        if findings:
            sys.stderr.write("\n".join(findings) + "\n")
            raise SystemExit(1)
        dataset = build_dataset()
        sys.stdout.write(
            f"synthetic dataset is current: {dataset.manifest_sha256} "
            f"({dataset.manifest.total_payment_attempts} attempts)\n"
        )
        return

    dataset = write_dataset(root)
    sys.stdout.write(
        f"generated {dataset.manifest.total_payment_attempts} payment attempts; "
        f"manifest sha256 {dataset.manifest_sha256}\n"
    )


if __name__ == "__main__":  # pragma: no cover
    main()
