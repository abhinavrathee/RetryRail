"""Precommitted detector-v2 development and nonce-derived blind data generator."""

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel

from retryrail.contracts.domain import CohortDimension, CohortPredicate
from retryrail.events.models import (
    ErrorEvidence,
    NormalizedPaymentEvent,
    PaymentEventType,
    PaymentMethod,
    PaymentSnapshot,
    PaymentStatus,
)
from retryrail.synthetic.models import ArtifactDigest, ScenarioKind
from retryrail.synthetic.v2_models import (
    V2AttemptTruth,
    V2DatasetManifest,
    V2DatasetRole,
    V2EvaluationProtocol,
    V2ReleaseTargets,
    V2ScenarioDefinition,
    V2ScenarioFamily,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_GENERATOR_VERSION = "detector_v2_generator_v1_0_0"
_DEVELOPMENT_DATASET_ID = "retryrail_detector_v2_development_v1"
_BLIND_DATASET_ID = "retryrail_detector_v2_blind_v1"
_PROTOCOL_ID = "detector_v2_protocol_v1"
_MERCHANT_ID = "merchant_synthetic_001"
_CURRENCY = "INR"
_ATTEMPT_INTERVAL_SECONDS = 30
_ATTEMPTS = 5_760
_METHOD_ISSUER_COHORT_SIZE = 2
_DEVELOPMENT_START = datetime(2026, 9, 15, tzinfo=UTC)
_BLIND_START = datetime(2026, 10, 1, tzinfo=UTC)
_DEVELOPMENT_SEED = "retryrail_detector_v2_development_seed_v1"
_DEVELOPMENT_MANIFEST_PATH = "fixtures/manifests/detector-v2-development.v1.json"
_DEVELOPMENT_DIGEST_PATH = "fixtures/manifests/detector-v2-development.v1.sha256"
_PROTOCOL_PATH = "evals/protocols/detector_v2.protocol.json"
_TEST_BLIND_NONCES = (
    "detector-v2-test-nonce-alpha",
    "detector-v2-test-nonce-beta",
)
_BLIND_NONCE_MINIMUM_CHARACTERS = 16
_UNRESOLVED_CHOICE = "weighted choice target must resolve"


@dataclass(frozen=True, slots=True)
class ScenarioRecipe:
    """Generator-only recipe fixed before detector-v2 candidate development."""

    scenario_id: str
    role: V2DatasetRole
    family: V2ScenarioFamily
    kind: ScenarioKind
    starts_at: datetime
    ends_at: datetime
    cohort: tuple[CohortPredicate, ...]
    baseline_failure_rate_bps: int
    seeded_failure_rate_bps: int
    root_cause: ErrorEvidence
    expected_gate_reason: str


@dataclass(frozen=True, slots=True)
class GeneratedV2Artifact:
    """One deterministic in-memory artifact and its content identity."""

    path: str
    content: bytes
    records: int

    @property
    def sha256(self) -> str:
        """Return the lowercase content digest."""

        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True, slots=True)
class _PartitionBuild:
    role: V2DatasetRole
    starts_at: datetime
    ends_at: datetime
    events: tuple[NormalizedPaymentEvent, ...]
    truth: tuple[V2AttemptTruth, ...]
    scenarios: tuple[V2ScenarioDefinition, ...]
    seed_commitment_sha256: str


@dataclass(frozen=True, slots=True)
class GeneratedV2Dataset:
    """Complete development or post-prediction blind evidence package."""

    event_artifact: GeneratedV2Artifact
    truth_artifact: GeneratedV2Artifact
    manifest: V2DatasetManifest
    manifest_content: bytes
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class V2BlindRuntime:
    """Blind runtime input with no scenario definitions or truth labels."""

    dataset_id: str
    seed_commitment_sha256: str
    starts_at: datetime
    ends_at: datetime
    payment_attempts: int
    event_artifact: GeneratedV2Artifact


@dataclass(frozen=True, slots=True)
class V2BlindTruth:
    """Blind labels loaded only after predictions have been persisted."""

    dataset_id: str
    seed_commitment_sha256: str
    normalized_events: int
    scenarios: tuple[V2ScenarioDefinition, ...]
    truth_artifact: GeneratedV2Artifact


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _seed_material(role: V2DatasetRole, nonce: str | None) -> str:
    if role is V2DatasetRole.DEVELOPMENT:
        if nonce is not None:
            msg = "development data does not accept a nonce"
            raise ValueError(msg)
        return _DEVELOPMENT_SEED
    if nonce is None or len(nonce) < _BLIND_NONCE_MINIMUM_CHARACTERS:
        msg = "blind nonce must contain at least 16 characters"
        raise ValueError(msg)
    return _digest(f"retryrail_detector_v2_blind\x1f{nonce}")


def _validate_official_nonce(nonce: str, *, official: bool) -> None:
    _seed_material(V2DatasetRole.BLIND, nonce)
    if official and nonce in _TEST_BLIND_NONCES:
        msg = "test nonces cannot be used for an official blind evaluation"
        raise ValueError(msg)


def _bucket(seed: str, namespace: str, modulo: int, *parts: object) -> int:
    if modulo <= 0:
        msg = "modulo must be positive"
        raise ValueError(msg)
    material = "\x1f".join((seed, namespace, *(str(item) for item in parts))).encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big") % modulo


def _weighted_choice[ChoiceT](
    seed: str,
    namespace: str,
    choices: Sequence[tuple[ChoiceT, int]],
    *parts: object,
) -> ChoiceT:
    total = sum(weight for _, weight in choices)
    if total <= 0 or any(weight <= 0 for _, weight in choices):
        msg = "weighted choices require positive weights"
        raise ValueError(msg)
    target = _bucket(seed, namespace, total, *parts)
    cumulative = 0
    for choice, weight in choices:
        cumulative += weight
        if target < cumulative:
            return choice
    raise AssertionError(_UNRESOLVED_CHOICE)


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


def _provider_error(method: PaymentMethod, variant: int) -> ErrorEvidence:
    if method is PaymentMethod.NETBANKING or variant % 2 == 0:
        return ErrorEvidence(
            code="GATEWAY_ERROR",
            source="bank",
            step="payment_authentication",
            reason="issuer_unavailable",
        )
    return ErrorEvidence(
        code="SERVER_ERROR",
        source="gateway",
        step="payment_processing",
        reason="payment_timed_out",
    )


def _cohort(method: PaymentMethod, issuer: str | None = None) -> tuple[CohortPredicate, ...]:
    result = [
        CohortPredicate(dimension=CohortDimension.METHOD, value=method.value)
    ]
    if issuer is not None:
        result.append(CohortPredicate(dimension=CohortDimension.ISSUER, value=issuer))
    return tuple(result)


def _development_recipes() -> tuple[ScenarioRecipe, ...]:
    start = _DEVELOPMENT_START
    return (
        _recipe(
            "dev_01",
            V2ScenarioFamily.METHOD_PROVIDER_DEGRADATION,
            partition_start=start,
            start_hour=4,
            duration_hours=2,
            method=PaymentMethod.CARD,
        ),
        _recipe(
            "dev_02",
            V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION,
            partition_start=start,
            start_hour=8,
            duration_hours=3,
            method=PaymentMethod.NETBANKING,
            issuer="issuer_synthetic_beta",
        ),
        _recipe(
            "dev_03",
            V2ScenarioFamily.CUSTOMER_BEHAVIOR_SPIKE,
            partition_start=start,
            start_hour=13,
            duration_hours=2,
            method=PaymentMethod.UPI,
        ),
        _recipe(
            "dev_04",
            V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION,
            partition_start=start,
            start_hour=18,
            duration_hours=2,
            method=PaymentMethod.CARD,
            issuer="issuer_synthetic_gamma",
        ),
        _recipe(
            "dev_05",
            V2ScenarioFamily.LOW_VOLUME_SPIKE,
            partition_start=start,
            start_hour=24,
            duration_hours=1,
            method=PaymentMethod.WALLET,
            issuer="wallet_synthetic_amber",
        ),
        _recipe(
            "dev_06",
            V2ScenarioFamily.METHOD_PROVIDER_DEGRADATION,
            partition_start=start,
            start_hour=28,
            duration_hours=2,
            method=PaymentMethod.UPI,
        ),
        _recipe(
            "dev_07",
            V2ScenarioFamily.TRANSIENT_PROVIDER_BURST,
            partition_start=start,
            start_hour=33,
            duration_hours=1 / 6,
            method=PaymentMethod.NETBANKING,
        ),
        _recipe(
            "dev_08",
            V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION,
            partition_start=start,
            start_hour=36,
            duration_hours=3,
            method=PaymentMethod.UPI,
            issuer="issuer_synthetic_beta",
        ),
        _recipe(
            "dev_09",
            V2ScenarioFamily.METHOD_PROVIDER_DEGRADATION,
            partition_start=start,
            start_hour=41,
            duration_hours=2,
            method=PaymentMethod.NETBANKING,
        ),
        _recipe(
            "dev_10",
            V2ScenarioFamily.CUSTOMER_BEHAVIOR_SPIKE,
            partition_start=start,
            start_hour=45,
            duration_hours=1.5,
            method=PaymentMethod.CARD,
        ),
    )


def _recipe(
    suffix: str,
    family: V2ScenarioFamily,
    *,
    partition_start: datetime,
    start_hour: int,
    duration_hours: float,
    method: PaymentMethod,
    issuer: str | None = None,
    role: V2DatasetRole = V2DatasetRole.DEVELOPMENT,
    variant: int = 0,
) -> ScenarioRecipe:
    true_incident = family in {
        V2ScenarioFamily.METHOD_PROVIDER_DEGRADATION,
        V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION,
    }
    if family is V2ScenarioFamily.CUSTOMER_BEHAVIOR_SPIKE:
        root_cause = _normal_error(method)
        seeded_rate = 6_500
        gate_reason = "blocked_by_non_actionable_error_source"
    elif family is V2ScenarioFamily.LOW_VOLUME_SPIKE:
        root_cause = ErrorEvidence(
            code="GATEWAY_ERROR",
            source="wallet",
            step="payment_processing",
            reason="payment_timed_out",
        )
        seeded_rate = 10_000
        gate_reason = "blocked_by_minimum_sample_gate"
    elif family is V2ScenarioFamily.TRANSIENT_PROVIDER_BURST:
        root_cause = _provider_error(method, variant)
        seeded_rate = 9_500
        gate_reason = "blocked_by_confirmation_gate"
    else:
        root_cause = _provider_error(method, variant)
        seeded_rate = (
            6_500
            if family is V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION
            else 4_800
        )
        gate_reason = "statistical_and_business_gates_pass"
    cohort_issuer = (
        issuer
        if family
        in {
            V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION,
            V2ScenarioFamily.LOW_VOLUME_SPIKE,
        }
        else None
    )
    return ScenarioRecipe(
        scenario_id=f"scenario_v2_{suffix}_{family.value}",
        role=role,
        family=family,
        kind=(ScenarioKind.TRUE_INCIDENT if true_incident else ScenarioKind.HARD_NEGATIVE),
        starts_at=partition_start + timedelta(hours=start_hour),
        ends_at=partition_start + timedelta(hours=start_hour + duration_hours),
        cohort=_cohort(method, cohort_issuer),
        baseline_failure_rate_bps=_base_failure_rate(method),
        seeded_failure_rate_bps=seeded_rate,
        root_cause=root_cause,
        expected_gate_reason=gate_reason,
    )


def _blind_recipes(seed: str) -> tuple[ScenarioRecipe, ...]:
    family_pool = (
        V2ScenarioFamily.METHOD_PROVIDER_DEGRADATION,
        V2ScenarioFamily.METHOD_PROVIDER_DEGRADATION,
        V2ScenarioFamily.METHOD_PROVIDER_DEGRADATION,
        V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION,
        V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION,
        V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION,
        V2ScenarioFamily.CUSTOMER_BEHAVIOR_SPIKE,
        V2ScenarioFamily.CUSTOMER_BEHAVIOR_SPIKE,
        V2ScenarioFamily.LOW_VOLUME_SPIKE,
        V2ScenarioFamily.TRANSIENT_PROVIDER_BURST,
    )
    families = tuple(
        value
        for _, value in sorted(
            (
                (_bucket(seed, "family_order", 1_000_000, index), family)
                for index, family in enumerate(family_pool)
            ),
            key=lambda item: item[0],
        )
    )
    start_hours = (4, 8, 13, 18, 24, 28, 33, 36, 41, 45)
    duration_by_family = {
        V2ScenarioFamily.METHOD_PROVIDER_DEGRADATION: 2.0,
        V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION: 3.0,
        V2ScenarioFamily.CUSTOMER_BEHAVIOR_SPIKE: 2.0,
        V2ScenarioFamily.LOW_VOLUME_SPIKE: 1.0,
        V2ScenarioFamily.TRANSIENT_PROVIDER_BURST: 1 / 6,
    }
    recipes: list[ScenarioRecipe] = []
    for index, (family, start_hour) in enumerate(
        zip(families, start_hours, strict=True),
        start=1,
    ):
        issuer: str | None
        if family is V2ScenarioFamily.LOW_VOLUME_SPIKE:
            method = PaymentMethod.WALLET
            issuer = _weighted_choice(
                seed,
                "blind_wallet",
                (("wallet_synthetic_amber", 1), ("wallet_synthetic_blue", 1)),
                index,
            )
        else:
            eligible_methods = (
                (
                    (PaymentMethod.CARD, 1),
                    (PaymentMethod.UPI, 1),
                )
                if family is V2ScenarioFamily.CUSTOMER_BEHAVIOR_SPIKE
                else (
                    (PaymentMethod.CARD, 1),
                    (PaymentMethod.UPI, 1),
                    (PaymentMethod.NETBANKING, 1),
                )
            )
            method = _weighted_choice(seed, "blind_method", eligible_methods, index)
            issuer = (
                _weighted_choice(
                    seed,
                    "blind_issuer",
                    (
                        ("issuer_synthetic_alpha", 1),
                        ("issuer_synthetic_beta", 1),
                        ("issuer_synthetic_gamma", 1),
                    ),
                    index,
                    method.value,
                )
                if family is V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION
                else None
            )
        recipes.append(
            _recipe(
                f"blind_{index:02d}",
                family,
                partition_start=_BLIND_START,
                start_hour=start_hour,
                duration_hours=duration_by_family[family],
                method=method,
                issuer=issuer,
                role=V2DatasetRole.BLIND,
                variant=_bucket(seed, "provider_variant", 2, index),
            )
        )
    return tuple(recipes)


def _method(seed: str, role: V2DatasetRole, index: int) -> PaymentMethod:
    return _weighted_choice(
        seed,
        "method",
        (
            (PaymentMethod.CARD, 35),
            (PaymentMethod.UPI, 40),
            (PaymentMethod.NETBANKING, 20),
            (PaymentMethod.WALLET, 5),
        ),
        role.value,
        index,
    )


def _issuer(seed: str, role: V2DatasetRole, index: int, method: PaymentMethod) -> str:
    choices: Sequence[tuple[str, int]]
    if method is PaymentMethod.WALLET:
        choices = (("wallet_synthetic_amber", 1), ("wallet_synthetic_blue", 1))
    else:
        choices = (
            ("issuer_synthetic_alpha", 45),
            ("issuer_synthetic_beta", 35),
            ("issuer_synthetic_gamma", 20),
        )
    return _weighted_choice(seed, "issuer", choices, role.value, index, method.value)


def _amount(seed: str, role: V2DatasetRole, index: int) -> int:
    return _weighted_choice(
        seed,
        "amount",
        ((49_900, 15), (99_900, 30), (149_900, 25), (249_900, 20), (499_900, 10)),
        role.value,
        index,
    )


def _active_recipe(
    recipes: Sequence[ScenarioRecipe],
    occurred_at: datetime,
) -> ScenarioRecipe | None:
    return next(
        (item for item in recipes if item.starts_at <= occurred_at < item.ends_at),
        None,
    )


def _force_sparse_membership(
    recipe: ScenarioRecipe | None,
    occurred_at: datetime,
    method: PaymentMethod,
    issuer: str,
) -> tuple[PaymentMethod, str]:
    if recipe is None:
        return method, issuer
    elapsed_seconds = int((occurred_at - recipe.starts_at).total_seconds())
    target_method = PaymentMethod(recipe.cohort[0].value)
    target_issuer = (
        recipe.cohort[1].value
        if len(recipe.cohort) == _METHOD_ISSUER_COHORT_SIZE
        else None
    )
    force = False
    if recipe.family is V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION:
        force = elapsed_seconds % 600 == 0
    elif recipe.family is V2ScenarioFamily.LOW_VOLUME_SPIKE:
        force = elapsed_seconds in {900, 2_700}
    elif recipe.family is V2ScenarioFamily.TRANSIENT_PROVIDER_BURST:
        force = elapsed_seconds % 120 == 0
    if not force:
        return method, issuer
    if target_issuer is not None:
        return target_method, target_issuer
    if method is target_method:
        return target_method, issuer
    return target_method, "issuer_synthetic_alpha"


def _matches(recipe: ScenarioRecipe, method: PaymentMethod, issuer: str) -> bool:
    values = {
        CohortDimension.METHOD: method.value,
        CohortDimension.ISSUER: issuer,
    }
    return all(values.get(item.dimension) == item.value for item in recipe.cohort)


def _identifier(role: V2DatasetRole, index: int, suffix: str) -> str:
    prefix = "dev" if role is V2DatasetRole.DEVELOPMENT else "blind"
    return f"evt_v2_{prefix}_{index:05d}_{suffix}"


def _build_partition(
    role: V2DatasetRole,
    starts_at: datetime,
    recipes: Sequence[ScenarioRecipe],
    *,
    nonce: str | None,
) -> _PartitionBuild:
    seed = _seed_material(role, nonce)
    events: list[NormalizedPaymentEvent] = []
    truth: list[V2AttemptTruth] = []
    role_prefix = "dev" if role is V2DatasetRole.DEVELOPMENT else "blind"
    for index in range(_ATTEMPTS):
        occurred_at = starts_at + timedelta(seconds=index * _ATTEMPT_INTERVAL_SECONDS)
        active = _active_recipe(recipes, occurred_at)
        method = _method(seed, role, index)
        issuer = _issuer(seed, role, index, method)
        method, issuer = _force_sparse_membership(active, occurred_at, method, issuer)
        matching = active if active is not None and _matches(active, method, issuer) else None
        amount_subunits = _amount(seed, role, index)
        failure_rate = (
            matching.seeded_failure_rate_bps
            if matching is not None
            else _base_failure_rate(method)
        )
        failed = _bucket(seed, "failure", 10_000, role.value, index) < failure_rate
        if matching is not None and matching.family is V2ScenarioFamily.LOW_VOLUME_SPIKE:
            failed = True
        attempt_id = f"attempt_v2_{role_prefix}_{index:05d}"
        payment_id = f"pay_v2_{role_prefix}_{index:05d}"
        event_ids: list[str] = []
        if failed:
            event_id = _identifier(role, index, "failed")
            event_ids.append(event_id)
            events.append(
                NormalizedPaymentEvent(
                    merchant_id=_MERCHANT_ID,
                    razorpay_event_id=event_id,
                    event_type=PaymentEventType.FAILED,
                    occurred_at=occurred_at,
                    received_at=occurred_at
                    + timedelta(seconds=1 + _bucket(seed, "receive", 4, index, "failed")),
                    synthetic=True,
                    payment=PaymentSnapshot(
                        payment_id=payment_id,
                        status=PaymentStatus.FAILED,
                        amount_subunits=amount_subunits,
                        currency=_CURRENCY,
                        method=method,
                        issuer=issuer,
                        error=(
                            matching.root_cause
                            if matching is not None
                            else _normal_error(method)
                        ),
                    ),
                )
            )
        else:
            authorized_id = _identifier(role, index, "authorized")
            captured_id = _identifier(role, index, "captured")
            captured_at = occurred_at + timedelta(
                seconds=10 + _bucket(seed, "capture_delay", 111, index)
            )
            event_ids.extend((authorized_id, captured_id))
            events.extend(
                (
                    NormalizedPaymentEvent(
                        merchant_id=_MERCHANT_ID,
                        razorpay_event_id=authorized_id,
                        event_type=PaymentEventType.AUTHORIZED,
                        occurred_at=occurred_at,
                        received_at=occurred_at
                        + timedelta(seconds=1 + _bucket(seed, "receive", 4, index, "auth")),
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
                        + timedelta(seconds=1 + _bucket(seed, "receive", 4, index, "capture")),
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
        truth.append(
            V2AttemptTruth(
                attempt_id=attempt_id,
                payment_id=payment_id,
                dataset_role=role,
                occurred_at=occurred_at,
                amount_subunits=amount_subunits,
                currency=_CURRENCY,
                method=method,
                issuer=issuer,
                failed=failed,
                normalized_event_ids=tuple(event_ids),
                scenario_id=matching.scenario_id if matching is not None else None,
                expected_incident_member=(
                    matching is not None and matching.kind is ScenarioKind.TRUE_INCIDENT
                ),
            )
        )
    scenarios = _materialize_scenarios(recipes, truth)
    return _PartitionBuild(
        role=role,
        starts_at=starts_at,
        ends_at=starts_at + timedelta(seconds=_ATTEMPTS * _ATTEMPT_INTERVAL_SECONDS),
        events=tuple(sorted(events, key=lambda item: (item.received_at, item.razorpay_event_id))),
        truth=tuple(truth),
        scenarios=scenarios,
        seed_commitment_sha256=_digest(
            _DEVELOPMENT_SEED if nonce is None else nonce
        ),
    )


def _materialize_scenarios(
    recipes: Sequence[ScenarioRecipe],
    truth: Sequence[V2AttemptTruth],
) -> tuple[V2ScenarioDefinition, ...]:
    return tuple(
        V2ScenarioDefinition(
            scenario_id=recipe.scenario_id,
            dataset_role=recipe.role,
            family=recipe.family,
            kind=recipe.kind,
            starts_at=recipe.starts_at,
            ends_at=recipe.ends_at,
            affected_cohort=recipe.cohort,
            baseline_failure_rate_bps=recipe.baseline_failure_rate_bps,
            seeded_failure_rate_bps=recipe.seeded_failure_rate_bps,
            expected_root_cause=recipe.root_cause,
            should_open_incident=recipe.kind is ScenarioKind.TRUE_INCIDENT,
            expected_gate_reason=recipe.expected_gate_reason,
            actual_attempt_count=sum(item.scenario_id == recipe.scenario_id for item in truth),
            actual_failure_count=sum(
                item.scenario_id == recipe.scenario_id and item.failed for item in truth
            ),
        )
        for recipe in recipes
    )


def _json_lines(values: Iterable[BaseModel]) -> bytes:
    return (
        "\n".join(
            json.dumps(
                item.model_dump(mode="json", exclude_none=True),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            for item in values
        )
        + "\n"
    ).encode()


def _canonical_json(value: BaseModel) -> bytes:
    return (
        json.dumps(
            value.model_dump(mode="json", exclude_none=True),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode()


def _artifact(path: str, values: Sequence[BaseModel]) -> GeneratedV2Artifact:
    return GeneratedV2Artifact(path=path, content=_json_lines(values), records=len(values))


def _assemble_dataset(
    partition: _PartitionBuild,
    *,
    dataset_id: str,
    event_path: str,
    truth_path: str,
) -> GeneratedV2Dataset:
    event_artifact = _artifact(event_path, partition.events)
    truth_artifact = _artifact(truth_path, partition.truth)
    manifest = V2DatasetManifest(
        dataset_id=dataset_id,
        generator_version=_GENERATOR_VERSION,
        dataset_role=partition.role,
        seed_commitment_sha256=partition.seed_commitment_sha256,
        merchant_id=_MERCHANT_ID,
        currency=_CURRENCY,
        starts_at=partition.starts_at,
        ends_at=partition.ends_at,
        payment_attempts=len(partition.truth),
        normalized_events=len(partition.events),
        true_incident_count=sum(
            item.kind is ScenarioKind.TRUE_INCIDENT for item in partition.scenarios
        ),
        hard_negative_count=sum(
            item.kind is ScenarioKind.HARD_NEGATIVE for item in partition.scenarios
        ),
        event_artifact=event_path,
        truth_artifact=truth_path,
        scenarios=partition.scenarios,
        artifacts=(
            ArtifactDigest(
                path=event_artifact.path,
                sha256=event_artifact.sha256,
                bytes=len(event_artifact.content),
                records=event_artifact.records,
            ),
            ArtifactDigest(
                path=truth_artifact.path,
                sha256=truth_artifact.sha256,
                bytes=len(truth_artifact.content),
                records=truth_artifact.records,
            ),
        ),
    )
    manifest_content = _canonical_json(manifest)
    return GeneratedV2Dataset(
        event_artifact=event_artifact,
        truth_artifact=truth_artifact,
        manifest=manifest,
        manifest_content=manifest_content,
        manifest_sha256=hashlib.sha256(manifest_content).hexdigest(),
    )


def build_development_dataset() -> GeneratedV2Dataset:
    """Build the only new dataset permitted for v2 candidate tuning."""

    partition = _build_partition(
        V2DatasetRole.DEVELOPMENT,
        _DEVELOPMENT_START,
        _development_recipes(),
        nonce=None,
    )
    return _assemble_dataset(
        partition,
        dataset_id=_DEVELOPMENT_DATASET_ID,
        event_path="fixtures/generated/detector_v2/development.normalized_events.v1.jsonl",
        truth_path="evals/generated/detector_v2/development.attempt_truth.v1.jsonl",
    )


def build_blind_runtime(nonce: str, *, official: bool) -> V2BlindRuntime:
    """Build only normalized blind events; no label object crosses this boundary."""

    _validate_official_nonce(nonce, official=official)
    seed = _seed_material(V2DatasetRole.BLIND, nonce)
    partition = _build_partition(
        V2DatasetRole.BLIND,
        _BLIND_START,
        _blind_recipes(seed),
        nonce=nonce,
    )
    return V2BlindRuntime(
        dataset_id=_BLIND_DATASET_ID,
        seed_commitment_sha256=partition.seed_commitment_sha256,
        starts_at=partition.starts_at,
        ends_at=partition.ends_at,
        payment_attempts=len(partition.truth),
        event_artifact=_artifact(
            "fixtures/generated/detector_v2/blind.normalized_events.v1.jsonl",
            partition.events,
        ),
    )


def load_blind_truth(nonce: str, *, official: bool) -> V2BlindTruth:
    """Materialize blind labels only after the evaluator has persisted predictions."""

    _validate_official_nonce(nonce, official=official)
    seed = _seed_material(V2DatasetRole.BLIND, nonce)
    partition = _build_partition(
        V2DatasetRole.BLIND,
        _BLIND_START,
        _blind_recipes(seed),
        nonce=nonce,
    )
    return V2BlindTruth(
        dataset_id=_BLIND_DATASET_ID,
        seed_commitment_sha256=partition.seed_commitment_sha256,
        normalized_events=len(partition.events),
        scenarios=partition.scenarios,
        truth_artifact=_artifact(
            "evals/blind/detector_v2/blind.attempt_truth.v1.jsonl",
            partition.truth,
        ),
    )


def assemble_blind_dataset(
    runtime: V2BlindRuntime,
    truth: V2BlindTruth,
) -> GeneratedV2Dataset:
    """Join blind events and labels only after prediction generation."""

    if (
        runtime.dataset_id != truth.dataset_id
        or runtime.seed_commitment_sha256 != truth.seed_commitment_sha256
    ):
        msg = "blind runtime and truth commitments do not match"
        raise ValueError(msg)
    manifest = V2DatasetManifest(
        dataset_id=runtime.dataset_id,
        generator_version=_GENERATOR_VERSION,
        dataset_role=V2DatasetRole.BLIND,
        seed_commitment_sha256=runtime.seed_commitment_sha256,
        merchant_id=_MERCHANT_ID,
        currency=_CURRENCY,
        starts_at=runtime.starts_at,
        ends_at=runtime.ends_at,
        payment_attempts=runtime.payment_attempts,
        normalized_events=truth.normalized_events,
        true_incident_count=sum(
            item.kind is ScenarioKind.TRUE_INCIDENT for item in truth.scenarios
        ),
        hard_negative_count=sum(
            item.kind is ScenarioKind.HARD_NEGATIVE for item in truth.scenarios
        ),
        event_artifact=runtime.event_artifact.path,
        truth_artifact=truth.truth_artifact.path,
        scenarios=truth.scenarios,
        artifacts=(
            ArtifactDigest(
                path=runtime.event_artifact.path,
                sha256=runtime.event_artifact.sha256,
                bytes=len(runtime.event_artifact.content),
                records=runtime.event_artifact.records,
            ),
            ArtifactDigest(
                path=truth.truth_artifact.path,
                sha256=truth.truth_artifact.sha256,
                bytes=len(truth.truth_artifact.content),
                records=truth.truth_artifact.records,
            ),
        ),
    )
    manifest_content = _canonical_json(manifest)
    return GeneratedV2Dataset(
        event_artifact=runtime.event_artifact,
        truth_artifact=truth.truth_artifact,
        manifest=manifest,
        manifest_content=manifest_content,
        manifest_sha256=hashlib.sha256(manifest_content).hexdigest(),
    )


def generator_bundle_sha256(root: Path = _REPOSITORY_ROOT) -> str:
    """Bind the protocol to generator code and every schema it consumes."""

    relative_paths = (
        "services/api/app/retryrail/events/models.py",
        "services/api/app/retryrail/synthetic/models.py",
        "services/api/app/retryrail/synthetic/v2_models.py",
        "services/api/app/retryrail/synthetic/v2_generator.py",
    )
    digest = hashlib.sha256()
    for relative_path in relative_paths:
        digest.update(relative_path.encode())
        digest.update(b"\0")
        source = (root / relative_path).read_bytes().replace(b"\r\n", b"\n")
        digest.update(source)
        digest.update(b"\0")
    return digest.hexdigest()


def build_evaluation_protocol(root: Path = _REPOSITORY_ROOT) -> V2EvaluationProtocol:
    """Create the protocol artifact that must remain unchanged through blind scoring."""

    development = build_development_dataset()
    return V2EvaluationProtocol(
        protocol_id=_PROTOCOL_ID,
        precommitted_at=datetime(2026, 9, 1, tzinfo=UTC),
        generator_version=_GENERATOR_VERSION,
        generator_bundle_sha256=generator_bundle_sha256(root),
        development_dataset_id=development.manifest.dataset_id,
        development_manifest_sha256=development.manifest_sha256,
        allowed_development_dataset_ids=(
            "retryrail_default_v1",
            _DEVELOPMENT_DATASET_ID,
        ),
        scenario_family_counts={
            V2ScenarioFamily.METHOD_PROVIDER_DEGRADATION: 3,
            V2ScenarioFamily.ISSUER_PROVIDER_DEGRADATION: 3,
            V2ScenarioFamily.CUSTOMER_BEHAVIOR_SPIKE: 2,
            V2ScenarioFamily.LOW_VOLUME_SPIKE: 1,
            V2ScenarioFamily.TRANSIENT_PROVIDER_BURST: 1,
        },
        forbidden_test_nonce_sha256=tuple(_digest(item) for item in _TEST_BLIND_NONCES),
        release_targets=V2ReleaseTargets(),
        rules=(
            "V1 tuning and consumed held-out data may be used only as development evidence.",
            "The official blind nonce is supplied only after the candidate config is frozen.",
            "Blind normalized events are loaded and predictions persisted before truth labels.",
            "No threshold, algorithm, or matching-rule change is allowed after nonce reveal.",
            "Any code or config change requires a new nonce and a newly identified blind run.",
            "Every hard negative must remain action-ineligible even if an incident is visible.",
            "All results, including failures, are committed as synthetic evidence.",
        ),
    )


def render_v2_committed_artifacts(root: Path = _REPOSITORY_ROOT) -> dict[Path, bytes]:
    """Render only pre-blind artifacts; official blind output cannot be generated here."""

    development = build_development_dataset()
    protocol = build_evaluation_protocol(root)
    return {
        root / _DEVELOPMENT_MANIFEST_PATH: development.manifest_content,
        root / _DEVELOPMENT_DIGEST_PATH: (
            f"{development.manifest_sha256}  detector-v2-development.v1.json\n".encode()
        ),
        root / _PROTOCOL_PATH: _canonical_json(protocol),
    }


def check_v2_artifacts(root: Path = _REPOSITORY_ROOT) -> list[str]:
    """Return drift findings for the frozen generator, protocol and dev manifest."""

    findings: list[str] = []
    for path, expected in render_v2_committed_artifacts(root).items():
        relative = path.relative_to(root).as_posix()
        if not path.is_file():
            findings.append(f"missing {relative}")
        elif path.read_bytes() != expected:
            findings.append(f"stale {relative}")
    return findings


def _write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    temporary_path.write_bytes(content)
    temporary_path.replace(path)


def write_v2_development(root: Path = _REPOSITORY_ROOT) -> GeneratedV2Dataset:
    """Write development data and committed pre-blind identities atomically."""

    development = build_development_dataset()
    _write_atomic(root / development.event_artifact.path, development.event_artifact.content)
    _write_atomic(root / development.truth_artifact.path, development.truth_artifact.content)
    for path, content in render_v2_committed_artifacts(root).items():
        _write_atomic(path, content)
    return development


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--write-development", action="store_true")
    action.add_argument("--print-development-manifest", action="store_true")
    action.add_argument("--print-protocol", action="store_true")
    return parser


def main() -> None:
    """Manage only pre-blind v2 artifacts; no CLI option accepts a blind nonce."""

    arguments = _parser().parse_args()
    if arguments.check:
        findings = check_v2_artifacts()
        if findings:
            sys.stderr.write("\n".join(findings) + "\n")
            raise SystemExit(1)
        development = build_development_dataset()
        sys.stdout.write(
            "detector-v2 protocol and development dataset are current: "
            f"{development.manifest_sha256} ({development.manifest.payment_attempts} attempts)\n"
        )
    elif arguments.write_development:
        development = write_v2_development()
        sys.stdout.write(
            "detector-v2 development data written: "
            f"{development.manifest_sha256}\n"
        )
    elif arguments.print_development_manifest:
        sys.stdout.buffer.write(build_development_dataset().manifest_content)
    else:
        sys.stdout.buffer.write(_canonical_json(build_evaluation_protocol()))


if __name__ == "__main__":  # pragma: no cover
    main()
