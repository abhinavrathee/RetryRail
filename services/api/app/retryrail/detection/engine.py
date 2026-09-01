"""Explainable event-time detector, attribution and incident state machine."""

import hashlib
import math
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from statistics import NormalDist

from retryrail.contracts.domain import CohortDimension, CohortPredicate, IncidentStatus
from retryrail.detection.models import (
    AggregateWindow,
    AttemptFact,
    AttributionItem,
    DetectedIncident,
    DetectionSignal,
    DetectorConfig,
    DetectorGateReason,
    DetectorRunResult,
    DetectorStatistics,
    DiagnosisHypothesis,
    DiagnosisSnapshot,
)
from retryrail.events.models import (
    ErrorEvidence,
    NormalizedPaymentEvent,
    PaymentEventType,
    PaymentMethod,
)

_BPS = 10_000
_PPM = 1_000_000
_MILLI = 1_000


class DetectorInputError(ValueError):
    """Malformed or contradictory event input that must fail closed."""

    reason_code = "DETECTOR_INPUT_INVALID"


class DetectorIdentityConflictError(DetectorInputError):
    """Events attempted to change immutable fields for one payment."""

    reason_code = "DETECTOR_PAYMENT_IDENTITY_CONFLICT"


@dataclass(slots=True)
class _AttemptBuilder:
    merchant_id: str
    payment_id: str
    occurred_at: datetime
    amount_subunits: int
    currency: str
    method: PaymentMethod
    issuer: str | None
    synthetic: bool
    captured: bool
    failed_event: NormalizedPaymentEvent | None
    events: list[NormalizedPaymentEvent]


@dataclass(slots=True)
class _AggregateBuilder:
    merchant_id: str
    cohort_key: str
    cohort: tuple[CohortPredicate, ...]
    window_start: datetime
    window_end: datetime
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    gmv_subunits: int = 0
    failed_gmv_subunits: int = 0
    currency: str | None = None
    synthetic: bool = True


@dataclass(slots=True)
class _ActiveIncident:
    method: PaymentMethod
    signals: list[DetectionSignal]
    healthy_minutes: int = 0
    resolved_at: datetime | None = None


def reconstruct_attempts(
    events: Iterable[NormalizedPaymentEvent],
) -> tuple[AttemptFact, ...]:
    """Collapse duplicate/out-of-order events into terminal, label-free attempts."""

    builders = _build_attempts(events)
    return _finalize_attempts(builders.values())


def _build_attempts(
    events: Iterable[NormalizedPaymentEvent],
) -> dict[tuple[str, str], _AttemptBuilder]:
    unique_events: dict[tuple[str, str], NormalizedPaymentEvent] = {}
    for event in events:
        key = (event.merchant_id, event.razorpay_event_id)
        prior = unique_events.get(key)
        if prior is not None and prior != event:
            raise DetectorIdentityConflictError
        unique_events[key] = event

    builders: dict[tuple[str, str], _AttemptBuilder] = {}
    ordered_events = sorted(
        unique_events.values(),
        key=lambda item: (item.occurred_at, item.received_at, item.razorpay_event_id),
    )
    for event in ordered_events:
        payment = event.payment
        key = (event.merchant_id, payment.payment_id)
        builder = builders.get(key)
        if builder is None:
            builder = _AttemptBuilder(
                merchant_id=event.merchant_id,
                payment_id=payment.payment_id,
                occurred_at=event.occurred_at.astimezone(UTC),
                amount_subunits=payment.amount_subunits,
                currency=payment.currency,
                method=payment.method,
                issuer=payment.issuer,
                synthetic=event.synthetic,
                captured=False,
                failed_event=None,
                events=[],
            )
            builders[key] = builder
        _validate_attempt_identity(builder, event)
        builder.occurred_at = min(builder.occurred_at, event.occurred_at.astimezone(UTC))
        if builder.issuer is None:
            builder.issuer = payment.issuer
        builder.events.append(event)
        if event.event_type is PaymentEventType.CAPTURED:
            builder.captured = True
        elif event.event_type is PaymentEventType.FAILED and builder.failed_event is None:
            builder.failed_event = event
    return builders


def _finalize_attempts(
    builders: Iterable[_AttemptBuilder],
) -> tuple[AttemptFact, ...]:
    facts: list[AttemptFact] = []
    for builder in builders:
        if not builder.captured and builder.failed_event is None:
            continue
        failed = not builder.captured
        error: ErrorEvidence | None = None
        if failed and builder.failed_event is not None:
            error = builder.failed_event.payment.error
        facts.append(
            AttemptFact(
                merchant_id=builder.merchant_id,
                payment_id=builder.payment_id,
                occurred_at=builder.occurred_at,
                amount_subunits=builder.amount_subunits,
                currency=builder.currency,
                method=builder.method,
                issuer=builder.issuer,
                failed=failed,
                error=error,
                event_ids=tuple(
                    sorted({item.razorpay_event_id for item in builder.events})
                ),
                synthetic=builder.synthetic,
            )
        )
    return tuple(sorted(facts, key=lambda item: (item.occurred_at, item.payment_id)))


def _validate_attempt_identity(
    builder: _AttemptBuilder,
    event: NormalizedPaymentEvent,
) -> None:
    payment = event.payment
    if (
        builder.merchant_id != event.merchant_id
        or builder.payment_id != payment.payment_id
        or builder.amount_subunits != payment.amount_subunits
        or builder.currency != payment.currency
        or builder.method is not payment.method
        or builder.synthetic is not event.synthetic
        or (
            builder.issuer is not None
            and payment.issuer is not None
            and builder.issuer != payment.issuer
        )
    ):
        raise DetectorIdentityConflictError


def cohort_key(cohort: Sequence[CohortPredicate]) -> str:
    """Return a canonical readable key for allowlisted exact predicates."""

    ordered = sorted(cohort, key=lambda item: item.dimension.value)
    return "|".join(f"{item.dimension.value}={item.value}" for item in ordered)


def materialize_aggregate_windows(
    attempts: Sequence[AttemptFact],
    *,
    step_minutes: int,
) -> tuple[AggregateWindow, ...]:
    """Build exact method and method/issuer tumbling windows from terminal attempts."""

    builders: dict[tuple[str, str, datetime], _AggregateBuilder] = {}
    for attempt in attempts:
        cohorts: list[tuple[CohortPredicate, ...]] = [
            (
                CohortPredicate(
                    dimension=CohortDimension.METHOD,
                    value=attempt.method.value,
                ),
            )
        ]
        if attempt.issuer is not None:
            cohorts.append(
                (
                    CohortPredicate(
                        dimension=CohortDimension.METHOD,
                        value=attempt.method.value,
                    ),
                    CohortPredicate(
                        dimension=CohortDimension.ISSUER,
                        value=attempt.issuer,
                    ),
                )
            )
        window_start = _floor_time(attempt.occurred_at, step_minutes)
        window_end = window_start + timedelta(minutes=step_minutes)
        for cohort in cohorts:
            key_text = cohort_key(cohort)
            key = (attempt.merchant_id, key_text, window_start)
            builder = builders.get(key)
            if builder is None:
                builder = _AggregateBuilder(
                    merchant_id=attempt.merchant_id,
                    cohort_key=key_text,
                    cohort=cohort,
                    window_start=window_start,
                    window_end=window_end,
                )
                builders[key] = builder
            if builder.currency is not None and builder.currency != attempt.currency:
                raise DetectorIdentityConflictError
            builder.currency = attempt.currency
            builder.attempts += 1
            builder.failures += int(attempt.failed)
            builder.successes += int(not attempt.failed)
            builder.gmv_subunits += attempt.amount_subunits
            builder.failed_gmv_subunits += attempt.amount_subunits if attempt.failed else 0
            builder.synthetic = builder.synthetic and attempt.synthetic

    return tuple(
        AggregateWindow(
            merchant_id=item.merchant_id,
            cohort_key=item.cohort_key,
            cohort=item.cohort,
            window_start=item.window_start,
            window_end=item.window_end,
            attempts=item.attempts,
            successes=item.successes,
            failures=item.failures,
            gmv_subunits=item.gmv_subunits,
            failed_gmv_subunits=item.failed_gmv_subunits,
            currency=item.currency or "INR",
            synthetic=item.synthetic,
        )
        for item in sorted(
            builders.values(),
            key=lambda value: (
                value.merchant_id,
                value.cohort_key,
                value.window_start,
            ),
        )
    )


def proportion_confidence_ppm(
    *,
    current_failures: int,
    current_attempts: int,
    baseline_failures: int,
    baseline_attempts: int,
) -> int:
    """One-sided pooled two-proportion confidence, scaled deterministically."""

    if current_attempts <= 0 or baseline_attempts <= 0:
        return 0
    current_rate = current_failures / current_attempts
    baseline_rate = baseline_failures / baseline_attempts
    pooled = (current_failures + baseline_failures) / (
        current_attempts + baseline_attempts
    )
    if pooled <= 0.0 or pooled >= 1.0:
        if current_rate > baseline_rate:
            return _PPM
        return _PPM // 2
    standard_error = math.sqrt(
        pooled
        * (1.0 - pooled)
        * ((1.0 / current_attempts) + (1.0 / baseline_attempts))
    )
    if standard_error == 0.0:
        return _PPM // 2
    z_score = (current_rate - baseline_rate) / standard_error
    return _scaled(NormalDist().cdf(z_score), _PPM)


class DetectorEngine:
    """Run a frozen, model-free detector over terminal attempt facts."""

    def __init__(self, config: DetectorConfig) -> None:
        self.config = config

    def run(
        self,
        events: Iterable[NormalizedPaymentEvent],
        *,
        partition_started_at: datetime,
        partition_ended_at: datetime,
    ) -> DetectorRunResult:
        """Reconstruct attempts and evaluate every aligned event-time cutoff."""

        attempts = reconstruct_attempts(events)
        return self.run_attempts(
            attempts,
            partition_started_at=partition_started_at,
            partition_ended_at=partition_ended_at,
        )

    def run_attempts(
        self,
        attempts: Sequence[AttemptFact],
        *,
        partition_started_at: datetime,
        partition_ended_at: datetime,
    ) -> DetectorRunResult:
        """Evaluate already-reconstructed attempts without any ground-truth input."""

        start, end, merchants = _validate_run_input(
            attempts,
            partition_started_at,
            partition_ended_at,
        )

        aggregates = materialize_aggregate_windows(
            attempts,
            step_minutes=self.config.step_minutes,
        )
        methods = tuple(sorted({item.method for item in attempts}, key=lambda item: item.value))
        active: dict[PaymentMethod, _ActiveIncident] = {}
        completed: list[_ActiveIncident] = []
        cutoff = start + timedelta(minutes=self.config.step_minutes)
        while cutoff <= end:
            signals, evaluations = self._signals_at_cutoff(
                attempts,
                methods=methods,
                merchants=merchants,
                active=active,
                evaluated_at=cutoff,
                partition_started_at=start,
            )
            self._advance_lifecycle(
                methods=methods,
                signals=signals,
                evaluations=evaluations,
                active=active,
                completed=completed,
                evaluated_at=cutoff,
            )
            cutoff += timedelta(minutes=self.config.step_minutes)

        episodes = (*completed, *active.values())
        incidents = tuple(
            self._finalize_incident(item, attempts)
            for item in sorted(
                episodes,
                key=lambda episode: episode.signals[0].statistics.evaluated_at,
            )
        )
        return DetectorRunResult(
            detector_version=self.config.detector_version,
            partition_started_at=start,
            partition_ended_at=end,
            attempts=tuple(attempts),
            aggregates=aggregates,
            incidents=incidents,
        )

    def _signals_at_cutoff(
        self,
        attempts: Sequence[AttemptFact],
        *,
        methods: Sequence[PaymentMethod],
        merchants: set[str],
        active: dict[PaymentMethod, _ActiveIncident],
        evaluated_at: datetime,
        partition_started_at: datetime,
    ) -> tuple[
        dict[PaymentMethod, DetectionSignal],
        dict[PaymentMethod, DetectorStatistics],
    ]:
        signals: dict[PaymentMethod, DetectionSignal] = {}
        evaluations: dict[PaymentMethod, DetectorStatistics] = {}
        for method in methods:
            active_incident = active.get(method)
            frozen_baseline = None
            if active_incident is not None:
                opening = active_incident.signals[0].statistics
                frozen_baseline = (
                    opening.baseline_started_at,
                    opening.baseline_ended_at,
                )
            statistics, current = self.evaluate_method(
                attempts,
                method=method,
                evaluated_at=evaluated_at,
                partition_started_at=partition_started_at,
                frozen_baseline=frozen_baseline,
            )
            evaluations[method] = statistics
            if statistics.gate_reason is DetectorGateReason.PASSED:
                merchant_id = current[0].merchant_id if current else next(iter(merchants))
                signals[method] = DetectionSignal(
                    merchant_id=merchant_id,
                    method=method,
                    statistics=statistics,
                    evidence_event_ids=_event_ids(current),
                )
        return signals, evaluations

    def _advance_lifecycle(
        self,
        *,
        methods: Sequence[PaymentMethod],
        signals: dict[PaymentMethod, DetectionSignal],
        evaluations: dict[PaymentMethod, DetectorStatistics],
        active: dict[PaymentMethod, _ActiveIncident],
        completed: list[_ActiveIncident],
        evaluated_at: datetime,
    ) -> None:
        for method in methods:
            signal = signals.get(method)
            incident = active.get(method)
            if signal is not None:
                if incident is None:
                    active[method] = _ActiveIncident(method=method, signals=[signal])
                else:
                    incident.signals.append(signal)
                    incident.healthy_minutes = 0
            elif incident is not None:
                statistics = evaluations[method]
                if self._is_healthy(statistics):
                    incident.healthy_minutes += self.config.step_minutes
                    if incident.healthy_minutes >= self.config.healthy_window_minutes:
                        incident.resolved_at = evaluated_at
                        completed.append(incident)
                        del active[method]
                else:
                    incident.healthy_minutes = 0

    def _is_healthy(self, statistics: DetectorStatistics) -> bool:
        """Require observed recovery; low/no traffic cannot resolve an incident."""

        return (
            statistics.current_attempts >= self.config.minimum_current_attempts
            and statistics.baseline_attempts >= self.config.baseline_minimum_attempts
            and statistics.success_rate_drop_bps
            < self.config.minimum_success_rate_drop_bps
        )

    def evaluate_method(
        self,
        attempts: Sequence[AttemptFact],
        *,
        method: PaymentMethod,
        evaluated_at: datetime,
        partition_started_at: datetime,
        frozen_baseline: tuple[datetime, datetime] | None = None,
    ) -> tuple[DetectorStatistics, tuple[AttemptFact, ...]]:
        """Return the first sample-eligible adaptive window and its gate decision."""

        cutoff = _require_aware(evaluated_at)
        start = _require_aware(partition_started_at)
        method_attempts = tuple(item for item in attempts if item.method is method)
        candidates: list[tuple[DetectorStatistics, tuple[AttemptFact, ...]]] = []
        for window_minutes in self.config.current_window_minutes:
            frozen_started_at = (
                _require_aware(frozen_baseline[0])
                if frozen_baseline is not None
                else None
            )
            frozen_ended_at = (
                _require_aware(frozen_baseline[1])
                if frozen_baseline is not None
                else None
            )
            current_started_at = max(
                start,
                cutoff - timedelta(minutes=window_minutes),
                frozen_ended_at or start,
            )
            baseline_ended_at = current_started_at
            baseline_started_at = max(
                start,
                baseline_ended_at
                - timedelta(minutes=self.config.baseline_lookback_minutes),
            )
            if frozen_started_at is not None and frozen_ended_at is not None:
                baseline_started_at = frozen_started_at
                baseline_ended_at = frozen_ended_at
            current = tuple(
                item
                for item in method_attempts
                if current_started_at <= item.occurred_at < cutoff
            )
            baseline = tuple(
                item
                for item in method_attempts
                if baseline_started_at <= item.occurred_at < baseline_ended_at
            )
            statistics = self._statistics(
                evaluated_at=cutoff,
                current_started_at=current_started_at,
                baseline_started_at=baseline_started_at,
                baseline_ended_at=baseline_ended_at,
                current=current,
                baseline=baseline,
                window_minutes=window_minutes,
                fallback_currency=_currency(method_attempts),
            )
            candidates.append((statistics, current))
            if (
                statistics.current_attempts >= self.config.minimum_current_attempts
                and statistics.baseline_attempts
                >= self.config.baseline_minimum_attempts
            ):
                return statistics, current
        if not candidates:
            raise DetectorInputError
        return candidates[-1]

    def _statistics(
        self,
        *,
        evaluated_at: datetime,
        current_started_at: datetime,
        baseline_started_at: datetime,
        baseline_ended_at: datetime,
        current: Sequence[AttemptFact],
        baseline: Sequence[AttemptFact],
        window_minutes: int,
        fallback_currency: str,
    ) -> DetectorStatistics:
        current_failures = sum(item.failed for item in current)
        baseline_failures = sum(item.failed for item in baseline)
        current_attempts = len(current)
        baseline_attempts = len(baseline)
        current_rate = current_failures / current_attempts if current_attempts else 0.0
        baseline_rate = (
            baseline_failures / baseline_attempts if baseline_attempts else 0.0
        )
        drop = max(current_rate - baseline_rate, 0.0)
        ewma = baseline_rate
        cusum = 0.0
        alpha = self.config.ewma_alpha_ppm / _PPM
        allowance = self.config.cusum_allowance_bps / _BPS
        for attempt in sorted(current, key=lambda item: (item.occurred_at, item.payment_id)):
            observation = float(attempt.failed)
            ewma = (alpha * observation) + ((1.0 - alpha) * ewma)
            cusum = max(0.0, cusum + observation - baseline_rate - allowance)
        excess = max(current_failures - (current_attempts * baseline_rate), 0.0)
        excess_failures = _round_half_up(excess)
        failed_gmv = sum(item.amount_subunits for item in current if item.failed)
        current_gmv = sum(item.amount_subunits for item in current)
        at_risk_gmv = max(_round_half_up(failed_gmv - (baseline_rate * current_gmv)), 0)
        confidence = proportion_confidence_ppm(
            current_failures=current_failures,
            current_attempts=current_attempts,
            baseline_failures=baseline_failures,
            baseline_attempts=baseline_attempts,
        )
        ewma_drop_bps = _scaled(max(ewma - baseline_rate, 0.0), _BPS)
        drop_bps = _scaled(drop, _BPS)
        gate_reason = self._gate_reason(
            current_attempts=current_attempts,
            baseline_attempts=baseline_attempts,
            current_failures=current_failures,
            drop_bps=drop_bps,
            confidence_ppm=confidence,
            ewma_drop_bps=ewma_drop_bps,
            cusum_milli=_round_half_up(cusum * _MILLI),
            excess_failures=excess_failures,
            at_risk_gmv_subunits=at_risk_gmv,
        )
        return DetectorStatistics(
            evaluated_at=evaluated_at,
            current_window_minutes=window_minutes,
            current_started_at=current_started_at,
            baseline_started_at=baseline_started_at,
            baseline_ended_at=baseline_ended_at,
            baseline_attempts=baseline_attempts,
            baseline_successes=baseline_attempts - baseline_failures,
            baseline_failures=baseline_failures,
            current_attempts=current_attempts,
            current_successes=current_attempts - current_failures,
            current_failures=current_failures,
            baseline_failure_rate_bps=_scaled(baseline_rate, _BPS),
            current_failure_rate_bps=_scaled(current_rate, _BPS),
            success_rate_drop_bps=drop_bps,
            confidence_ppm=confidence,
            ewma_failure_rate_bps=_scaled(ewma, _BPS),
            ewma_drop_bps=ewma_drop_bps,
            cusum_milli=_round_half_up(cusum * _MILLI),
            excess_failures=excess_failures,
            at_risk_gmv_subunits=at_risk_gmv,
            currency=_currency((*current, *baseline)) or fallback_currency,
            gate_reason=gate_reason,
            minimum_current_attempts=self.config.minimum_current_attempts,
            baseline_minimum_attempts=self.config.baseline_minimum_attempts,
            minimum_current_failures=self.config.minimum_current_failures,
            minimum_success_rate_drop_bps=self.config.minimum_success_rate_drop_bps,
            confidence_threshold_ppm=self.config.confidence_threshold_ppm,
            ewma_drop_threshold_bps=self.config.ewma_drop_threshold_bps,
            cusum_threshold_milli=self.config.cusum_threshold_milli,
            minimum_excess_failures=self.config.minimum_excess_failures,
            minimum_at_risk_gmv_subunits=self.config.minimum_at_risk_gmv_subunits,
        )

    def _gate_reason(
        self,
        *,
        current_attempts: int,
        baseline_attempts: int,
        current_failures: int,
        drop_bps: int,
        confidence_ppm: int,
        ewma_drop_bps: int,
        cusum_milli: int,
        excess_failures: int,
        at_risk_gmv_subunits: int,
    ) -> DetectorGateReason:
        gates = (
            (
                current_attempts < self.config.minimum_current_attempts,
                DetectorGateReason.CURRENT_SAMPLE,
            ),
            (
                baseline_attempts < self.config.baseline_minimum_attempts,
                DetectorGateReason.BASELINE_SAMPLE,
            ),
            (
                current_failures < self.config.minimum_current_failures,
                DetectorGateReason.CURRENT_FAILURES,
            ),
            (
                drop_bps < self.config.minimum_success_rate_drop_bps,
                DetectorGateReason.RATE_DROP,
            ),
            (
                confidence_ppm < self.config.confidence_threshold_ppm,
                DetectorGateReason.CONFIDENCE,
            ),
            (
                ewma_drop_bps < self.config.ewma_drop_threshold_bps,
                DetectorGateReason.EWMA,
            ),
            (
                cusum_milli < self.config.cusum_threshold_milli,
                DetectorGateReason.CUSUM,
            ),
            (
                excess_failures < self.config.minimum_excess_failures,
                DetectorGateReason.EXCESS_FAILURES,
            ),
            (
                at_risk_gmv_subunits < self.config.minimum_at_risk_gmv_subunits,
                DetectorGateReason.BUSINESS_IMPACT,
            ),
        )
        return next((reason for failed, reason in gates if failed), DetectorGateReason.PASSED)

    def _finalize_incident(
        self,
        episode: _ActiveIncident,
        attempts: Sequence[AttemptFact],
    ) -> DetectedIncident:
        observations = tuple(episode.signals)
        first = observations[0]
        peak = max(
            observations,
            key=lambda item: (
                item.statistics.at_risk_gmv_subunits,
                item.statistics.excess_failures,
                item.statistics.confidence_ppm,
                -int(item.statistics.evaluated_at.timestamp()),
            ),
        )
        diagnosis, affected_cohort = self._diagnose(attempts, peak)
        opened_at = first.statistics.evaluated_at
        identity = (
            f"{first.merchant_id}\x1f{self.config.detector_version}\x1f"
            f"{first.method.value}\x1f{opened_at.isoformat()}"
        )
        incident_id = f"inc_{hashlib.sha256(identity.encode()).hexdigest()[:24]}"
        detector_cohort = (
            CohortPredicate(
                dimension=CohortDimension.METHOD,
                value=first.method.value,
            ),
        )
        return DetectedIncident(
            incident_id=incident_id,
            merchant_id=first.merchant_id,
            detector_version=self.config.detector_version,
            status=(
                IncidentStatus.RESOLVED
                if episode.resolved_at is not None
                else IncidentStatus.OPEN
            ),
            opened_at=opened_at,
            last_observed_at=observations[-1].statistics.evaluated_at,
            resolved_at=episode.resolved_at,
            detector_cohort=detector_cohort,
            affected_cohort=affected_cohort,
            peak_signal=peak,
            observations=observations,
            diagnosis=diagnosis,
            synthetic=all(item.synthetic for item in attempts),
        )

    def _diagnose(
        self,
        attempts: Sequence[AttemptFact],
        signal: DetectionSignal,
    ) -> tuple[DiagnosisSnapshot, tuple[CohortPredicate, ...]]:
        stats = signal.statistics
        current_all = tuple(
            item
            for item in attempts
            if stats.current_started_at <= item.occurred_at < stats.evaluated_at
        )
        baseline_all = tuple(
            item
            for item in attempts
            if stats.baseline_started_at
            <= item.occurred_at
            < stats.baseline_ended_at
        )
        current_method = tuple(item for item in current_all if item.method is signal.method)
        baseline_method = tuple(item for item in baseline_all if item.method is signal.method)
        rankings: list[AttributionItem] = []
        rankings.extend(
            self._rank_slices(
                CohortDimension.METHOD,
                current_all,
                baseline_all,
                lambda item: item.method.value,
            )
        )
        rankings.extend(
            self._rank_slices(
                CohortDimension.ISSUER,
                current_method,
                baseline_method,
                lambda item: item.issuer,
            )
        )
        error_extractors = (
            (CohortDimension.ERROR_SOURCE, lambda item: item.error.source if item.error else None),
            (CohortDimension.ERROR_STEP, lambda item: item.error.step if item.error else None),
            (CohortDimension.ERROR_REASON, lambda item: item.error.reason if item.error else None),
        )
        for dimension, extractor in error_extractors:
            rankings.extend(
                self._rank_slices(
                    dimension,
                    current_method,
                    baseline_method,
                    extractor,
                    shared_denominator=True,
                )
            )
        if not rankings:
            raise DetectorInputError

        affected: list[CohortPredicate] = [
            CohortPredicate(
                dimension=CohortDimension.METHOD,
                value=signal.method.value,
            )
        ]
        issuer_top = next(
            (
                item
                for item in rankings
                if item.dimension is CohortDimension.ISSUER and item.rank == 1
            ),
            None,
        )
        if (
            issuer_top is not None
            and issuer_top.contribution_ppm
            >= self.config.attribution_issuer_share_ppm
        ):
            affected.append(
                CohortPredicate(
                    dimension=CohortDimension.ISSUER,
                    value=issuer_top.value,
                )
            )

        dimension_order = (
            CohortDimension.ERROR_REASON,
            CohortDimension.ERROR_SOURCE,
            CohortDimension.ERROR_STEP,
        )
        cause_items = [
            item
            for dimension in dimension_order
            for item in rankings
            if item.dimension is dimension and item.rank == 1
        ][:3]
        if not cause_items and issuer_top is not None:
            cause_items = [issuer_top]
        if not cause_items:
            cause_items = [rankings[0]]
        likely_causes = tuple(dict.fromkeys(item.value for item in cause_items))
        cause_evidence = tuple(
            sorted(
                {
                    event_id
                    for item in cause_items
                    for event_id in item.evidence_event_ids
                }
            )
        )
        source = _top_value(rankings, CohortDimension.ERROR_SOURCE) or "unknown_source"
        step = _top_value(rankings, CohortDimension.ERROR_STEP) or "unknown_step"
        reason = _top_value(rankings, CohortDimension.ERROR_REASON) or "unknown_reason"
        confidence = min(item.confidence_ppm for item in cause_items)
        hypothesis = DiagnosisHypothesis(
            statement=(
                "Merchant-local evidence is consistent with elevated "
                f"{reason} failures from {source} during {step}; external provider "
                "state is unverified."
            ),
            confidence_ppm=confidence,
            evidence_event_ids=cause_evidence,
        )
        diagnosis = DiagnosisSnapshot(
            verified_attributions=tuple(rankings),
            hypotheses=(hypothesis,),
            unknowns=(
                "External provider status is not verified by merchant-local payment events.",
                "The contribution calculation is observational and does not prove causality.",
            ),
            likely_causes=likely_causes,
        )
        return diagnosis, tuple(affected)

    def _rank_slices(
        self,
        dimension: CohortDimension,
        current: Sequence[AttemptFact],
        baseline: Sequence[AttemptFact],
        extractor: "SliceExtractor",
        *,
        shared_denominator: bool = False,
    ) -> tuple[AttributionItem, ...]:
        values = sorted(
            {
                value
                for item in current
                if item.failed and (value := extractor(item)) is not None
            }
        )
        raw: list[tuple[str, int, int, int, int, int, tuple[str, ...]]] = []
        for value in values:
            if shared_denominator:
                current_slice = tuple(current)
                baseline_slice = tuple(baseline)
                current_failures = tuple(
                    item
                    for item in current
                    if item.failed and extractor(item) == value
                )
                baseline_failures = tuple(
                    item
                    for item in baseline
                    if item.failed and extractor(item) == value
                )
            else:
                current_slice = tuple(item for item in current if extractor(item) == value)
                baseline_slice = tuple(item for item in baseline if extractor(item) == value)
                current_failures = tuple(item for item in current_slice if item.failed)
                baseline_failures = tuple(item for item in baseline_slice if item.failed)
            if (
                len(current_failures) < self.config.attribution_minimum_failures
                or not current_slice
                or not baseline_slice
            ):
                continue
            baseline_rate = len(baseline_failures) / len(baseline_slice)
            expected_milli = _round_half_up(
                len(current_slice) * baseline_rate * _MILLI
            )
            excess_milli = max(
                (len(current_failures) * _MILLI) - expected_milli,
                0,
            )
            if excess_milli <= 0:
                continue
            raw.append(
                (
                    value,
                    len(current_slice),
                    len(current_failures),
                    len(baseline_slice),
                    len(baseline_failures),
                    excess_milli,
                    _event_ids(current_failures),
                )
            )
        ordered = sorted(raw, key=lambda item: (-item[5], item[0]))
        total_excess = sum(item[5] for item in ordered)
        results: list[AttributionItem] = []
        for rank, item in enumerate(ordered, start=1):
            (
                value,
                current_attempt_count,
                current_failure_count,
                baseline_attempt_count,
                baseline_failure_count,
                excess,
                event_ids,
            ) = item
            baseline_rate = baseline_failure_count / baseline_attempt_count
            results.append(
                AttributionItem(
                    dimension=dimension,
                    value=value,
                    rank=rank,
                    current_attempts=current_attempt_count,
                    current_failures=current_failure_count,
                    baseline_attempts=baseline_attempt_count,
                    baseline_failures=baseline_failure_count,
                    expected_failures_milli=_round_half_up(
                        current_attempt_count * baseline_rate * _MILLI
                    ),
                    excess_failures_milli=excess,
                    contribution_ppm=_scaled(excess / total_excess, _PPM),
                    confidence_ppm=proportion_confidence_ppm(
                        current_failures=current_failure_count,
                        current_attempts=current_attempt_count,
                        baseline_failures=baseline_failure_count,
                        baseline_attempts=baseline_attempt_count,
                    ),
                    evidence_event_ids=event_ids,
                )
            )
        return tuple(results)


type SliceExtractor = Callable[[AttemptFact], str | None]


def _validate_run_input(
    attempts: Sequence[AttemptFact],
    partition_started_at: datetime,
    partition_ended_at: datetime,
) -> tuple[datetime, datetime, set[str]]:
    start = _require_aware(partition_started_at)
    end = _require_aware(partition_ended_at)
    if end <= start:
        raise DetectorInputError
    if any(not (start <= item.occurred_at < end) for item in attempts):
        raise DetectorInputError
    merchants = {item.merchant_id for item in attempts}
    if len(merchants) > 1:
        raise DetectorInputError
    return start, end, merchants


def _top_value(
    rankings: Sequence[AttributionItem],
    dimension: CohortDimension,
) -> str | None:
    return next(
        (
            item.value
            for item in rankings
            if item.dimension is dimension and item.rank == 1
        ),
        None,
    )


def _event_ids(attempts: Sequence[AttemptFact]) -> tuple[str, ...]:
    return tuple(
        sorted({event_id for item in attempts for event_id in item.event_ids})
    )


def _currency(attempts: Sequence[AttemptFact]) -> str:
    currencies = {item.currency for item in attempts}
    if len(currencies) > 1:
        raise DetectorIdentityConflictError
    return next(iter(currencies), "INR")


def _scaled(value: float, scale: int) -> int:
    return min(max(_round_half_up(value * scale), 0), scale)


def _round_half_up(value: float) -> int:
    return math.floor(value + 0.5)


def _floor_time(value: datetime, minutes: int) -> datetime:
    aware = _require_aware(value)
    seconds = minutes * 60
    timestamp = int(aware.timestamp())
    return datetime.fromtimestamp(timestamp - (timestamp % seconds), tz=UTC)


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DetectorInputError
    return value.astimezone(UTC)
