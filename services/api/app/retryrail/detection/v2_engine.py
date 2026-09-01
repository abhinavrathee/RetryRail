"""Hierarchical, actionability-aware detector-v2 candidate engine."""

import hashlib
import math
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from retryrail.contracts.domain import CohortDimension, CohortPredicate, IncidentStatus
from retryrail.detection.engine import (
    DetectorInputError,
    materialize_aggregate_windows,
    proportion_confidence_ppm,
    reconstruct_attempts,
)
from retryrail.detection.models import (
    AttemptFact,
    AttributionItem,
    DiagnosisHypothesis,
    DiagnosisSnapshot,
)
from retryrail.detection.v2_models import (
    DetectorV2Config,
    V2CandidateDisposition,
    V2CohortLevel,
    V2DetectedIncident,
    V2DetectionSignal,
    V2DetectorRunResult,
    V2DetectorStatistics,
    V2GateReason,
    V2SuppressedCandidate,
)
from retryrail.events.models import NormalizedPaymentEvent, PaymentMethod

_BPS = 10_000
_PPM = 1_000_000
_MILLI = 1_000


@dataclass(slots=True)
class _Episode:
    """Internal candidate/confirmed state keyed by payment method."""

    method: PaymentMethod
    cohort: tuple[CohortPredicate, ...]
    confirmation_error_signature: str
    signals: list[V2DetectionSignal]
    confirmed_at: datetime | None = None
    healthy_minutes: int = 0
    resolved_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class _Evaluation:
    """Statistics plus the exact attempt slices that produced them."""

    statistics: V2DetectorStatistics
    current: tuple[AttemptFact, ...]
    baseline: tuple[AttemptFact, ...]
    recent: tuple[AttemptFact, ...]


@dataclass(frozen=True, slots=True)
class _Thresholds:
    minimum_current_attempts: int
    baseline_minimum_attempts: int
    minimum_rate_drop_bps: int
    confidence_threshold_ppm: int


@dataclass(frozen=True, slots=True)
class _ConfirmationThresholds:
    signals: int
    evidence_steps: int
    unique_actionable_failures: int
    requires_fresh_latest_step: bool
    minimum_post_open_attempts: int
    maximum_minutes: int
    tolerates_statistical_misses: bool


@dataclass(slots=True)
class _RunState:
    """Mutable lifecycle collections kept out of the public result."""

    active: dict[PaymentMethod, _Episode]
    completed: list[_Episode]
    suppressed: list[V2SuppressedCandidate]
    cooldown_until: dict[PaymentMethod, datetime]


class DetectorV2Engine:
    """Run the frozen v2 candidate without labels, models or runtime overrides."""

    def __init__(self, config: DetectorV2Config) -> None:
        self.config = config

    def run(
        self,
        events: Iterable[NormalizedPaymentEvent],
        *,
        partition_started_at: datetime,
        partition_ended_at: datetime,
    ) -> V2DetectorRunResult:
        """Reconstruct terminal attempts before running hierarchical detection."""

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
    ) -> V2DetectorRunResult:
        """Evaluate event-time cutoffs and retain pre-confirmation audit evidence."""

        start, end = _validate_run_input(
            attempts,
            partition_started_at,
            partition_ended_at,
        )
        aggregates = materialize_aggregate_windows(
            attempts,
            step_minutes=self.config.step_minutes,
        )
        methods = tuple(
            sorted({item.method for item in attempts}, key=lambda item: item.value)
        )
        state = _RunState(active={}, completed=[], suppressed=[], cooldown_until={})

        cutoff = start + timedelta(minutes=self.config.step_minutes)
        while cutoff <= end:
            for method in methods:
                self._advance_method(
                    attempts,
                    method=method,
                    evaluated_at=cutoff,
                    partition_started_at=start,
                    state=state,
                )
            cutoff += timedelta(minutes=self.config.step_minutes)

        confirmed = list(state.completed)
        for episode in state.active.values():
            if episode.confirmed_at is None:
                state.suppressed.append(
                    self._suppress(
                        episode,
                        V2CandidateDisposition.PARTITION_ENDED,
                        attempts,
                        evaluated_at=end,
                    )
                )
            else:
                confirmed.append(episode)

        incidents = tuple(
            self._finalize_incident(item, attempts)
            for item in sorted(
                confirmed,
                key=lambda value: value.signals[0].statistics.evaluated_at,
            )
        )
        return V2DetectorRunResult(
            detector_version=self.config.detector_version,
            partition_started_at=start,
            partition_ended_at=end,
            attempts=tuple(attempts),
            aggregates=aggregates,
            incidents=incidents,
            suppressed_candidates=tuple(
                sorted(
                    state.suppressed,
                    key=lambda item: (item.started_at, item.candidate_id),
                )
            ),
        )

    def _advance_method(
        self,
        attempts: Sequence[AttemptFact],
        *,
        method: PaymentMethod,
        evaluated_at: datetime,
        partition_started_at: datetime,
        state: _RunState,
    ) -> None:
        episode = state.active.get(method)
        if episode is None:
            self._start_candidate(
                attempts,
                method=method,
                evaluated_at=evaluated_at,
                partition_started_at=partition_started_at,
                state=state,
            )
            return
        evaluation = self.evaluate_cohort(
            attempts,
            cohort=episode.cohort,
            evaluated_at=evaluated_at,
            partition_started_at=partition_started_at,
            frozen_baseline=_opening_baseline(episode),
        )
        if evaluation.statistics.gate_reason is V2GateReason.PASSED:
            self._record_passing_signal(
                attempts,
                episode=episode,
                evaluation=evaluation,
                method=method,
                evaluated_at=evaluated_at,
                state=state,
            )
            return
        self._record_failed_signal(
            attempts,
            episode=episode,
            evaluation=evaluation,
            method=method,
            evaluated_at=evaluated_at,
            state=state,
        )

    def _start_candidate(
        self,
        attempts: Sequence[AttemptFact],
        *,
        method: PaymentMethod,
        evaluated_at: datetime,
        partition_started_at: datetime,
        state: _RunState,
    ) -> None:
        if evaluated_at < state.cooldown_until.get(method, partition_started_at):
            return
        signal = self._select_new_signal(
            attempts,
            method=method,
            evaluated_at=evaluated_at,
            partition_started_at=partition_started_at,
        )
        if signal is not None:
            state.active[method] = _Episode(
                method=method,
                cohort=signal.cohort,
                confirmation_error_signature=signal.confirmation_error_signature,
                signals=[signal],
            )

    def _record_passing_signal(
        self,
        attempts: Sequence[AttemptFact],
        *,
        episode: _Episode,
        evaluation: _Evaluation,
        method: PaymentMethod,
        evaluated_at: datetime,
        state: _RunState,
    ) -> None:
        episode.signals.append(
            self._signal(
                evaluation,
                method=method,
                confirmation_error_signature=episode.confirmation_error_signature,
            )
        )
        episode.healthy_minutes = 0
        if episode.confirmed_at is not None:
            return
        if self._confirmation_met(
            episode,
            attempts,
            evaluated_at=evaluated_at,
        ):
            episode.confirmed_at = evaluated_at
            return
        if self._confirmation_expired(episode, evaluated_at=evaluated_at):
            self._expire_candidate(
                attempts,
                episode=episode,
                method=method,
                evaluated_at=evaluated_at,
                disposition=V2CandidateDisposition.CONFIRMATION_EXPIRED,
                state=state,
            )

    def _record_failed_signal(
        self,
        attempts: Sequence[AttemptFact],
        *,
        episode: _Episode,
        evaluation: _Evaluation,
        method: PaymentMethod,
        evaluated_at: datetime,
        state: _RunState,
    ) -> None:
        if episode.confirmed_at is None:
            confirmation = self._confirmation_thresholds(episode.cohort)
            if confirmation.tolerates_statistical_misses and not (
                self._confirmation_expired(episode, evaluated_at=evaluated_at)
            ):
                return
            self._expire_candidate(
                attempts,
                episode=episode,
                method=method,
                evaluated_at=evaluated_at,
                disposition=V2CandidateDisposition.STATISTICAL_SIGNAL_LOST,
                state=state,
            )
            return
        if self._is_healthy(evaluation.statistics):
            episode.healthy_minutes += self.config.step_minutes
            if episode.healthy_minutes >= self.config.healthy_window_minutes:
                episode.resolved_at = evaluated_at
                state.completed.append(episode)
                del state.active[method]
        else:
            episode.healthy_minutes = 0

    def _expire_candidate(
        self,
        attempts: Sequence[AttemptFact],
        *,
        episode: _Episode,
        method: PaymentMethod,
        evaluated_at: datetime,
        disposition: V2CandidateDisposition,
        state: _RunState,
    ) -> None:
        state.suppressed.append(
            self._suppress(
                episode,
                disposition,
                attempts,
                evaluated_at=evaluated_at,
            )
        )
        del state.active[method]
        state.cooldown_until[method] = evaluated_at + timedelta(
            minutes=self.config.suppressed_candidate_cooldown_minutes
        )

    def evaluate_cohort(
        self,
        attempts: Sequence[AttemptFact],
        *,
        cohort: tuple[CohortPredicate, ...],
        evaluated_at: datetime,
        partition_started_at: datetime,
        frozen_baseline: tuple[datetime, datetime] | None = None,
    ) -> _Evaluation:
        """Evaluate one canonical method or method/issuer cohort."""

        level = _cohort_level(cohort)
        cutoff = _require_aware(evaluated_at)
        start = _require_aware(partition_started_at)
        cohort_attempts = tuple(item for item in attempts if _matches(item, cohort))
        fallback_currency = _currency(cohort_attempts)
        candidates: list[_Evaluation] = []
        for window_minutes in self.config.current_window_minutes:
            thresholds = self._thresholds(level, window_minutes=window_minutes)
            current_started_at, baseline_started_at, baseline_ended_at = (
                self._window_boundaries(
                    cutoff=cutoff,
                    partition_started_at=start,
                    window_minutes=window_minutes,
                    frozen_baseline=frozen_baseline,
                )
            )
            current = tuple(
                item
                for item in cohort_attempts
                if current_started_at <= item.occurred_at < cutoff
            )
            baseline = tuple(
                item
                for item in cohort_attempts
                if baseline_started_at <= item.occurred_at < baseline_ended_at
            )
            recent_started_at = max(
                current_started_at,
                cutoff - timedelta(minutes=self.config.recent_evidence_minutes),
            )
            recent = tuple(
                item
                for item in current
                if recent_started_at <= item.occurred_at < cutoff
            )
            evaluation = _Evaluation(
                statistics=self._statistics(
                    cohort=cohort,
                    level=level,
                    evaluated_at=cutoff,
                    current_started_at=current_started_at,
                    baseline_started_at=baseline_started_at,
                    baseline_ended_at=baseline_ended_at,
                    current=current,
                    baseline=baseline,
                    recent=recent,
                    window_minutes=window_minutes,
                    thresholds=thresholds,
                    fallback_currency=fallback_currency,
                ),
                current=current,
                baseline=baseline,
                recent=recent,
            )
            candidates.append(evaluation)
            if (
                len(current) >= thresholds.minimum_current_attempts
                and len(baseline) >= thresholds.baseline_minimum_attempts
            ):
                return evaluation
        if not candidates:
            raise DetectorInputError
        return candidates[-1]

    def _window_boundaries(
        self,
        *,
        cutoff: datetime,
        partition_started_at: datetime,
        window_minutes: int,
        frozen_baseline: tuple[datetime, datetime] | None,
    ) -> tuple[datetime, datetime, datetime]:
        frozen_started_at = (
            _require_aware(frozen_baseline[0]) if frozen_baseline is not None else None
        )
        frozen_ended_at = (
            _require_aware(frozen_baseline[1]) if frozen_baseline is not None else None
        )
        current_started_at = max(
            partition_started_at,
            cutoff - timedelta(minutes=window_minutes),
            frozen_ended_at or partition_started_at,
        )
        baseline_ended_at = current_started_at
        baseline_started_at = max(
            partition_started_at,
            baseline_ended_at - timedelta(minutes=self.config.baseline_lookback_minutes),
        )
        if frozen_started_at is not None and frozen_ended_at is not None:
            baseline_started_at = frozen_started_at
            baseline_ended_at = frozen_ended_at
        return current_started_at, baseline_started_at, baseline_ended_at

    def _statistics(
        self,
        *,
        cohort: tuple[CohortPredicate, ...],
        level: V2CohortLevel,
        evaluated_at: datetime,
        current_started_at: datetime,
        baseline_started_at: datetime,
        baseline_ended_at: datetime,
        current: Sequence[AttemptFact],
        baseline: Sequence[AttemptFact],
        recent: Sequence[AttemptFact],
        window_minutes: int,
        thresholds: _Thresholds,
        fallback_currency: str,
    ) -> V2DetectorStatistics:
        baseline_failures = tuple(item for item in baseline if item.failed)
        current_failures = tuple(item for item in current if item.failed)
        baseline_actionable = tuple(
            item for item in baseline_failures if self._is_actionable_failure(item)
        )
        current_actionable = tuple(
            item for item in current_failures if self._is_actionable_failure(item)
        )
        recent_actionable = tuple(
            item for item in recent if self._is_actionable_failure(item)
        )
        current_non_actionable = len(current_failures) - len(current_actionable)
        baseline_rate = len(baseline_actionable) / len(baseline) if baseline else 0.0
        current_rate = len(current_actionable) / len(current) if current else 0.0
        rate_drop = max(current_rate - baseline_rate, 0.0)
        excess = max(len(current_actionable) - (len(current) * baseline_rate), 0.0)
        excess_failures = _round_half_up(excess)
        failed_gmv = sum(item.amount_subunits for item in current_actionable)
        current_gmv = sum(item.amount_subunits for item in current)
        at_risk_gmv = max(
            _round_half_up(failed_gmv - (baseline_rate * current_gmv)),
            0,
        )
        confidence = proportion_confidence_ppm(
            current_failures=len(current_actionable),
            current_attempts=len(current),
            baseline_failures=len(baseline_actionable),
            baseline_attempts=len(baseline),
        )
        gate_reason = self._gate_reason(
            current=current,
            current_failures=current_failures,
            current_actionable=current_actionable,
            baseline_attempts=len(baseline),
            rate_drop_bps=_scaled(rate_drop, _BPS),
            confidence_ppm=confidence,
            excess_failures=excess_failures,
            at_risk_gmv_subunits=at_risk_gmv,
            thresholds=thresholds,
        )
        return V2DetectorStatistics(
            evaluated_at=evaluated_at,
            cohort_level=level,
            cohort=cohort,
            current_window_minutes=window_minutes,
            current_started_at=current_started_at,
            baseline_started_at=baseline_started_at,
            baseline_ended_at=baseline_ended_at,
            baseline_attempts=len(baseline),
            baseline_failures=len(baseline_failures),
            baseline_actionable_failures=len(baseline_actionable),
            current_attempts=len(current),
            current_failures=len(current_failures),
            current_actionable_failures=len(current_actionable),
            current_non_actionable_failures=current_non_actionable,
            recent_actionable_failures=len(recent_actionable),
            baseline_actionable_failure_rate_bps=_scaled(baseline_rate, _BPS),
            current_actionable_failure_rate_bps=_scaled(current_rate, _BPS),
            actionable_rate_drop_bps=_scaled(rate_drop, _BPS),
            confidence_ppm=confidence,
            excess_actionable_failures=excess_failures,
            at_risk_gmv_subunits=at_risk_gmv,
            currency=_currency((*current, *baseline)) or fallback_currency,
            gate_reason=gate_reason,
            minimum_current_attempts=thresholds.minimum_current_attempts,
            baseline_minimum_attempts=thresholds.baseline_minimum_attempts,
            minimum_actionable_failures=self.config.minimum_actionable_failures,
            minimum_actionable_rate_drop_bps=thresholds.minimum_rate_drop_bps,
            confidence_threshold_ppm=thresholds.confidence_threshold_ppm,
            minimum_excess_actionable_failures=(
                self.config.minimum_excess_actionable_failures
            ),
            minimum_at_risk_gmv_subunits=self.config.minimum_at_risk_gmv_subunits,
        )

    def _gate_reason(
        self,
        *,
        current: Sequence[AttemptFact],
        current_failures: Sequence[AttemptFact],
        current_actionable: Sequence[AttemptFact],
        baseline_attempts: int,
        rate_drop_bps: int,
        confidence_ppm: int,
        excess_failures: int,
        at_risk_gmv_subunits: int,
        thresholds: _Thresholds,
    ) -> V2GateReason:
        non_actionable_only = bool(current_failures) and not current_actionable and all(
            item.error is not None
            and item.error.source in self.config.non_actionable_error_sources
            for item in current_failures
        )
        gates = (
            (
                len(current) < thresholds.minimum_current_attempts,
                V2GateReason.CURRENT_SAMPLE,
            ),
            (
                baseline_attempts < thresholds.baseline_minimum_attempts,
                V2GateReason.BASELINE_SAMPLE,
            ),
            (non_actionable_only, V2GateReason.NON_ACTIONABLE_SOURCE),
            (
                len(current_actionable) < self.config.minimum_actionable_failures,
                V2GateReason.ACTIONABLE_FAILURES,
            ),
            (rate_drop_bps < thresholds.minimum_rate_drop_bps, V2GateReason.RATE_DROP),
            (
                confidence_ppm < thresholds.confidence_threshold_ppm,
                V2GateReason.CONFIDENCE,
            ),
            (
                excess_failures < self.config.minimum_excess_actionable_failures,
                V2GateReason.EXCESS_FAILURES,
            ),
            (
                at_risk_gmv_subunits < self.config.minimum_at_risk_gmv_subunits,
                V2GateReason.BUSINESS_IMPACT,
            ),
        )
        return next((reason for failed, reason in gates if failed), V2GateReason.PASSED)

    def _select_new_signal(
        self,
        attempts: Sequence[AttemptFact],
        *,
        method: PaymentMethod,
        evaluated_at: datetime,
        partition_started_at: datetime,
    ) -> V2DetectionSignal | None:
        evaluations = tuple(
            self.evaluate_cohort(
                attempts,
                cohort=cohort,
                evaluated_at=evaluated_at,
                partition_started_at=partition_started_at,
            )
            for cohort in _candidate_cohorts(attempts, method, evaluated_at)
        )
        passing = tuple(
            item
            for item in evaluations
            if item.statistics.gate_reason is V2GateReason.PASSED
            and item.statistics.recent_actionable_failures > 0
        )
        if not passing:
            return None
        method_evaluation = next(
            (
                item
                for item in passing
                if item.statistics.cohort_level is V2CohortLevel.METHOD
            ),
            None,
        )
        issuer_evaluations = tuple(
            item
            for item in passing
            if item.statistics.cohort_level is V2CohortLevel.METHOD_ISSUER
        )
        issuer_evaluation = max(
            issuer_evaluations,
            key=lambda item: (
                item.statistics.excess_actionable_failures,
                item.statistics.confidence_ppm,
                item.statistics.current_actionable_failures,
                tuple(predicate.value for predicate in item.statistics.cohort),
            ),
            default=None,
        )
        selected = method_evaluation or issuer_evaluation
        if method_evaluation is not None and issuer_evaluation is not None:
            method_excess = max(
                method_evaluation.statistics.excess_actionable_failures,
                1,
            )
            issuer_share_ppm = _scaled(
                issuer_evaluation.statistics.excess_actionable_failures
                / method_excess,
                _PPM,
            )
            if issuer_share_ppm >= self.config.attribution_issuer_share_ppm:
                selected = issuer_evaluation
        if selected is None:
            return None
        return self._signal(selected, method=method)

    def _signal(
        self,
        evaluation: _Evaluation,
        *,
        method: PaymentMethod,
        confirmation_error_signature: str | None = None,
    ) -> V2DetectionSignal:
        actionable = tuple(
            item for item in evaluation.current if self._is_actionable_failure(item)
        )
        recent = tuple(
            item for item in evaluation.recent if self._is_actionable_failure(item)
        )
        signature = confirmation_error_signature or _dominant_error_signature(
            actionable,
            recent,
        )
        recent_confirmation = tuple(
            item for item in recent if _error_signature(item) == signature
        )
        merchant_id = (
            evaluation.current[0].merchant_id
            if evaluation.current
            else evaluation.baseline[0].merchant_id
        )
        return V2DetectionSignal(
            merchant_id=merchant_id,
            method=method,
            cohort=evaluation.statistics.cohort,
            statistics=evaluation.statistics,
            evidence_event_ids=_event_ids(evaluation.current),
            actionable_evidence_event_ids=_event_ids(actionable),
            recent_actionable_event_ids=_event_ids(recent),
            confirmation_error_signature=signature,
            recent_confirmation_event_ids=_event_ids(recent_confirmation),
        )

    def _confirmation_met(
        self,
        episode: _Episode,
        attempts: Sequence[AttemptFact],
        *,
        evaluated_at: datetime,
    ) -> bool:
        thresholds = self._confirmation_thresholds(episode.cohort)
        confirmation_signals = _confirmation_signals(episode)
        if len(confirmation_signals) < thresholds.signals:
            return False
        evidence_signals = tuple(
            item
            for item in confirmation_signals
            if item.recent_confirmation_event_ids
        )
        unique_failures = {
            event_id
            for item in evidence_signals
            for event_id in item.recent_confirmation_event_ids
        }
        post_open_attempts = sum(
            _matches(item, episode.cohort)
            and episode.signals[0].statistics.evaluated_at
            <= item.occurred_at
            < evaluated_at
            for item in attempts
        )
        return (
            len(evidence_signals) >= thresholds.evidence_steps
            and len(unique_failures)
            >= thresholds.unique_actionable_failures
            and (
                not thresholds.requires_fresh_latest_step
                or bool(confirmation_signals[-1].recent_confirmation_event_ids)
            )
            and post_open_attempts >= thresholds.minimum_post_open_attempts
        )

    def _confirmation_expired(
        self,
        episode: _Episode,
        *,
        evaluated_at: datetime,
    ) -> bool:
        thresholds = self._confirmation_thresholds(episode.cohort)
        elapsed = evaluated_at - episode.signals[0].statistics.evaluated_at
        signal_limit_reached = (
            not thresholds.tolerates_statistical_misses
            and len(_confirmation_signals(episode)) >= thresholds.signals
        )
        return signal_limit_reached or elapsed >= timedelta(
            minutes=thresholds.maximum_minutes
        )

    def _is_healthy(self, statistics: V2DetectorStatistics) -> bool:
        """Resolve only with sample-backed provider-rate recovery."""

        return (
            statistics.current_attempts >= statistics.minimum_current_attempts
            and statistics.baseline_attempts >= statistics.baseline_minimum_attempts
            and statistics.actionable_rate_drop_bps
            < statistics.minimum_actionable_rate_drop_bps
        )

    def _suppress(
        self,
        episode: _Episode,
        disposition: V2CandidateDisposition,
        attempts: Sequence[AttemptFact],
        *,
        evaluated_at: datetime,
    ) -> V2SuppressedCandidate:
        first = episode.signals[0]
        last = episode.signals[-1]
        identity = (
            f"{first.merchant_id}\x1f{self.config.detector_version}\x1f"
            f"{_cohort_key(episode.cohort)}\x1f"
            f"{first.statistics.evaluated_at.isoformat()}"
        )
        return V2SuppressedCandidate(
            candidate_id=f"cand_{hashlib.sha256(identity.encode()).hexdigest()[:24]}",
            merchant_id=first.merchant_id,
            detector_version=self.config.detector_version,
            started_at=first.statistics.evaluated_at,
            last_observed_at=last.statistics.evaluated_at,
            cohort=episode.cohort,
            signals=tuple(episode.signals),
            disposition=disposition,
            gate_reason=self._suppression_gate_reason(
                episode,
                attempts,
                evaluated_at=evaluated_at,
            ),
            synthetic=all(item.synthetic for item in attempts),
        )

    def _suppression_gate_reason(
        self,
        episode: _Episode,
        attempts: Sequence[AttemptFact],
        *,
        evaluated_at: datetime,
    ) -> V2GateReason:
        if _cohort_level(episode.cohort) is V2CohortLevel.METHOD:
            return V2GateReason.CONFIRMATION
        post_open_attempts = sum(
            _matches(item, episode.cohort)
            and episode.signals[0].statistics.evaluated_at
            <= item.occurred_at
            < evaluated_at
            for item in attempts
        )
        if post_open_attempts < self.config.issuer_confirmation_minimum_post_open_attempts:
            return V2GateReason.CURRENT_SAMPLE
        return V2GateReason.CONFIRMATION

    def _finalize_incident(
        self,
        episode: _Episode,
        attempts: Sequence[AttemptFact],
    ) -> V2DetectedIncident:
        if episode.confirmed_at is None:
            raise DetectorInputError
        observations = tuple(episode.signals)
        first = observations[0]
        peak = max(
            observations,
            key=lambda item: (
                item.statistics.at_risk_gmv_subunits,
                item.statistics.excess_actionable_failures,
                item.statistics.confidence_ppm,
                -int(item.statistics.evaluated_at.timestamp()),
            ),
        )
        diagnosis, affected_cohort = self._diagnose(attempts, peak)
        opened_at = first.statistics.evaluated_at
        identity = (
            f"{first.merchant_id}\x1f{self.config.detector_version}\x1f"
            f"{_cohort_key(episode.cohort)}\x1f{opened_at.isoformat()}"
        )
        evidence_signals = tuple(
            item
            for item in observations
            if item.cohort == episode.cohort and item.recent_confirmation_event_ids
        )
        unique_actionable = {
            event_id
            for item in evidence_signals
            for event_id in item.recent_confirmation_event_ids
        }
        return V2DetectedIncident(
            incident_id=f"inc_{hashlib.sha256(identity.encode()).hexdigest()[:24]}",
            merchant_id=first.merchant_id,
            detector_version=self.config.detector_version,
            status=(
                IncidentStatus.RESOLVED
                if episode.resolved_at is not None
                else IncidentStatus.OPEN
            ),
            opened_at=opened_at,
            confirmed_at=episode.confirmed_at,
            last_observed_at=observations[-1].statistics.evaluated_at,
            resolved_at=episode.resolved_at,
            detector_cohort=episode.cohort,
            affected_cohort=affected_cohort,
            peak_signal=peak,
            observations=observations,
            diagnosis=diagnosis,
            confirmation_evidence_steps=len(evidence_signals),
            confirmation_unique_actionable_failures=len(unique_actionable),
            synthetic=all(item.synthetic for item in attempts),
        )

    def _diagnose(
        self,
        attempts: Sequence[AttemptFact],
        signal: V2DetectionSignal,
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
        baseline_method = tuple(
            item for item in baseline_all if item.method is signal.method
        )
        current_cohort = tuple(item for item in current_all if _matches(item, signal.cohort))
        baseline_cohort = tuple(
            item for item in baseline_all if _matches(item, signal.cohort)
        )

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
        error_extractors: tuple[tuple[CohortDimension, SliceExtractor], ...] = (
            (
                CohortDimension.ERROR_SOURCE,
                lambda item: item.error.source if item.error else None,
            ),
            (
                CohortDimension.ERROR_STEP,
                lambda item: item.error.step if item.error else None,
            ),
            (
                CohortDimension.ERROR_REASON,
                lambda item: item.error.reason if item.error else None,
            ),
        )
        for dimension, extractor in error_extractors:
            rankings.extend(
                self._rank_slices(
                    dimension,
                    current_cohort,
                    baseline_cohort,
                    extractor,
                    shared_denominator=True,
                )
            )
        if not rankings:
            raise DetectorInputError

        affected = list(signal.cohort)
        if len(affected) == 1:
            issuer_top = _top_value_item(rankings, CohortDimension.ISSUER)
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

        cause_items = [
            item
            for dimension in (
                CohortDimension.ERROR_REASON,
                CohortDimension.ERROR_SOURCE,
                CohortDimension.ERROR_STEP,
            )
            for item in rankings
            if item.dimension is dimension and item.rank == 1
        ][:3]
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
        hypothesis = DiagnosisHypothesis(
            statement=(
                "Merchant-local provider-actionable evidence is consistent with elevated "
                f"{reason} failures from {source} during {step}; external provider "
                "state is unverified."
            ),
            confidence_ppm=min(item.confidence_ppm for item in cause_items),
            evidence_event_ids=cause_evidence,
        )
        return (
            DiagnosisSnapshot(
                verified_attributions=tuple(rankings),
                hypotheses=(hypothesis,),
                unknowns=(
                    "External provider status is not verified by merchant-local events.",
                    "The deterministic contribution calculation does not prove causality.",
                ),
                likely_causes=likely_causes,
            ),
            tuple(affected),
        )

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
                if self._is_actionable_failure(item)
                and (value := extractor(item)) is not None
            }
        )
        raw: list[tuple[str, int, int, int, int, int, tuple[str, ...]]] = []
        for value in values:
            current_slice = (
                tuple(current)
                if shared_denominator
                else tuple(item for item in current if extractor(item) == value)
            )
            baseline_slice = (
                tuple(baseline)
                if shared_denominator
                else tuple(item for item in baseline if extractor(item) == value)
            )
            current_failures = tuple(
                item
                for item in current
                if self._is_actionable_failure(item) and extractor(item) == value
            )
            baseline_failures = tuple(
                item
                for item in baseline
                if self._is_actionable_failure(item) and extractor(item) == value
            )
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
        return tuple(
            AttributionItem(
                dimension=dimension,
                value=item[0],
                rank=rank,
                current_attempts=item[1],
                current_failures=item[2],
                baseline_attempts=item[3],
                baseline_failures=item[4],
                expected_failures_milli=_round_half_up(
                    item[1] * (item[4] / item[3]) * _MILLI
                ),
                excess_failures_milli=item[5],
                contribution_ppm=_scaled(item[5] / total_excess, _PPM),
                confidence_ppm=proportion_confidence_ppm(
                    current_failures=item[2],
                    current_attempts=item[1],
                    baseline_failures=item[4],
                    baseline_attempts=item[3],
                ),
                evidence_event_ids=item[6],
            )
            for rank, item in enumerate(ordered, start=1)
        )

    def _thresholds(
        self,
        level: V2CohortLevel,
        *,
        window_minutes: int,
    ) -> _Thresholds:
        if level is V2CohortLevel.METHOD:
            return _Thresholds(
                minimum_current_attempts=self.config.method_minimum_current_attempts,
                baseline_minimum_attempts=self.config.method_baseline_minimum_attempts,
                minimum_rate_drop_bps=(
                    self.config.method_minimum_actionable_rate_drop_bps
                ),
                confidence_threshold_ppm=self.config.method_confidence_threshold_ppm,
            )
        return _Thresholds(
            minimum_current_attempts=max(
                self.config.issuer_minimum_current_attempts,
                math.ceil(
                    self.config.issuer_minimum_attempts_per_hour
                    * window_minutes
                    / 60
                ),
            ),
            baseline_minimum_attempts=self.config.issuer_baseline_minimum_attempts,
            minimum_rate_drop_bps=self.config.issuer_minimum_actionable_rate_drop_bps,
            confidence_threshold_ppm=self.config.issuer_confidence_threshold_ppm,
        )

    def _confirmation_thresholds(
        self,
        cohort: Sequence[CohortPredicate],
    ) -> _ConfirmationThresholds:
        if _cohort_level(cohort) is V2CohortLevel.METHOD:
            return _ConfirmationThresholds(
                signals=self.config.method_confirmation_signals,
                evidence_steps=self.config.method_confirmation_evidence_steps,
                unique_actionable_failures=(
                    self.config.method_confirmation_unique_actionable_failures
                ),
                requires_fresh_latest_step=(
                    self.config.method_confirmation_requires_fresh_latest_step
                ),
                minimum_post_open_attempts=0,
                maximum_minutes=(
                    (self.config.method_confirmation_signals - 1)
                    * self.config.step_minutes
                ),
                tolerates_statistical_misses=False,
            )
        return _ConfirmationThresholds(
            signals=self.config.issuer_confirmation_signals,
            evidence_steps=self.config.issuer_confirmation_evidence_steps,
            unique_actionable_failures=(
                self.config.issuer_confirmation_unique_actionable_failures
            ),
            requires_fresh_latest_step=(
                self.config.issuer_confirmation_requires_fresh_latest_step
            ),
            minimum_post_open_attempts=(
                self.config.issuer_confirmation_minimum_post_open_attempts
            ),
            maximum_minutes=self.config.issuer_confirmation_maximum_minutes,
            tolerates_statistical_misses=True,
        )

    def _is_actionable_failure(self, attempt: AttemptFact) -> bool:
        return (
            attempt.failed
            and attempt.error is not None
            and attempt.error.source in self.config.actionable_error_sources
        )


type SliceExtractor = Callable[[AttemptFact], str | None]


def _candidate_cohorts(
    attempts: Sequence[AttemptFact],
    method: PaymentMethod,
    evaluated_at: datetime,
) -> tuple[tuple[CohortPredicate, ...], ...]:
    method_cohort = (
        CohortPredicate(dimension=CohortDimension.METHOD, value=method.value),
    )
    issuers = sorted(
        {
            item.issuer
            for item in attempts
            if item.method is method
            and item.issuer is not None
            and item.occurred_at < evaluated_at
        }
    )
    return (
        method_cohort,
        *(
            (
                *method_cohort,
                CohortPredicate(dimension=CohortDimension.ISSUER, value=issuer),
            )
            for issuer in issuers
        ),
    )


def _opening_baseline(episode: _Episode) -> tuple[datetime, datetime]:
    opening = next(item.statistics for item in episode.signals if item.cohort == episode.cohort)
    return opening.baseline_started_at, opening.baseline_ended_at


def _confirmation_signals(episode: _Episode) -> tuple[V2DetectionSignal, ...]:
    return tuple(item for item in episode.signals if item.cohort == episode.cohort)


def _cohort_level(cohort: Sequence[CohortPredicate]) -> V2CohortLevel:
    dimensions = tuple(item.dimension for item in cohort)
    if dimensions == (CohortDimension.METHOD,):
        return V2CohortLevel.METHOD
    if dimensions == (CohortDimension.METHOD, CohortDimension.ISSUER):
        return V2CohortLevel.METHOD_ISSUER
    raise DetectorInputError


def _matches(attempt: AttemptFact, cohort: Sequence[CohortPredicate]) -> bool:
    values = {
        CohortDimension.METHOD: attempt.method.value,
        CohortDimension.ISSUER: attempt.issuer,
    }
    return all(values.get(item.dimension) == item.value for item in cohort)


def _validate_run_input(
    attempts: Sequence[AttemptFact],
    partition_started_at: datetime,
    partition_ended_at: datetime,
) -> tuple[datetime, datetime]:
    start = _require_aware(partition_started_at)
    end = _require_aware(partition_ended_at)
    if end <= start:
        raise DetectorInputError
    if any(not (start <= item.occurred_at < end) for item in attempts):
        raise DetectorInputError
    if len({item.merchant_id for item in attempts}) > 1:
        raise DetectorInputError
    return start, end


def _top_value_item(
    rankings: Sequence[AttributionItem],
    dimension: CohortDimension,
) -> AttributionItem | None:
    return next(
        (
            item
            for item in rankings
            if item.dimension is dimension and item.rank == 1
        ),
        None,
    )


def _top_value(
    rankings: Sequence[AttributionItem],
    dimension: CohortDimension,
) -> str | None:
    item = _top_value_item(rankings, dimension)
    return item.value if item is not None else None


def _event_ids(attempts: Sequence[AttemptFact]) -> tuple[str, ...]:
    return tuple(sorted({event_id for item in attempts for event_id in item.event_ids}))


def _currency(attempts: Sequence[AttemptFact]) -> str:
    currencies = {item.currency for item in attempts}
    if len(currencies) > 1:
        raise DetectorInputError
    return next(iter(currencies), "INR")


def _cohort_key(cohort: Sequence[CohortPredicate]) -> str:
    return "|".join(f"{item.dimension.value}={item.value}" for item in cohort)


def _error_signature(attempt: AttemptFact) -> str:
    if attempt.error is None:
        raise DetectorInputError
    return "|".join(
        value or "unknown"
        for value in (
            attempt.error.code,
            attempt.error.source,
            attempt.error.step,
            attempt.error.reason,
        )
    )


def _dominant_error_signature(
    actionable: Sequence[AttemptFact],
    recent: Sequence[AttemptFact],
) -> str:
    signatures = {_error_signature(item) for item in actionable}
    if not signatures:
        raise DetectorInputError
    recent_counts = {
        signature: sum(_error_signature(item) == signature for item in recent)
        for signature in signatures
    }
    total_counts = {
        signature: sum(_error_signature(item) == signature for item in actionable)
        for signature in signatures
    }
    return min(
        signatures,
        key=lambda signature: (
            -recent_counts[signature],
            -total_counts[signature],
            signature,
        ),
    )


def _scaled(value: float, scale: int) -> int:
    return min(max(_round_half_up(value * scale), 0), scale)


def _round_half_up(value: float) -> int:
    return math.floor(value + 0.5)


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DetectorInputError
    return value.astimezone(UTC)
