"""Canonical-cohort detector-v4 lifecycle with label-free scope arbitration."""

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from retryrail.contracts.domain import CohortPredicate
from retryrail.detection.engine import (
    DetectorInputError,
    materialize_aggregate_windows,
    reconstruct_attempts,
)
from retryrail.detection.models import AttemptFact
from retryrail.detection.v2_engine import (
    DetectorV2Engine,
    _candidate_cohorts,
    _cohort_key,
    _cohort_level,
    _ConfirmationThresholds,
    _Episode,
    _opening_baseline,
    _validate_run_input,
)
from retryrail.detection.v2_models import (
    V2CandidateDisposition,
    V2CohortLevel,
    V2DetectedIncident,
    V2GateReason,
    V2SuppressedCandidate,
)
from retryrail.detection.v4_models import (
    DetectorV4Config,
    V4DetectorRunResult,
    V4ScopeArbitration,
    V4ScopeDisposition,
)
from retryrail.events.models import NormalizedPaymentEvent, PaymentMethod


@dataclass(slots=True)
class _V4RunState:
    """Lifecycle state keyed by a complete canonical cohort identity."""

    active: dict[str, _Episode]
    completed: list[_Episode]
    suppressed: list[V2SuppressedCandidate]
    cooldown_until: dict[str, datetime]


class V4ArbitrationError(RuntimeError):
    """Confirmed episode state is invalid for deterministic arbitration."""


class DetectorV4Engine(DetectorV2Engine):
    """Observe parents and children independently, then emit one overlap winner."""

    _v4_config: DetectorV4Config

    def __init__(self, config: DetectorV4Config) -> None:
        super().__init__(config)
        self._v4_config = config

    def _window_boundaries(
        self,
        *,
        cutoff: datetime,
        partition_started_at: datetime,
        window_minutes: int,
        frozen_baseline: tuple[datetime, datetime] | None,
    ) -> tuple[datetime, datetime, datetime]:
        """Preserve v3's guarded, frozen, non-overlapping baseline."""

        evaluated_at = _require_aware(cutoff)
        partition_start = _require_aware(partition_started_at)
        frozen_started_at = (
            _require_aware(frozen_baseline[0]) if frozen_baseline is not None else None
        )
        frozen_ended_at = (
            _require_aware(frozen_baseline[1]) if frozen_baseline is not None else None
        )
        current_started_at = max(
            partition_start,
            evaluated_at - timedelta(minutes=window_minutes),
            frozen_ended_at or partition_start,
        )
        if frozen_started_at is not None and frozen_ended_at is not None:
            return current_started_at, frozen_started_at, frozen_ended_at

        baseline_ended_at = max(
            partition_start,
            evaluated_at - timedelta(minutes=self._v4_config.baseline_guard_minutes),
        )
        if baseline_ended_at > current_started_at:
            msg = "baseline guard cannot overlap the selected current window"
            raise DetectorInputError(msg)
        baseline_started_at = max(
            partition_start,
            baseline_ended_at - timedelta(minutes=self.config.baseline_lookback_minutes),
        )
        return current_started_at, baseline_started_at, baseline_ended_at

    def _confirmation_thresholds(
        self,
        cohort: Sequence[CohortPredicate],
    ) -> _ConfirmationThresholds:
        """Preserve v3's bounded tolerance for sparse parent observations."""

        thresholds = super()._confirmation_thresholds(cohort)
        if thresholds.tolerates_statistical_misses:
            return thresholds
        return replace(
            thresholds,
            maximum_minutes=self._v4_config.method_confirmation_maximum_minutes,
            tolerates_statistical_misses=(
                self._v4_config.method_confirmation_tolerates_statistical_misses
            ),
        )

    def run(
        self,
        events: Iterable[NormalizedPaymentEvent],
        *,
        partition_started_at: datetime,
        partition_ended_at: datetime,
    ) -> V4DetectorRunResult:
        """Reconstruct terminal attempts before canonical-cohort detection."""

        return self.run_attempts(
            reconstruct_attempts(events),
            partition_started_at=partition_started_at,
            partition_ended_at=partition_ended_at,
        )

    def run_attempts(
        self,
        attempts: Sequence[AttemptFact],
        *,
        partition_started_at: datetime,
        partition_ended_at: datetime,
    ) -> V4DetectorRunResult:
        """Advance each cohort independently and arbitrate confirmed overlaps."""

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
        attempts_by_cohort = _index_attempts(attempts)
        state = _V4RunState(active={}, completed=[], suppressed=[], cooldown_until={})

        cutoff = start + timedelta(minutes=self.config.step_minutes)
        while cutoff <= end:
            for method in methods:
                for cohort in _candidate_cohorts(attempts, method, cutoff):
                    cohort_attempts = attempts_by_cohort[_cohort_key(cohort)]
                    self._advance_cohort(
                        cohort_attempts,
                        method=method,
                        cohort=cohort,
                        evaluated_at=cutoff,
                        partition_started_at=start,
                        state=state,
                    )
            cutoff += timedelta(minutes=self.config.step_minutes)

        confirmed = list(state.completed)
        for episode in state.active.values():
            cohort_attempts = attempts_by_cohort[_cohort_key(episode.cohort)]
            if episode.confirmed_at is None:
                state.suppressed.append(
                    self._suppress(
                        episode,
                        V2CandidateDisposition.PARTITION_ENDED,
                        cohort_attempts,
                        evaluated_at=end,
                    )
                )
            else:
                confirmed.append(episode)

        incidents, arbitrations = self._arbitrate_confirmed(
            confirmed,
            attempts,
            partition_ended_at=end,
        )
        return V4DetectorRunResult(
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
            arbitrations=arbitrations,
        )

    def _advance_cohort(
        self,
        attempts: Sequence[AttemptFact],
        *,
        method: PaymentMethod,
        cohort: tuple[CohortPredicate, ...],
        evaluated_at: datetime,
        partition_started_at: datetime,
        state: _V4RunState,
    ) -> None:
        key = _cohort_key(cohort)
        episode = state.active.get(key)
        if episode is None:
            self._start_cohort_candidate(
                attempts,
                method=method,
                cohort=cohort,
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
            episode.signals.append(
                self._signal(
                    evaluation,
                    method=method,
                    confirmation_error_signature=episode.confirmation_error_signature,
                )
            )
            episode.healthy_minutes = 0
            if episode.confirmed_at is None:
                if self._confirmation_met(
                    episode,
                    attempts,
                    evaluated_at=evaluated_at,
                ):
                    episode.confirmed_at = evaluated_at
                elif self._confirmation_expired(episode, evaluated_at=evaluated_at):
                    self._expire_cohort_candidate(
                        attempts,
                        episode=episode,
                        evaluated_at=evaluated_at,
                        disposition=V2CandidateDisposition.CONFIRMATION_EXPIRED,
                        state=state,
                    )
            return

        if episode.confirmed_at is None:
            confirmation = self._confirmation_thresholds(episode.cohort)
            if confirmation.tolerates_statistical_misses and not (
                self._confirmation_expired(episode, evaluated_at=evaluated_at)
            ):
                return
            self._expire_cohort_candidate(
                attempts,
                episode=episode,
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
                del state.active[key]
        else:
            episode.healthy_minutes = 0

    def _start_cohort_candidate(
        self,
        attempts: Sequence[AttemptFact],
        *,
        method: PaymentMethod,
        cohort: tuple[CohortPredicate, ...],
        evaluated_at: datetime,
        partition_started_at: datetime,
        state: _V4RunState,
    ) -> None:
        key = _cohort_key(cohort)
        if evaluated_at < state.cooldown_until.get(key, partition_started_at):
            return
        evaluation = self.evaluate_cohort(
            attempts,
            cohort=cohort,
            evaluated_at=evaluated_at,
            partition_started_at=partition_started_at,
        )
        if (
            evaluation.statistics.gate_reason is not V2GateReason.PASSED
            or evaluation.statistics.recent_actionable_failures == 0
        ):
            return
        signal = self._signal(evaluation, method=method)
        state.active[key] = _Episode(
            method=method,
            cohort=cohort,
            confirmation_error_signature=signal.confirmation_error_signature,
            signals=[signal],
        )

    def _expire_cohort_candidate(
        self,
        attempts: Sequence[AttemptFact],
        *,
        episode: _Episode,
        evaluated_at: datetime,
        disposition: V2CandidateDisposition,
        state: _V4RunState,
    ) -> None:
        key = _cohort_key(episode.cohort)
        state.suppressed.append(
            self._suppress(
                episode,
                disposition,
                attempts,
                evaluated_at=evaluated_at,
            )
        )
        del state.active[key]
        state.cooldown_until[key] = evaluated_at + timedelta(
            minutes=self.config.suppressed_candidate_cooldown_minutes
        )

    def _arbitrate_confirmed(
        self,
        episodes: Sequence[_Episode],
        attempts: Sequence[AttemptFact],
        *,
        partition_ended_at: datetime,
    ) -> tuple[tuple[V2DetectedIncident, ...], tuple[V4ScopeArbitration, ...]]:
        """Select one incident from every connected overlap component."""

        incidents: list[V2DetectedIncident] = []
        arbitrations: list[V4ScopeArbitration] = []
        for group in _overlap_groups(episodes, partition_ended_at=partition_ended_at):
            winner, confirmed_child_count = self._select_scope_winner(group)
            incident = self._finalize_incident(winner, attempts)
            incidents.append(incident)
            for candidate in group:
                if candidate is winner:
                    continue
                arbitrations.append(
                    _arbitration_record(
                        candidate,
                        winner=winner,
                        selected_incident_id=incident.incident_id,
                        confirmed_child_count=confirmed_child_count,
                        detector_version=self.config.detector_version,
                        synthetic=all(item.synthetic for item in attempts),
                    )
                )
        return (
            tuple(
                sorted(
                    incidents,
                    key=lambda item: (item.opened_at, item.incident_id),
                )
            ),
            tuple(
                sorted(
                    arbitrations,
                    key=lambda item: (item.candidate_opened_at, item.arbitration_id),
                )
            ),
        )

    def _select_scope_winner(
        self,
        episodes: Sequence[_Episode],
    ) -> tuple[_Episode, int]:
        parents = tuple(
            item
            for item in episodes
            if _cohort_level(item.cohort) is V2CohortLevel.METHOD
        )
        children = tuple(
            item
            for item in episodes
            if _cohort_level(item.cohort) is V2CohortLevel.METHOD_ISSUER
        )
        confirmed_child_count = len({_cohort_key(item.cohort) for item in children})
        if (
            parents
            and confirmed_child_count
            >= self._v4_config.broad_scope_minimum_confirmed_children
        ):
            return _strongest_episode(parents), confirmed_child_count
        if children:
            return _strongest_episode(children), confirmed_child_count
        return _strongest_episode(parents), confirmed_child_count


def _overlap_groups(
    episodes: Sequence[_Episode],
    *,
    partition_ended_at: datetime,
) -> tuple[tuple[_Episode, ...], ...]:
    """Create deterministic connected components of same-method time overlap."""

    groups: list[tuple[_Episode, ...]] = []
    for method in sorted({item.method for item in episodes}, key=lambda item: item.value):
        ordered = sorted(
            (item for item in episodes if item.method is method),
            key=lambda item: (
                item.signals[0].statistics.evaluated_at,
                _cohort_key(item.cohort),
            ),
        )
        current: list[_Episode] = []
        current_end: datetime | None = None
        for episode in ordered:
            started_at = episode.signals[0].statistics.evaluated_at
            ended_at = episode.resolved_at or partition_ended_at
            if current and current_end is not None and started_at > current_end:
                groups.append(tuple(current))
                current = []
                current_end = None
            current.append(episode)
            current_end = ended_at if current_end is None else max(current_end, ended_at)
        if current:
            groups.append(tuple(current))
    return tuple(groups)


def _index_attempts(
    attempts: Sequence[AttemptFact],
) -> dict[str, tuple[AttemptFact, ...]]:
    """Index immutable attempt slices once without changing event-time filtering."""

    indexed: dict[str, list[AttemptFact]] = {}
    for attempt in attempts:
        method_cohort = tuple(
            cohort
            for cohort in _candidate_cohorts(
                (attempt,),
                attempt.method,
                attempt.occurred_at + timedelta(microseconds=1),
            )
        )
        for cohort in method_cohort:
            indexed.setdefault(_cohort_key(cohort), []).append(attempt)
    return {key: tuple(values) for key, values in indexed.items()}


def _strongest_episode(episodes: Sequence[_Episode]) -> _Episode:
    if not episodes:
        raise V4ArbitrationError

    def strength(episode: _Episode) -> tuple[int, int, int, int, datetime, str]:
        peak = max(
            (
                item.statistics
                for item in episode.signals
                if item.cohort == episode.cohort
            ),
            key=lambda item: (
                item.excess_actionable_failures,
                item.at_risk_gmv_subunits,
                item.confidence_ppm,
                -int(item.evaluated_at.timestamp()),
            ),
        )
        unique_evidence = {
            event_id
            for signal in episode.signals
            for event_id in signal.recent_confirmation_event_ids
        }
        return (
            -peak.excess_actionable_failures,
            -peak.at_risk_gmv_subunits,
            -len(unique_evidence),
            -peak.confidence_ppm,
            episode.signals[0].statistics.evaluated_at,
            _cohort_key(episode.cohort),
        )

    return min(episodes, key=strength)


def _candidate_id(episode: _Episode, detector_version: str) -> str:
    first = episode.signals[0]
    identity = (
        f"{first.merchant_id}\x1f{detector_version}\x1f"
        f"{_cohort_key(episode.cohort)}\x1f"
        f"{first.statistics.evaluated_at.isoformat()}"
    )
    return f"cand_{hashlib.sha256(identity.encode()).hexdigest()[:24]}"


def _arbitration_record(
    candidate: _Episode,
    *,
    winner: _Episode,
    selected_incident_id: str,
    confirmed_child_count: int,
    detector_version: str,
    synthetic: bool,
) -> V4ScopeArbitration:
    candidate_id = _candidate_id(candidate, detector_version)
    if (
        _cohort_level(candidate.cohort) is V2CohortLevel.METHOD
        and _cohort_level(winner.cohort) is V2CohortLevel.METHOD_ISSUER
    ):
        disposition = V4ScopeDisposition.PARENT_NOT_SELECTED_SINGLE_CHILD
    elif (
        _cohort_level(candidate.cohort) is V2CohortLevel.METHOD_ISSUER
        and _cohort_level(winner.cohort) is V2CohortLevel.METHOD
    ):
        disposition = V4ScopeDisposition.CHILD_NOT_SELECTED_MULTI_CHILD_BREADTH
    else:
        disposition = V4ScopeDisposition.PEER_NOT_SELECTED_BY_STRENGTH
    identity = f"{candidate_id}\x1f{selected_incident_id}\x1f{disposition.value}"
    return V4ScopeArbitration(
        arbitration_id=f"arb_{hashlib.sha256(identity.encode()).hexdigest()[:24]}",
        candidate_id=candidate_id,
        method=candidate.method,
        candidate_cohort=candidate.cohort,
        candidate_opened_at=candidate.signals[0].statistics.evaluated_at,
        candidate_confirmed_at=_confirmed_at(candidate),
        candidate_last_observed_at=candidate.signals[-1].statistics.evaluated_at,
        selected_incident_id=selected_incident_id,
        selected_cohort=winner.cohort,
        selected_opened_at=winner.signals[0].statistics.evaluated_at,
        confirmed_child_cohort_count=confirmed_child_count,
        disposition=disposition,
        synthetic=synthetic,
    )


def _confirmed_at(episode: _Episode) -> datetime:
    if episode.confirmed_at is None:
        raise V4ArbitrationError
    return episode.confirmed_at


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        msg = "detector timestamps must be timezone-aware"
        raise DetectorInputError(msg)
    return value.astimezone(UTC)
