"""Guarded-baseline detector-v3 engine built on frozen v2 evidence semantics."""

from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from retryrail.contracts.domain import CohortPredicate
from retryrail.detection.engine import DetectorInputError
from retryrail.detection.v2_engine import DetectorV2Engine, _ConfirmationThresholds
from retryrail.detection.v3_models import DetectorV3Config


class DetectorV3Engine(DetectorV2Engine):
    """Retain v2 gates and lifecycle while preventing pre-signal baseline drift."""

    config: DetectorV3Config

    def __init__(self, config: DetectorV3Config) -> None:
        super().__init__(config)

    def _window_boundaries(
        self,
        *,
        cutoff: datetime,
        partition_started_at: datetime,
        window_minutes: int,
        frozen_baseline: tuple[datetime, datetime] | None,
    ) -> tuple[datetime, datetime, datetime]:
        """End unopened baselines one full guard interval before evaluation."""

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
            evaluated_at - timedelta(minutes=self.config.baseline_guard_minutes),
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
        """Let method candidates survive sparse steps within a bounded horizon."""

        thresholds = super()._confirmation_thresholds(cohort)
        if thresholds.tolerates_statistical_misses:
            return thresholds
        return replace(
            thresholds,
            maximum_minutes=self.config.method_confirmation_maximum_minutes,
            tolerates_statistical_misses=(
                self.config.method_confirmation_tolerates_statistical_misses
            ),
        )


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        msg = "detector timestamps must be timezone-aware"
        raise DetectorInputError(msg)
    return value.astimezone(UTC)
