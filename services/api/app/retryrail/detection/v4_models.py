"""Typed detector-v4 hierarchy lifecycle and arbitration contracts."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from retryrail.contracts.domain import CohortPredicate, StrictContract
from retryrail.detection.v2_models import DetectorV2Config, V2DetectorRunResult
from retryrail.events.models import PaymentMethod

_BROAD_SCOPE_MINIMUM_CONFIRMED_CHILDREN = 2


class V4ScopeDisposition(StrEnum):
    """Why one confirmed overlapping candidate did not emit an incident."""

    PARENT_NOT_SELECTED_SINGLE_CHILD = "parent_not_selected_single_confirmed_child"
    CHILD_NOT_SELECTED_MULTI_CHILD_BREADTH = (
        "child_not_selected_multi_child_confirmed_breadth"
    )
    PEER_NOT_SELECTED_BY_STRENGTH = "peer_not_selected_by_deterministic_strength"


class V4ScopeArbitration(StrictContract):
    """Durable label-free disposition for a confirmed overlapping candidate."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    arbitration_id: str = Field(pattern=r"^arb_[a-f0-9]{24}$")
    candidate_id: str = Field(pattern=r"^cand_[a-f0-9]{24}$")
    detector_version: Literal["detector_v4_0_0"] = "detector_v4_0_0"
    method: PaymentMethod
    candidate_cohort: tuple[CohortPredicate, ...] = Field(min_length=1, max_length=2)
    candidate_opened_at: AwareDatetime
    candidate_confirmed_at: AwareDatetime
    candidate_last_observed_at: AwareDatetime
    selected_incident_id: str = Field(pattern=r"^inc_[a-f0-9]{24}$")
    selected_cohort: tuple[CohortPredicate, ...] = Field(min_length=1, max_length=2)
    selected_opened_at: AwareDatetime
    confirmed_child_cohort_count: int = Field(ge=0)
    disposition: V4ScopeDisposition
    arbitration_strategy: Literal["confirmed_child_breadth_then_strength_v1"] = (
        "confirmed_child_breadth_then_strength_v1"
    )
    runtime_action_eligible: Literal[False] = False
    synthetic: bool

    @model_validator(mode="after")
    def validate_arbitration(self) -> Self:
        """Bind both cohorts to one method and keep candidate time monotonic."""

        candidate_method = self.candidate_cohort[0].value
        selected_method = self.selected_cohort[0].value
        if candidate_method != self.method.value or selected_method != self.method.value:
            msg = "arbitrated cohorts must belong to the declared payment method"
            raise ValueError(msg)
        if not (
            self.candidate_opened_at
            <= self.candidate_confirmed_at
            <= self.candidate_last_observed_at
        ):
            msg = "arbitrated candidate timestamps must be monotonic"
            raise ValueError(msg)
        if self.candidate_id == self.selected_incident_id:
            msg = "candidate and selected incident identities must remain distinct"
            raise ValueError(msg)
        if self.candidate_cohort == self.selected_cohort:
            msg = "an arbitration loser cannot equal the selected canonical cohort"
            raise ValueError(msg)
        candidate_is_parent = len(self.candidate_cohort) == 1
        selected_is_parent = len(self.selected_cohort) == 1
        if self.disposition is V4ScopeDisposition.PARENT_NOT_SELECTED_SINGLE_CHILD:
            valid_shape = (
                candidate_is_parent
                and not selected_is_parent
                and self.confirmed_child_cohort_count == 1
            )
        elif self.disposition is V4ScopeDisposition.CHILD_NOT_SELECTED_MULTI_CHILD_BREADTH:
            valid_shape = (
                not candidate_is_parent
                and selected_is_parent
                and self.confirmed_child_cohort_count
                >= _BROAD_SCOPE_MINIMUM_CONFIRMED_CHILDREN
            )
        else:
            valid_shape = candidate_is_parent is selected_is_parent
        if not valid_shape:
            msg = "scope disposition must agree with parent/child evidence shape"
            raise ValueError(msg)
        return self


class DetectorV4Config(DetectorV2Config):
    """V3-equivalent gates plus a precommitted canonical-cohort lifecycle."""

    schema_version: Literal["4.0.0"] = "4.0.0"  # type: ignore[assignment]
    detector_version: Literal["detector_v4_0_0"] = "detector_v4_0_0"
    protocol_id: Literal["detector_v4_protocol_v1"] = "detector_v4_protocol_v1"
    protocol_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    development_evidence_ids: tuple[str, str, str]
    revealed_v2_development_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    revealed_v3_development_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    baseline_guard_minutes: int = Field(gt=0, le=1_440)
    method_confirmation_maximum_minutes: int = Field(gt=0, le=240)
    method_confirmation_tolerates_statistical_misses: Literal[True] = True
    candidate_state_key: Literal["canonical_cohort"] = "canonical_cohort"
    scope_arbitration_strategy: Literal[
        "confirmed_child_breadth_then_strength_v1"
    ] = "confirmed_child_breadth_then_strength_v1"
    broad_scope_minimum_confirmed_children: Literal[2] = 2

    @model_validator(mode="after")
    def validate_v4_boundary(self) -> Self:
        """Reject evidence drift or any hidden weakening of predecessor gates."""

        if self.development_evidence_ids != (
            "detector_v2_development_v1",
            "detector_v2_official_blind_ef49a16703b1612ef774",
            "detector_v3_official_blind_1a1852634945b54e300a",
        ):
            msg = "detector-v4 development evidence must match the precommitted triple"
            raise ValueError(msg)
        if self.baseline_guard_minutes < max(self.current_window_minutes):
            msg = "baseline guard must cover the maximum current window"
            raise ValueError(msg)
        if self.baseline_guard_minutes % self.step_minutes:
            msg = "baseline guard must align to the detector step"
            raise ValueError(msg)
        minimum_confirmation_minutes = (self.method_confirmation_signals - 1) * (
            self.step_minutes
        )
        if self.method_confirmation_maximum_minutes < minimum_confirmation_minutes:
            msg = "method confirmation maximum cannot precede its signal horizon"
            raise ValueError(msg)
        if self.method_confirmation_maximum_minutes % self.step_minutes:
            msg = "method confirmation maximum must align to the detector step"
            raise ValueError(msg)

        expected_gate_values = {
            "candidate_levels": ("method", "method_issuer"),
            "step_minutes": 5,
            "current_window_minutes": (15, 30, 60),
            "baseline_lookback_minutes": 240,
            "method_minimum_current_attempts": 10,
            "issuer_minimum_current_attempts": 2,
            "issuer_minimum_attempts_per_hour": 8,
            "method_baseline_minimum_attempts": 50,
            "issuer_baseline_minimum_attempts": 10,
            "minimum_actionable_failures": 2,
            "method_minimum_actionable_rate_drop_bps": 1500,
            "issuer_minimum_actionable_rate_drop_bps": 2500,
            "method_confidence_threshold_ppm": 950000,
            "issuer_confidence_threshold_ppm": 900000,
            "minimum_excess_actionable_failures": 2,
            "minimum_at_risk_gmv_subunits": 50000,
            "recent_evidence_minutes": 5,
            "method_confirmation_signals": 4,
            "method_confirmation_evidence_steps": 3,
            "method_confirmation_unique_actionable_failures": 4,
            "method_confirmation_requires_fresh_latest_step": True,
            "issuer_confirmation_signals": 3,
            "issuer_confirmation_evidence_steps": 2,
            "issuer_confirmation_unique_actionable_failures": 2,
            "issuer_confirmation_requires_fresh_latest_step": True,
            "issuer_confirmation_minimum_post_open_attempts": 5,
            "issuer_confirmation_maximum_minutes": 60,
            "suppressed_candidate_cooldown_minutes": 30,
            "healthy_window_minutes": 60,
            "actionable_error_sources": ("bank", "gateway", "wallet"),
            "non_actionable_error_sources": ("customer",),
            "attribution_minimum_failures": 2,
            "attribution_issuer_share_ppm": 800000,
            "baseline_guard_minutes": 60,
            "method_confirmation_maximum_minutes": 30,
            "method_confirmation_tolerates_statistical_misses": True,
        }
        actual = self.model_dump(mode="python")
        changed = tuple(
            name for name, expected in expected_gate_values.items() if actual[name] != expected
        )
        if changed:
            msg = "detector-v4 cannot change precommitted core gates: " + ", ".join(
                changed
            )
            raise ValueError(msg)
        return self


@dataclass(frozen=True, slots=True)
class V4DetectorRunResult(V2DetectorRunResult):
    """Label-free v4 output plus durable scope-arbitration dispositions."""

    arbitrations: tuple[V4ScopeArbitration, ...]


@dataclass(frozen=True, slots=True)
class V4EpisodeInterval:
    """Internal immutable interval used to test deterministic overlap grouping."""

    started_at: datetime
    ended_at: datetime
