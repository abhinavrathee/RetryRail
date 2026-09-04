"""Strict M5 contracts for assignment, attribution and incremental-value evidence."""

from enum import StrEnum
from typing import Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from retryrail.contracts.domain import StrictContract
from retryrail.events.models import Currency, Dimension, Identifier, PaymentMethod
from retryrail.synthetic.models import ArtifactPath, ExperimentDesign, Sha256Digest


class ExperimentArm(StrEnum):
    """Mutually exclusive recovery experiment arms."""

    TREATMENT = "treatment"
    CONTROL = "control"


class AmountBandDefinition(StrictContract):
    """A complete non-overlapping integer-subunit amount interval."""

    band_id: Identifier
    lower_bound_subunits: int = Field(ge=0)
    upper_bound_subunits: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        """Reject an empty or inverted interval."""

        if (
            self.upper_bound_subunits is not None
            and self.upper_bound_subunits <= self.lower_bound_subunits
        ):
            msg = "amount-band upper bound must exceed its lower bound"
            raise ValueError(msg)
        return self


class ExperimentSource(StrictContract):
    """Exact qualified synthetic source batch authorized for measurement."""

    dataset_id: Identifier
    dataset_role: Literal["blind"] = "blind"
    merchant_id: Identifier
    currency: Currency
    manifest_path: ArtifactPath
    manifest_sha256: Sha256Digest
    truth_path: ArtifactPath
    truth_sha256: Sha256Digest
    truth_records: int = Field(gt=0)
    detector_version: Identifier
    detector_release_path: ArtifactPath
    detector_release_sha256: Sha256Digest
    detector_release_qualified: Literal[True] = True
    synthetic: Literal[True] = True


class EligibilityDefinition(StrictContract):
    """Selection rule frozen before assignment and shared by both arms."""

    source_rows_scanned_in_full: Literal[True] = True
    incident_members_only: Literal[True] = True
    failed_payments_only: Literal[True] = True
    exclude_already_recovered: Literal[True] = True
    same_rule_for_treatment_and_control: Literal[True] = True
    required_schema_version: Literal["2.0.0"] = "2.0.0"
    required_dataset_role: Literal["blind"] = "blind"
    required_currency: Currency
    synthetic_only: Literal[True] = True


class BootstrapDesign(StrictContract):
    """Pre-outcome uncertainty procedure for both primary and companion metrics."""

    method: Literal["independent_arm_nonparametric_percentile"] = (
        "independent_arm_nonparametric_percentile"
    )
    statistic: Literal["value_per_eligible_difference"] = "value_per_eligible_difference"
    recovery_rate_statistic: Literal["recovery_rate_difference"] = (
        "recovery_rate_difference"
    )
    replicates: int = Field(ge=1_000, le=100_000)
    confidence_level_ppm: Literal[950_000] = 950_000
    namespace: Identifier
    deterministic_sha256_index_draws: Literal[True] = True


class CostAssumptions(StrictContract):
    """Synthetic per-action costs fixed before outcomes, never provider fee claims."""

    currency: Currency
    action_cost_per_treatment_subunits: int = Field(ge=0)
    false_intervention_cost_per_unrecovered_treatment_subunits: int = Field(ge=0)
    interpretation: Literal["synthetic_modeling_assumption_not_razorpay_pricing"] = (
        "synthetic_modeling_assumption_not_razorpay_pricing"
    )


class RecoveryExperimentProtocol(StrictContract):
    """Complete pre-outcome M5 analysis contract."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    protocol_id: Identifier
    experiment_id: Identifier
    status: Literal["frozen_before_assignment_and_outcomes"] = (
        "frozen_before_assignment_and_outcomes"
    )
    frozen_at: AwareDatetime
    source: ExperimentSource
    design: ExperimentDesign
    eligibility: EligibilityDefinition
    amount_bands: tuple[AmountBandDefinition, ...] = Field(min_length=2, max_length=10)
    bootstrap: BootstrapDesign
    costs: CostAssumptions
    primary_estimand: Literal["incremental_recovered_gmv_value_per_eligible"] = (
        "incremental_recovered_gmv_value_per_eligible"
    )
    secondary_estimand: Literal["absolute_recovery_rate_uplift"] = (
        "absolute_recovery_rate_uplift"
    )
    gross_recovery_is_not_incremental: Literal[True] = True
    inconclusive_when_primary_interval_includes_zero: Literal[True] = True
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_protocol(self) -> Self:
        """Bind the inherited M1 design to the complete M5 analysis procedure."""

        if self.design.design_id != "experiment_design_v1":
            msg = "M5 protocol must inherit the frozen M1 experiment design"
            raise ValueError(msg)
        if self.design.frozen_at != self.frozen_at:
            msg = "protocol and embedded design freeze timestamps must match"
            raise ValueError(msg)
        if tuple(self.design.strata) != ("method", "issuer", "amount_band"):
            msg = "experiment strata must remain method, issuer and amount_band"
            raise ValueError(msg)
        if self.eligibility.required_currency != self.source.currency:
            msg = "eligibility and source currencies must match"
            raise ValueError(msg)
        if self.costs.currency != self.source.currency:
            msg = "cost and source currencies must match"
            raise ValueError(msg)
        _validate_amount_bands(self.amount_bands)
        return self


class ExperimentAssignment(StrictContract):
    """One immutable, pre-outcome assignment for an eligible failed payment."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    experiment_id: Identifier
    assignment_id: Identifier
    attempt_id: Identifier
    payment_id: Identifier
    scenario_id: Identifier
    eligible_at: AwareDatetime
    assigned_at: AwareDatetime
    amount_subunits: int = Field(gt=0)
    currency: Currency
    method: PaymentMethod
    issuer: Dimension
    amount_band: Identifier
    stratum_id: Identifier
    arm: ExperimentArm
    assignment_rank_sha256: Sha256Digest
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_assignment_time(self) -> Self:
        """Assignment cannot predate the failure becoming eligible."""

        if self.assigned_at < self.eligible_at:
            msg = "assignment cannot precede eligibility"
            raise ValueError(msg)
        return self


class StratumAssignmentSummary(StrictContract):
    """Assignment balance evidence for one predeclared stratum."""

    stratum_id: Identifier
    method: PaymentMethod
    issuer: Dimension
    amount_band: Identifier
    eligible_count: int = Field(gt=0)
    treatment_count: int = Field(ge=0)
    control_count: int = Field(ge=0)
    treatment_gmv_subunits: int = Field(ge=0)
    control_gmv_subunits: int = Field(ge=0)
    observed_control_allocation_bps: int = Field(ge=0, le=10_000)
    allocation_deviation_bps: int = Field(ge=0, le=10_000)

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        """Reconcile each stratum to its mutually exclusive arm counts."""

        if self.treatment_count + self.control_count != self.eligible_count:
            msg = "stratum arm counts must equal eligible count"
            raise ValueError(msg)
        return self


class ExperimentAssignmentFreeze(StrictContract):
    """Eligibility and assignment bytes fixed before any simulated outcome draw."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    freeze_id: Identifier
    experiment_id: Identifier
    protocol_sha256: Sha256Digest
    frozen_at: AwareDatetime
    source_rows_scanned: int = Field(gt=0)
    eligible_count: int = Field(gt=1)
    eligible_gmv_subunits: int = Field(gt=0)
    currency: Currency
    treatment_count: int = Field(gt=0)
    control_count: int = Field(gt=0)
    eligibility_snapshot_sha256: Sha256Digest
    assignments_sha256: Sha256Digest
    assignments: tuple[ExperimentAssignment, ...] = Field(min_length=2)
    balance_by_stratum: tuple[StratumAssignmentSummary, ...] = Field(min_length=1)
    outcomes_observed: Literal[False] = False
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_freeze(self) -> Self:
        """Reject duplicates, count drift, cross-experiment rows and money drift."""

        if len(self.assignments) != self.eligible_count:
            msg = "assignment rows must equal eligible count"
            raise ValueError(msg)
        payment_ids = tuple(item.payment_id for item in self.assignments)
        assignment_ids = tuple(item.assignment_id for item in self.assignments)
        if len(set(payment_ids)) != len(payment_ids) or len(set(assignment_ids)) != len(
            assignment_ids
        ):
            msg = "assignment payment and assignment identifiers must be unique"
            raise ValueError(msg)
        if any(item.experiment_id != self.experiment_id for item in self.assignments):
            msg = "assignment belongs to another experiment"
            raise ValueError(msg)
        if any(item.currency != self.currency for item in self.assignments):
            msg = "assignment currency differs from experiment currency"
            raise ValueError(msg)
        treatment = sum(item.arm is ExperimentArm.TREATMENT for item in self.assignments)
        control = sum(item.arm is ExperimentArm.CONTROL for item in self.assignments)
        if (treatment, control) != (self.treatment_count, self.control_count):
            msg = "assignment arm counts do not match freeze totals"
            raise ValueError(msg)
        if sum(item.amount_subunits for item in self.assignments) != self.eligible_gmv_subunits:
            msg = "assignment GMV does not match eligibility GMV"
            raise ValueError(msg)
        return self


class RecoveryOutcome(StrictContract):
    """One same-payment outcome observed within the predeclared attribution window."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    experiment_id: Identifier
    assignment_id: Identifier
    payment_id: Identifier
    arm: ExperimentArm
    eligible_at: AwareDatetime
    observed_at: AwareDatetime
    attribution_window_seconds: int = Field(gt=0)
    outcome_draw_sha256: Sha256Digest
    recovered: bool
    amount_subunits: int = Field(gt=0)
    recovered_gmv_subunits: int = Field(ge=0)
    currency: Currency
    action_cost_subunits: int = Field(ge=0)
    false_intervention: bool
    false_intervention_cost_subunits: int = Field(ge=0)
    attribution_rule: Literal["same_payment_within_predeclared_window"] = (
        "same_payment_within_predeclared_window"
    )
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        """Keep attribution, recovery value and false-intervention costs consistent."""

        elapsed = (self.observed_at - self.eligible_at).total_seconds()
        if elapsed < 0 or elapsed > self.attribution_window_seconds:
            msg = "outcome falls outside the attribution window"
            raise ValueError(msg)
        expected_recovered = self.amount_subunits if self.recovered else 0
        if self.recovered_gmv_subunits != expected_recovered:
            msg = "recovered GMV must equal the eligible amount only on recovery"
            raise ValueError(msg)
        if self.arm is ExperimentArm.CONTROL and (
            self.action_cost_subunits != 0
            or self.false_intervention
            or self.false_intervention_cost_subunits != 0
        ):
            msg = "holdout outcomes cannot carry intervention costs"
            raise ValueError(msg)
        if self.false_intervention is not (
            self.arm is ExperimentArm.TREATMENT and not self.recovered
        ):
            msg = "false intervention must mean an unrecovered treatment assignment"
            raise ValueError(msg)
        return self


class RecoveryOutcomeBatch(StrictContract):
    """All synthetic outcomes generated only after the assignment freeze."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    batch_id: Identifier
    experiment_id: Identifier
    protocol_sha256: Sha256Digest
    assignment_freeze_sha256: Sha256Digest
    generated_at: AwareDatetime
    outcome_count: int = Field(gt=1)
    outcomes_sha256: Sha256Digest
    outcomes: tuple[RecoveryOutcome, ...] = Field(min_length=2)
    assignment_frozen_before_outcomes: Literal[True] = True
    metric_scope: Literal["synthetic_batch_not_live_merchant_performance"] = (
        "synthetic_batch_not_live_merchant_performance"
    )
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_batch(self) -> Self:
        """Require complete unique outcomes from one experiment."""

        if len(self.outcomes) != self.outcome_count:
            msg = "outcome rows must equal outcome count"
            raise ValueError(msg)
        assignment_ids = tuple(item.assignment_id for item in self.outcomes)
        if len(set(assignment_ids)) != len(assignment_ids):
            msg = "outcome assignment identifiers must be unique"
            raise ValueError(msg)
        if any(item.experiment_id != self.experiment_id for item in self.outcomes):
            msg = "outcome belongs to another experiment"
            raise ValueError(msg)
        return self


class ExperimentArmSummary(StrictContract):
    """Raw arm-level recovery totals; no causal relabeling."""

    arm: ExperimentArm
    eligible_count: int = Field(gt=0)
    eligible_gmv_subunits: int = Field(gt=0)
    recovered_count: int = Field(ge=0)
    recovery_rate_ppm: int = Field(ge=0, le=1_000_000)
    recovered_gmv_subunits: int = Field(ge=0)
    value_per_eligible_subunits_rounded: int = Field(ge=0)
    action_count: int = Field(ge=0)
    action_cost_subunits: int = Field(ge=0)
    false_intervention_count: int = Field(ge=0)
    false_intervention_cost_subunits: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        """Bound successes and holdout intervention costs."""

        if self.recovered_count > self.eligible_count:
            msg = "recovered count cannot exceed eligible count"
            raise ValueError(msg)
        if self.recovered_gmv_subunits > self.eligible_gmv_subunits:
            msg = "recovered GMV cannot exceed eligible GMV"
            raise ValueError(msg)
        if self.arm is ExperimentArm.CONTROL and any(
            (
                self.action_count,
                self.action_cost_subunits,
                self.false_intervention_count,
                self.false_intervention_cost_subunits,
            )
        ):
            msg = "control arm cannot contain intervention costs"
            raise ValueError(msg)
        return self


class BootstrapUncertainty(StrictContract):
    """Deterministic percentile intervals around value and recovery-rate uplift."""

    method: Literal["independent_arm_nonparametric_percentile"]
    replicates: int = Field(ge=1_000)
    confidence_level_ppm: Literal[950_000] = 950_000
    bootstrap_seed_sha256: Sha256Digest
    incremental_gmv_lower_subunits: int
    incremental_gmv_point_subunits: int
    incremental_gmv_upper_subunits: int
    incremental_gmv_interval_includes_zero: bool
    recovery_rate_uplift_lower_bps: int
    recovery_rate_uplift_point_bps: int
    recovery_rate_uplift_upper_bps: int
    recovery_rate_interval_includes_zero: bool

    @model_validator(mode="after")
    def validate_intervals(self) -> Self:
        """Require ordered intervals and truthful zero-inclusion labels."""

        if not (
            self.incremental_gmv_lower_subunits
            <= self.incremental_gmv_point_subunits
            <= self.incremental_gmv_upper_subunits
        ):
            msg = "incremental GMV interval must contain its point estimate"
            raise ValueError(msg)
        if not (
            self.recovery_rate_uplift_lower_bps
            <= self.recovery_rate_uplift_point_bps
            <= self.recovery_rate_uplift_upper_bps
        ):
            msg = "recovery-rate interval must contain its point estimate"
            raise ValueError(msg)
        gmv_includes_zero = (
            self.incremental_gmv_lower_subunits <= 0 <= self.incremental_gmv_upper_subunits
        )
        rate_includes_zero = (
            self.recovery_rate_uplift_lower_bps
            <= 0
            <= self.recovery_rate_uplift_upper_bps
        )
        if self.incremental_gmv_interval_includes_zero is not gmv_includes_zero:
            msg = "incremental GMV zero-inclusion label is inconsistent"
            raise ValueError(msg)
        if self.recovery_rate_interval_includes_zero is not rate_includes_zero:
            msg = "recovery-rate zero-inclusion label is inconsistent"
            raise ValueError(msg)
        return self


class IncrementalValueSummary(StrictContract):
    """Raw, counterfactual, incremental and net value kept explicitly separate."""

    currency: Currency
    gross_treatment_recovered_gmv_subunits: int = Field(ge=0)
    observed_control_recovered_gmv_subunits: int = Field(ge=0)
    estimated_natural_recovery_in_treatment_subunits: int = Field(ge=0)
    incremental_recovered_gmv_subunits: int
    action_cost_subunits: int = Field(ge=0)
    false_intervention_cost_subunits: int = Field(ge=0)
    net_recovered_value_subunits: int
    absolute_recovery_rate_uplift_bps: int
    incremental_recovered_payments_milli: int
    estimator: Literal["difference_in_value_per_eligible_times_treatment_count"] = (
        "difference_in_value_per_eligible_times_treatment_count"
    )

    @model_validator(mode="after")
    def validate_value_arithmetic(self) -> Self:
        """Prevent gross or pre-cost values from being presented as net impact."""

        if self.incremental_recovered_gmv_subunits != (
            self.gross_treatment_recovered_gmv_subunits
            - self.estimated_natural_recovery_in_treatment_subunits
        ):
            msg = "incremental GMV must subtract estimated natural recovery from gross"
            raise ValueError(msg)
        if self.net_recovered_value_subunits != (
            self.incremental_recovered_gmv_subunits
            - self.action_cost_subunits
            - self.false_intervention_cost_subunits
        ):
            msg = "net value must subtract action and false-intervention costs"
            raise ValueError(msg)
        return self


class RecoveryExperimentReport(StrictContract):
    """Reviewer-facing M5 report for a full, versioned synthetic batch."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    report_id: Identifier
    experiment_id: Identifier
    generated_at: AwareDatetime
    protocol_sha256: Sha256Digest
    assignment_freeze_sha256: Sha256Digest
    outcome_batch_sha256: Sha256Digest
    source_manifest_sha256: Sha256Digest
    source_truth_sha256: Sha256Digest
    source_rows_scanned: int = Field(gt=0)
    eligible_count: int = Field(gt=1)
    treatment: ExperimentArmSummary
    control: ExperimentArmSummary
    balance_by_stratum: tuple[StratumAssignmentSummary, ...] = Field(min_length=1)
    value: IncrementalValueSummary
    uncertainty: BootstrapUncertainty
    conclusion: Literal[
        "statistically_positive_synthetic_incremental_value",
        "statistically_negative_synthetic_incremental_value",
        "inconclusive_synthetic_experiment",
    ]
    gross_recovery_is_not_incremental: Literal[True] = True
    metric_scope: Literal["synthetic_batch_not_live_merchant_performance"] = (
        "synthetic_batch_not_live_merchant_performance"
    )
    synthetic: Literal[True] = True

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        """Reconcile arm totals and force uncertainty-aware conclusion wording."""

        if self.treatment.arm is not ExperimentArm.TREATMENT:
            msg = "treatment summary has the wrong arm"
            raise ValueError(msg)
        if self.control.arm is not ExperimentArm.CONTROL:
            msg = "control summary has the wrong arm"
            raise ValueError(msg)
        if self.treatment.eligible_count + self.control.eligible_count != self.eligible_count:
            msg = "arm sample sizes must equal report eligibility"
            raise ValueError(msg)
        if self.uncertainty.incremental_gmv_interval_includes_zero:
            expected_conclusion = "inconclusive_synthetic_experiment"
        elif self.uncertainty.incremental_gmv_lower_subunits > 0:
            expected_conclusion = "statistically_positive_synthetic_incremental_value"
        else:
            expected_conclusion = "statistically_negative_synthetic_incremental_value"
        if self.conclusion != expected_conclusion:
            msg = "report conclusion does not follow the precommitted uncertainty rule"
            raise ValueError(msg)
        return self


def _validate_amount_bands(bands: tuple[AmountBandDefinition, ...]) -> None:
    """Require contiguous coverage from zero through an open-ended final band."""

    previous_upper = 0
    for index, band in enumerate(bands):
        if band.lower_bound_subunits != previous_upper:
            msg = "amount bands must be contiguous and begin at zero"
            raise ValueError(msg)
        if band.upper_bound_subunits is None:
            if index != len(bands) - 1:
                msg = "only the final amount band can be open-ended"
                raise ValueError(msg)
            continue
        previous_upper = band.upper_bound_subunits
    if bands[-1].upper_bound_subunits is not None:
        msg = "final amount band must be open-ended"
        raise ValueError(msg)
