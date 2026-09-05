"""Typed M6 boundaries for redacted model input and advisory output."""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from retryrail.contracts.domain import (
    CohortPredicate,
    IncidentEvidence,
    IncidentStatus,
    RecoveryTemplate,
    StrictContract,
)
from retryrail.detection.models import AttributionItem
from retryrail.events.models import Currency, Dimension, Identifier
from retryrail.recovery.models import (
    RulesBasedIncidentBrief,
    RulesBasedPlanFallback,
)

BoundedAnalystText = Annotated[str, Field(min_length=1, max_length=400)]
AnalystStopCondition = Literal[
    "POLICY_INCIDENT_NOT_ACTION_ELIGIBLE",
    "POLICY_OPERATING_MODE_ANALYZE_ONLY",
    "POLICY_CUSTOMER_OPTED_OUT",
    "POLICY_ATTEMPT_CAP_REACHED",
    "POLICY_COOLDOWN_ACTIVE",
    "POLICY_PLAN_EXPIRED",
    "POLICY_KILL_SWITCH_ON",
    "POLICY_PAYMENT_ALREADY_RECOVERED",
]
REQUIRED_ANALYST_STOP_CONDITIONS = frozenset(
    {
        "POLICY_INCIDENT_NOT_ACTION_ELIGIBLE",
        "POLICY_OPERATING_MODE_ANALYZE_ONLY",
        "POLICY_CUSTOMER_OPTED_OUT",
        "POLICY_ATTEMPT_CAP_REACHED",
        "POLICY_COOLDOWN_ACTIVE",
        "POLICY_PLAN_EXPIRED",
        "POLICY_KILL_SWITCH_ON",
        "POLICY_PAYMENT_ALREADY_RECOVERED",
    }
)


class IncidentSnapshot(StrictContract):
    """PII-free allowlist sent to an incident-analysis provider.

    This contract deliberately excludes merchant identifiers, raw events, payment
    identifiers, descriptions, notes, customer fields, secrets and action authority.
    """

    schema_version: Literal["1.0.0"] = "1.0.0"
    snapshot_id: Identifier
    incident_id: Identifier
    detector_version: Identifier
    status: IncidentStatus
    opened_at: AwareDatetime
    last_observed_at: AwareDatetime
    affected_cohort: tuple[CohortPredicate, ...] = Field(min_length=1, max_length=8)
    evidence: IncidentEvidence
    verified_attributions: tuple[AttributionItem, ...] = Field(min_length=1, max_length=3)
    detector_hypotheses: tuple[BoundedAnalystText, ...] = Field(min_length=1, max_length=3)
    unknowns: tuple[BoundedAnalystText, ...] = Field(min_length=1, max_length=5)
    gmv_at_risk_subunits: int = Field(ge=0)
    currency: Currency
    action_eligible: bool
    scope: Literal["single_merchant"] = "single_merchant"
    synthetic: bool

    @model_validator(mode="after")
    def validate_citations_and_time(self) -> Self:
        """Require bounded evidence references and monotonic incident time."""

        if self.last_observed_at < self.opened_at:
            msg = "snapshot observation time cannot precede incident opening"
            raise ValueError(msg)
        event_ids = {
            event_id
            for attribution in self.verified_attributions
            for event_id in attribution.evidence_event_ids
        }
        if not event_ids:
            msg = "snapshot requires verified attribution citations"
            raise ValueError(msg)
        return self


class AnalystEvidenceClaim(StrictContract):
    """One advisory statement tied to detector-created evidence identifiers."""

    statement: str = Field(min_length=1, max_length=400)
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=8)
    evidence_kind: Literal["verified_observation"] = "verified_observation"


class AnalystHypothesis(StrictContract):
    """One explicitly inferred, merchant-local explanation."""

    statement: str = Field(min_length=1, max_length=400)
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=8)
    confidence_ppm: int = Field(ge=0, le=1_000_000)
    evidence_kind: Literal["inferred_hypothesis"] = "inferred_hypothesis"


class ModelIncidentBrief(StrictContract):
    """Structured, grounded model brief with no execution authority."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    executive_summary: str = Field(min_length=1, max_length=600)
    executive_summary_evidence_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=8,
    )
    verified_evidence: tuple[AnalystEvidenceClaim, ...] = Field(min_length=2, max_length=6)
    hypotheses: tuple[AnalystHypothesis, ...] = Field(max_length=3)
    unknowns: tuple[BoundedAnalystText, ...] = Field(min_length=1, max_length=5)
    confidence_ppm: int = Field(ge=0, le=1_000_000)
    scope: Literal["single_merchant"] = "single_merchant"
    mutation_authority: Literal[False] = False


class ModelRecoveryProposal(StrictContract):
    """Advisory proposal restricted to one server-owned template identifier."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    recommended_template: Literal[RecoveryTemplate.STANDARD_PAYMENT_LINK] = (
        RecoveryTemplate.STANDARD_PAYMENT_LINK
    )
    rationale: str = Field(min_length=1, max_length=500)
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=8)
    opportunity_gmv_subunits: int = Field(ge=0)
    currency: Currency
    opportunity_interpretation: Literal["at_risk_opportunity_not_forecast"] = (
        "at_risk_opportunity_not_forecast"
    )
    expected_benefit: Literal["not_estimated_without_outcome_evidence"] = (
        "not_estimated_without_outcome_evidence"
    )
    customer_risk: Literal[
        "No customer message is sent; any action still requires merchant approval."
    ] = "No customer message is sent; any action still requires merchant approval."
    stop_conditions: tuple[AnalystStopCondition, ...] = Field(min_length=8, max_length=8)
    requires_external_approval: Literal[True] = True
    executable: Literal[False] = False
    external_notifications_enabled: Literal[False] = False

    @model_validator(mode="after")
    def validate_stop_conditions(self) -> Self:
        """Require the exact server-known stop-condition set with no duplicates."""

        if frozenset(self.stop_conditions) != REQUIRED_ANALYST_STOP_CONDITIONS:
            msg = "proposal must retain every known stop condition exactly once"
            raise ValueError(msg)
        return self


class ModelIncidentAnalysisDraft(StrictContract):
    """Exact strict-schema payload requested from the configured model."""

    brief: ModelIncidentBrief
    proposal: ModelRecoveryProposal


class AnalystModelStatus(StrEnum):
    """Low-cardinality model outcomes exposed without provider response text."""

    SUCCEEDED = "succeeded"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    INVALID_RESPONSE = "invalid_response"
    PROVIDER_ERROR = "provider_error"


class AnalystProvenance(StrictContract):
    """Versioned, cost-observable provenance safe for audit and UI."""

    provider: Literal["openai"] = "openai"
    model: Dimension
    prompt_version: Identifier
    output_schema_version: Literal["1.0.0"] = "1.0.0"
    evaluator_version: Identifier
    latency_ms: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    estimated_cost_microusd: int | None = Field(default=None, ge=0)
    pricing_version: Literal[
        "openai_public_pricing_2026_09_05",
        "unavailable_for_model",
    ]
    schema_repair_attempts: int = Field(ge=0, le=1)
    response_stored_by_provider: Literal[False] = False

    @model_validator(mode="after")
    def validate_usage(self) -> Self:
        """Require internally consistent token accounting."""

        if self.total_tokens != self.input_tokens + self.output_tokens:
            msg = "total tokens must equal input plus output tokens"
            raise ValueError(msg)
        pricing_available = self.pricing_version == "openai_public_pricing_2026_09_05"
        if pricing_available is not (self.estimated_cost_microusd is not None):
            msg = "cost estimate and pricing version must agree"
            raise ValueError(msg)
        return self


class ModelIncidentAnalysis(StrictContract):
    """Durable advisory document bound to one redacted source snapshot."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    analysis_id: Identifier
    incident_id: Identifier
    snapshot_id: Identifier
    brief: ModelIncidentBrief
    proposal: ModelRecoveryProposal
    provenance: AnalystProvenance
    model_status: Literal[AnalystModelStatus.SUCCEEDED] = AnalystModelStatus.SUCCEEDED
    fallback_used: Literal[False] = False
    synthetic: bool


class ModelIncidentAnalysisResponse(StrictContract):
    """Created or content-addressed replay of a successful model analysis."""

    disposition: Literal["created", "replayed"]
    analysis: ModelIncidentAnalysis
    plan_fallback: RulesBasedPlanFallback


class AnalystFallbackResponse(StrictContract):
    """Deterministic completion plus sanitized reason for a failed model attempt."""

    disposition: Literal["created", "replayed"]
    brief: RulesBasedIncidentBrief
    plan_fallback: RulesBasedPlanFallback
    model_status: Literal[
        AnalystModelStatus.UNAVAILABLE,
        AnalystModelStatus.TIMEOUT,
        AnalystModelStatus.REFUSED,
        AnalystModelStatus.INVALID_RESPONSE,
        AnalystModelStatus.PROVIDER_ERROR,
    ]
    fallback_used: Literal[True] = True
    attempted_model: Dimension | None = None
    prompt_version: Identifier
    evaluator_version: Identifier
    fallback_reason_code: Identifier


IncidentAnalysisResult = ModelIncidentAnalysisResponse | AnalystFallbackResponse
