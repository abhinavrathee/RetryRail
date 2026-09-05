"""Low-cardinality Prometheus metrics for the M2 event pipeline."""

from fastapi import APIRouter, Request, Response
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from prometheus_client.exposition import CONTENT_TYPE_LATEST


class PipelineMetrics:
    """Per-application metric registry that never labels customer identifiers."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry(auto_describe=True)
        self.webhook_requests = Counter(
            "retryrail_webhook_requests_total",
            "Authenticated webhook ingestion outcomes.",
            ("result",),
            registry=self.registry,
        )
        self.webhook_signature_failures = Counter(
            "retryrail_webhook_signature_failures_total",
            "Webhook requests rejected before JSON parsing.",
            ("reason",),
            registry=self.registry,
        )
        self.duplicate_events = Counter(
            "retryrail_duplicate_events_total",
            "Duplicate merchant/event identities safely ignored.",
            registry=self.registry,
        )
        self.ingestion_duration = Histogram(
            "retryrail_webhook_ingestion_duration_seconds",
            "Time from application receipt through durable commit.",
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
            registry=self.registry,
        )
        self.event_processing_lag = Histogram(
            "retryrail_event_processing_lag_seconds",
            "Wall time between webhook receipt and projection processing.",
            buckets=(0.01, 0.1, 0.5, 1, 2, 5, 15, 60, 300, 3600, 7200),
            registry=self.registry,
        )
        self.outbox_results = Counter(
            "retryrail_outbox_results_total",
            "Outbox processing results.",
            ("result",),
            registry=self.registry,
        )
        self.outbox_retries = Counter(
            "retryrail_outbox_retries_total",
            "Outbox messages returned to bounded retry.",
            registry=self.registry,
        )
        self.dead_letters = Counter(
            "retryrail_outbox_dead_letters_total",
            "Outbox messages moved to terminal dead-letter state.",
            ("reason",),
            registry=self.registry,
        )
        self.projection_results = Counter(
            "retryrail_payment_projection_results_total",
            "Payment projection state decisions.",
            ("result",),
            registry=self.registry,
        )
        self.detector_runs = Counter(
            "retryrail_detector_runs_total",
            "Deterministic detector refresh outcomes.",
            ("result",),
            registry=self.registry,
        )
        self.incident_detection_latency = Histogram(
            "retryrail_incident_detection_latency_seconds",
            "Wall time for one detector refresh over a persisted source snapshot.",
            buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
            registry=self.registry,
        )
        self.incident_transitions = Counter(
            "retryrail_incident_transitions_total",
            "Durable incident lifecycle changes.",
            ("transition",),
            registry=self.registry,
        )
        self.active_incidents = Gauge(
            "retryrail_active_incidents",
            "Current detected open incidents, including review-only incidents.",
            registry=self.registry,
        )
        self.incident_at_risk_gmv = Gauge(
            "retryrail_incident_at_risk_gmv_subunits",
            "At-risk GMV for detected open incidents in integer currency subunits.",
            registry=self.registry,
        )
        self.recovery_plan_previews = Counter(
            "retryrail_recovery_plan_previews_total",
            "Durable recovery preview outcomes.",
            ("result",),
            registry=self.registry,
        )
        self.recovery_policy_decisions = Counter(
            "retryrail_recovery_policy_decisions_total",
            "Complete deterministic recovery policy outcomes.",
            ("stage", "decision"),
            registry=self.registry,
        )
        self.policy_decisions = Counter(
            "retryrail_policy_decisions_total",
            "Bounded policy-rule outcomes by aggregate decision and reason code.",
            ("decision", "reason"),
            registry=self.registry,
        )
        self.recovery_approval_decisions = Counter(
            "retryrail_recovery_approval_decisions_total",
            "Authenticated merchant approval decision outcomes.",
            ("decision", "result"),
            registry=self.registry,
        )
        self.approval_token_consumptions = Counter(
            "retryrail_approval_token_consumptions_total",
            "Atomic approval-token consumption outcomes.",
            ("result",),
            registry=self.registry,
        )
        self.recovery_action_executions = Counter(
            "retryrail_recovery_action_executions_total",
            "Execute-once recovery outcomes by bounded state.",
            ("result", "state"),
            registry=self.registry,
        )
        self.recovery_actions = Counter(
            "retryrail_recovery_actions_total",
            "Recovery execution results by bounded terminal or pending status.",
            ("status",),
            registry=self.registry,
        )
        self.duplicate_actions_prevented = Counter(
            "retryrail_duplicate_actions_prevented_total",
            "Execute-once replays that returned existing evidence without another mutation.",
            registry=self.registry,
        )
        self.recovery_action_reconciliations = Counter(
            "retryrail_recovery_action_reconciliations_total",
            "Read-only provider reconciliation outcomes by terminal state.",
            ("result", "state"),
            registry=self.registry,
        )
        self.recovery_provider_dispatches = Counter(
            "retryrail_recovery_provider_dispatches_total",
            "Durable pre-network dispatches by bounded provider target.",
            ("target",),
            registry=self.registry,
        )
        self.recovery_provider_outcomes = Counter(
            "retryrail_recovery_provider_outcomes_total",
            "Sanitized create outcomes without merchant or action identifiers.",
            ("target", "result"),
            registry=self.registry,
        )
        self.recovery_provider_lookups = Counter(
            "retryrail_recovery_provider_lookups_total",
            "Lookup-only reconciliation outcomes.",
            ("target", "result"),
            registry=self.registry,
        )
        self.experiment_report_reads = Counter(
            "retryrail_experiment_report_reads_total",
            "Authenticated reads of the immutable synthetic experiment report.",
            ("result",),
            registry=self.registry,
        )
        self.experiment_eligible_payments = Gauge(
            "retryrail_experiment_eligible_payments",
            "Eligible payments in the frozen synthetic experiment.",
            registry=self.registry,
        )
        self.experiment_incremental_recovered_gmv = Gauge(
            "retryrail_experiment_incremental_recovered_gmv_subunits",
            "Estimated synthetic incremental recovered GMV in integer subunits.",
            registry=self.registry,
        )
        self.recovered_gmv = Gauge(
            "retryrail_recovered_gmv_subunits",
            "Observed synthetic recovered GMV in integer subunits by experiment arm.",
            ("arm",),
            registry=self.registry,
        )
        self.experiment_net_recovered_value = Gauge(
            "retryrail_experiment_net_recovered_value_subunits",
            "Synthetic incremental value after action and false-intervention costs.",
            registry=self.registry,
        )
        self.rules_fallback_analyses = Counter(
            "retryrail_rules_fallback_analyses_total",
            "Content-addressed incident briefs produced without a model provider.",
            ("result",),
            registry=self.registry,
        )
        self.incident_analyses = Counter(
            "retryrail_incident_analyses_total",
            "Bounded incident-analysis outcomes without incident or merchant labels.",
            ("result",),
            registry=self.registry,
        )
        self.agent_requests = Counter(
            "retryrail_agent_requests_total",
            "Bounded advisory-model orchestration outcomes.",
            ("result",),
            registry=self.registry,
        )
        self.agent_fallbacks = Counter(
            "retryrail_agent_fallback_total",
            "Deterministic fallback activations by bounded reason code.",
            ("reason",),
            registry=self.registry,
        )
        self.incident_analysis_latency = Histogram(
            "retryrail_incident_analysis_latency_seconds",
            "Provider wall time for one validated redacted incident analysis.",
            buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30),
            registry=self.registry,
        )
        self.agent_latency = Histogram(
            "retryrail_agent_latency_seconds",
            "Provider wall time for one validated redacted advisory request.",
            buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30),
            registry=self.registry,
        )
        self.incident_analysis_tokens = Counter(
            "retryrail_incident_analysis_tokens_total",
            "Validated provider token usage by input or output direction.",
            ("direction",),
            registry=self.registry,
        )
        self.incident_analysis_estimated_cost = Counter(
            "retryrail_incident_analysis_estimated_cost_microusd_total",
            "Versioned public-price estimate for validated model analysis.",
            registry=self.registry,
        )
        self.agent_estimated_cost = Counter(
            "retryrail_agent_estimated_cost_microusd_total",
            "Versioned estimated advisory-model cost in micro-US-dollars.",
            registry=self.registry,
        )


router = APIRouter(tags=["operations"])


@router.get("/metrics", include_in_schema=False)
def metrics(request: Request) -> Response:
    """Expose only the current process's bounded metric registry."""

    pipeline_metrics = request.app.state.metrics
    if not isinstance(pipeline_metrics, PipelineMetrics):
        msg = "application metrics were not initialized"
        raise TypeError(msg)
    return Response(
        content=generate_latest(pipeline_metrics.registry),
        media_type=CONTENT_TYPE_LATEST,
    )
