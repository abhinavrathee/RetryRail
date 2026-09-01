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
