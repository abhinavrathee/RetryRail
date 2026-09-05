"""Raw-body Razorpay webhook HTTP boundary."""

from typing import Annotated, Literal

from fastapi import APIRouter, Header, HTTPException, Path, Request, Response, status
from pydantic import BaseModel, ConfigDict, StringConstraints

from retryrail.config import Settings
from retryrail.events.ingestion import (
    EventIdentityConflictError,
    EventIngestionService,
    EventPersistenceError,
    WebhookPayloadError,
)
from retryrail.webhooks.signatures import WebhookSignatureError

MerchantPath = Annotated[
    str,
    Path(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_-]+$"),
]
EventHeader = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=80,
        pattern=r"^[A-Za-z0-9_-]+$",
    ),
]

router = APIRouter(prefix="/v1/merchants/{merchant_id}/webhooks", tags=["webhooks"])


class WebhookReceipt(BaseModel):
    """Bounded acknowledgement returned only after a durable transaction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["accepted", "duplicate"]
    event_id: str
    event_internal_id: str


def _http_error(status_code: int, reason_code: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"reason_code": reason_code})


async def _read_bounded_body(request: Request, maximum_bytes: int) -> bytes:
    """Read exact request chunks while stopping before an unbounded allocation."""

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as error:
            raise _http_error(status.HTTP_400_BAD_REQUEST, "CONTENT_LENGTH_INVALID") from error
        if declared_length < 0:
            raise _http_error(status.HTTP_400_BAD_REQUEST, "CONTENT_LENGTH_INVALID")
        if declared_length > maximum_bytes:
            raise _http_error(
                status.HTTP_413_CONTENT_TOO_LARGE,
                "WEBHOOK_BODY_TOO_LARGE",
            )

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > maximum_bytes:
            raise _http_error(
                status.HTTP_413_CONTENT_TOO_LARGE,
                "WEBHOOK_BODY_TOO_LARGE",
            )
        chunks.append(chunk)
    return b"".join(chunks)


@router.post(
    "/razorpay",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Authenticate and durably queue a Razorpay payment event",
)
async def ingest_razorpay_webhook(
    request: Request,
    response: Response,
    merchant_id: MerchantPath,
    razorpay_event_id: Annotated[EventHeader, Header(alias="X-Razorpay-Event-Id")],
    signature: Annotated[str | None, Header(alias="X-Razorpay-Signature")] = None,
) -> WebhookReceipt:
    """Read exact bytes once and verify them before JSON parsing or persistence."""

    settings = request.app.state.settings
    service = request.app.state.ingestion_service
    if not isinstance(settings, Settings) or not isinstance(service, EventIngestionService):
        raise _http_error(status.HTTP_503_SERVICE_UNAVAILABLE, "SERVICE_NOT_READY")
    if merchant_id != settings.merchant_id:
        raise _http_error(status.HTTP_404_NOT_FOUND, "MERCHANT_NOT_FOUND")
    if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
        raise _http_error(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "CONTENT_TYPE_UNSUPPORTED")

    raw_body = await _read_bounded_body(request, settings.max_webhook_body_bytes)
    try:
        result = await service.ingest(
            merchant_id=merchant_id,
            razorpay_event_id=razorpay_event_id,
            raw_body=raw_body,
            signature=signature,
        )
    except WebhookSignatureError as error:
        raise _http_error(status.HTTP_401_UNAUTHORIZED, error.reason_code) from error
    except WebhookPayloadError as error:
        raise _http_error(status.HTTP_422_UNPROCESSABLE_CONTENT, error.reason_code) from error
    except EventIdentityConflictError as error:
        raise _http_error(status.HTTP_409_CONFLICT, error.reason_code) from error
    except EventPersistenceError as error:
        raise _http_error(status.HTTP_503_SERVICE_UNAVAILABLE, error.reason_code) from error

    response.headers["X-RetryRail-Domain-Trace-Id"] = result.trace_id
    return WebhookReceipt(
        status=result.disposition.value,
        event_id=result.razorpay_event_id,
        event_internal_id=result.event_internal_id,
    )
