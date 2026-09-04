"""Authenticated merchant HTTP boundary for preview, approval and execution."""

import hmac
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Path, Request, status

from retryrail.config import Settings
from retryrail.contracts.recovery import ApprovalDecision
from retryrail.recovery.analysis import RulesBasedIncidentAnalyst
from retryrail.recovery.execution import (
    RecoveryActionNotFoundError,
    RecoveryActionNotReconciliationRequiredError,
    RecoveryExecutionService,
    RecoveryFakeTargetRequiresSyntheticError,
)
from retryrail.recovery.models import (
    ApprovalDecisionRequest,
    ApprovalDecisionResponse,
    CreateRecoveryPlanRequest,
    ExecuteRecoveryPlanRequest,
    ReconcileRecoveryActionRequest,
    RecoveryErrorResponse,
    RecoveryExecutionResponse,
    RecoveryPlanPreviewResponse,
    RecoveryReconciliationResponse,
    RulesBasedIncidentAnalysisResponse,
)
from retryrail.recovery.workflow import (
    ApprovalActorError,
    ApprovalAlreadyDecidedError,
    ApprovalTokenAlreadyUsedError,
    ApprovalTokenExpiredError,
    ApprovalTokenInvalidError,
    IncidentNotFoundError,
    MerchantScopeError,
    PaymentNotEligibleError,
    PaymentNotFoundError,
    PlanExpiredError,
    PlanNotFoundError,
    PlanPolicyDeniedError,
    RecoveryControlsMissingError,
    RecoveryEvidenceInvalidError,
    RecoveryIdempotencyConflictError,
    RecoveryPersistenceError,
    RecoveryWorkflowError,
    RecoveryWorkflowService,
)

RecoveryPath = Annotated[
    str,
    Path(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_-]+$"),
]
MerchantAuthorization = Annotated[
    str | None,
    Header(alias="X-RetryRail-Merchant-Authorization"),
]
ApprovalToken = Annotated[
    str | None,
    Header(alias="X-RetryRail-Approval-Token"),
]

router = APIRouter(prefix="/api/v1", tags=["recovery"])

_ERROR_RESPONSES: dict[int | str, dict[str, object]] = {
    status.HTTP_401_UNAUTHORIZED: {"model": RecoveryErrorResponse},
    status.HTTP_403_FORBIDDEN: {"model": RecoveryErrorResponse},
    status.HTTP_404_NOT_FOUND: {"model": RecoveryErrorResponse},
    status.HTTP_409_CONFLICT: {"model": RecoveryErrorResponse},
    status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": RecoveryErrorResponse},
    status.HTTP_503_SERVICE_UNAVAILABLE: {"model": RecoveryErrorResponse},
}


@router.post(
    "/incidents/{incident_id}/analyze",
    responses=_ERROR_RESPONSES,
    summary="Create a grounded incident brief without a model provider",
)
async def analyze_incident_with_rules(
    request: Request,
    incident_id: RecoveryPath,
    authorization: MerchantAuthorization = None,
) -> RulesBasedIncidentAnalysisResponse:
    """Persist or replay a content-bound rules brief and safe plan fallback."""

    service, settings = _authenticated_analysis_resources(request, authorization)
    try:
        return await service.analyze(
            merchant_id=settings.merchant_id,
            incident_id=incident_id,
        )
    except RecoveryWorkflowError as error:
        raise _http_error(error) from error


@router.post(
    "/incidents/{incident_id}/plans",
    responses=_ERROR_RESPONSES,
    summary="Create an authoritative recovery plan preview",
)
async def create_recovery_plan(
    body: CreateRecoveryPlanRequest,
    request: Request,
    incident_id: RecoveryPath,
    authorization: MerchantAuthorization = None,
) -> RecoveryPlanPreviewResponse:
    """Persist plan/policy evidence without accepting caller-supplied policy facts."""

    service, settings = _authenticated_resources(request, authorization)
    try:
        return await service.create_preview(
            merchant_id=settings.merchant_id,
            incident_id=incident_id,
            payment_id=body.payment_id,
            idempotency_key=body.idempotency_key,
        )
    except RecoveryWorkflowError as error:
        raise _http_error(error) from error


@router.post(
    "/plans/{plan_id}/preview",
    responses=_ERROR_RESPONSES,
    summary="Retrieve and verify a persisted plan preview",
)
async def retrieve_recovery_plan_preview(
    request: Request,
    plan_id: RecoveryPath,
    authorization: MerchantAuthorization = None,
) -> RecoveryPlanPreviewResponse:
    """Return immutable plan/effect/policy evidence with no write or provider call."""

    service, settings = _authenticated_resources(request, authorization)
    try:
        return await service.get_preview(
            merchant_id=settings.merchant_id,
            plan_id=plan_id,
        )
    except RecoveryWorkflowError as error:
        raise _http_error(error) from error


@router.post(
    "/plans/{plan_id}/approve",
    responses=_ERROR_RESPONSES,
    summary="Approve a policy-allowed plan as the merchant",
)
async def approve_recovery_plan(
    body: ApprovalDecisionRequest,
    request: Request,
    plan_id: RecoveryPath,
    authorization: MerchantAuthorization = None,
) -> ApprovalDecisionResponse:
    """Issue one short-lived bearer; only its keyed hash enters durable storage."""

    return await _decide(
        body=body,
        request=request,
        plan_id=plan_id,
        authorization=authorization,
        decision=ApprovalDecision.APPROVE,
    )


@router.post(
    "/plans/{plan_id}/reject",
    responses=_ERROR_RESPONSES,
    summary="Reject a plan as the merchant",
)
async def reject_recovery_plan(
    body: ApprovalDecisionRequest,
    request: Request,
    plan_id: RecoveryPath,
    authorization: MerchantAuthorization = None,
) -> ApprovalDecisionResponse:
    """Persist a terminal token-free merchant rejection outside the model."""

    return await _decide(
        body=body,
        request=request,
        plan_id=plan_id,
        authorization=authorization,
        decision=ApprovalDecision.REJECT,
    )


@router.post(
    "/plans/{plan_id}/execute",
    responses=_ERROR_RESPONSES,
    summary="Execute one approved fake-provider recovery action",
)
async def execute_recovery_plan(
    body: ExecuteRecoveryPlanRequest,
    request: Request,
    plan_id: RecoveryPath,
    authorization: MerchantAuthorization = None,
    approval_token: ApprovalToken = None,
) -> RecoveryExecutionResponse:
    """Freshly revalidate policy, consume approval and write one durable receipt."""

    service, settings = _authenticated_execution_resources(request, authorization)
    try:
        return await service.execute(
            merchant_id=settings.merchant_id,
            plan_id=plan_id,
            raw_approval_token=approval_token,
            idempotency_key=body.idempotency_key,
        )
    except RecoveryWorkflowError as error:
        raise _http_error(error) from error


@router.post(
    "/actions/{action_id}/reconcile",
    responses=_ERROR_RESPONSES,
    summary="Reconcile an ambiguous fake-provider action by stable reference",
)
async def reconcile_recovery_action(
    body: ReconcileRecoveryActionRequest,
    request: Request,
    action_id: RecoveryPath,
    authorization: MerchantAuthorization = None,
) -> RecoveryReconciliationResponse:
    """Perform provider lookup only; this endpoint never retries link creation."""

    service, settings = _authenticated_execution_resources(request, authorization)
    try:
        return await service.reconcile(
            merchant_id=settings.merchant_id,
            action_id=action_id,
            idempotency_key=body.idempotency_key,
        )
    except RecoveryWorkflowError as error:
        raise _http_error(error) from error


async def _decide(
    *,
    body: ApprovalDecisionRequest,
    request: Request,
    plan_id: str,
    authorization: str | None,
    decision: ApprovalDecision,
) -> ApprovalDecisionResponse:
    service, settings = _authenticated_resources(request, authorization)
    try:
        return await service.decide(
            merchant_id=settings.merchant_id,
            plan_id=plan_id,
            actor_id=settings.merchant_approver_id,
            decision=decision,
            idempotency_key=body.idempotency_key,
        )
    except RecoveryWorkflowError as error:
        raise _http_error(error) from error


def _authenticated_resources(
    request: Request,
    authorization: str | None,
) -> tuple[RecoveryWorkflowService, Settings]:
    settings = request.app.state.settings
    service = request.app.state.recovery_workflow_service
    if not isinstance(settings, Settings) or not isinstance(service, RecoveryWorkflowService):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason_code": "SERVICE_NOT_READY"},
        )
    supplied = authorization or ""
    expected = settings.merchant_approval_secret.get_secret_value()
    if not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"reason_code": "MERCHANT_AUTHENTICATION_FAILED"},
        )
    return service, settings


def _authenticated_execution_resources(
    request: Request,
    authorization: str | None,
) -> tuple[RecoveryExecutionService, Settings]:
    _, settings = _authenticated_resources(request, authorization)
    service = request.app.state.recovery_execution_service
    if not isinstance(service, RecoveryExecutionService):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason_code": "SERVICE_NOT_READY"},
        )
    return service, settings


def _authenticated_analysis_resources(
    request: Request,
    authorization: str | None,
) -> tuple[RulesBasedIncidentAnalyst, Settings]:
    _, settings = _authenticated_resources(request, authorization)
    service = request.app.state.rules_based_incident_analyst
    if not isinstance(service, RulesBasedIncidentAnalyst):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason_code": "SERVICE_NOT_READY"},
        )
    return service, settings


def _http_error(error: RecoveryWorkflowError) -> HTTPException:
    if isinstance(
        error,
        (
            MerchantScopeError,
            IncidentNotFoundError,
            PaymentNotFoundError,
            PlanNotFoundError,
            RecoveryActionNotFoundError,
        ),
    ):
        code = status.HTTP_404_NOT_FOUND
    elif isinstance(error, (ApprovalActorError, ApprovalTokenInvalidError)):
        code = (
            status.HTTP_401_UNAUTHORIZED
            if isinstance(error, ApprovalTokenInvalidError)
            else status.HTTP_403_FORBIDDEN
        )
    elif isinstance(error, RecoveryEvidenceInvalidError):
        code = status.HTTP_500_INTERNAL_SERVER_ERROR
    elif isinstance(error, RecoveryPersistenceError):
        code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif isinstance(
        error,
        (
            PaymentNotEligibleError,
            RecoveryControlsMissingError,
            RecoveryIdempotencyConflictError,
            PlanPolicyDeniedError,
            PlanExpiredError,
            ApprovalAlreadyDecidedError,
            ApprovalTokenExpiredError,
            ApprovalTokenAlreadyUsedError,
            RecoveryActionNotReconciliationRequiredError,
            RecoveryFakeTargetRequiresSyntheticError,
        ),
    ):
        code = status.HTTP_409_CONFLICT
    else:
        code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return HTTPException(status_code=code, detail={"reason_code": error.reason_code})
