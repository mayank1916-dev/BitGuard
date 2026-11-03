"""FastAPI router for Circuit Breaker operations (Milestone S18 / F9, F14).

Invariants:
- Invariant #6: Asymmetric Policy Evolution (tightening/lockdown = one person, instant; loosening/unlock = 2-approver WebAuthn quorum).
- Invariant #7: Immutable Audit Trail.
- Invariant #8: Explicit Data Provenance (data_label REAL).
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from services.bitguard.approvals.webauthn import WebAuthnVerificationError
from services.bitguard.breaker.models import (
    BreakerStatusResponse,
    DeescalateApprovalResult,
    DeescalateApproveRequest,
    DeescalateRequestCreate,
    DeescalationRequestModel,
    EscalateRequest,
)
from services.bitguard.breaker.store import distributed_breaker_store
from services.bitguard.models import Permission, Role, UserResponse
from services.bitguard.rbac import require_permission, require_role

logger = logging.getLogger("bitguard.breaker.router")

router = APIRouter(prefix="/breaker", tags=["Circuit Breaker"])


@router.get(
    "",
    response_model=BreakerStatusResponse,
    summary="Get active circuit breaker operational status",
    description="Returns current circuit breaker state, reason, epoch, and active de-escalation request.",
)
def get_breaker_status(
    current_user: UserResponse = Depends(require_permission(Permission.READ_BREAKER)),
) -> BreakerStatusResponse:
    """Retrieves current circuit breaker state and telemetry."""
    return distributed_breaker_store.get_status()


@router.post(
    "/escalate",
    response_model=BreakerStatusResponse,
    summary="Instant circuit breaker escalation",
    description=(
        "SecOps or Admin can escalate to any strictly higher restriction state instantly. "
        "Entering HOLD or LOCKDOWN immediately increments the token epoch (revoking live tokens) "
        "and triggers KeyUsePolicyHook at KMS/HSM level."
    ),
)
def escalate_breaker(
    payload: EscalateRequest,
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN)),
) -> BreakerStatusResponse:
    """Instantly elevates circuit breaker restrictions."""
    try:
        distributed_breaker_store.escalate(
            target_state=payload.target_state,
            reason=payload.reason,
            updated_by=current_user.id,
        )
        return distributed_breaker_store.get_status()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.error("breaker_escalation_failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute circuit breaker escalation: {exc}",
        ) from exc


@router.post(
    "/deescalate-request",
    response_model=DeescalationRequestModel,
    status_code=status.HTTP_201_CREATED,
    summary="Create circuit breaker de-escalation proposal",
    description=(
        "Proposes lowering the circuit breaker state. Generates a 32-byte cryptographic challenge "
        "that must be signed with WebAuthn by 2 distinct authorized approvers."
    ),
)
def create_deescalation_request(
    payload: DeescalateRequestCreate,
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN)),
) -> DeescalationRequestModel:
    """Creates a de-escalation request requiring 2-approver WebAuthn quorum."""
    try:
        return distributed_breaker_store.create_deescalation_request(
            target_state=payload.target_state,
            reason=payload.reason,
            requested_by=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.error("breaker_deescalate_request_failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create de-escalation request: {exc}",
        ) from exc


@router.post(
    "/deescalate-approve",
    response_model=DeescalateApprovalResult,
    summary="Approve circuit breaker de-escalation with WebAuthn assertion",
    description=(
        "Submits a WebAuthn assertion over the de-escalation challenge. "
        "Requires 2 distinct approvers. Requester cannot approve their own proposal. "
        "Once quorum is reached, the breaker state is lowered."
    ),
)
def approve_deescalation(
    payload: DeescalateApproveRequest,
    current_user: UserResponse = Depends(require_role(Role.APPROVER, Role.ADMIN)),
) -> DeescalateApprovalResult:
    """Approves circuit breaker de-escalation proposal using WebAuthn hardware key."""
    try:
        return distributed_breaker_store.approve_deescalation(
            request_id=payload.request_id,
            approver_id=current_user.id,
            assertion=payload.assertion,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except WebAuthnVerificationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"WebAuthn verification failed: {exc.detail} (code={exc.code})",
        ) from exc
    except Exception as exc:
        logger.error("breaker_approve_deescalation_failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal error processing de-escalation approval: {exc}",
        ) from exc
