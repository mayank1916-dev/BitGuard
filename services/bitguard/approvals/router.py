"""V1 API Router for Quorum Approvals and Hold Tickets (Milestones S14 & S16).

Invariants:
- Invariant #4: Raw Byte Source of Truth (independent decode).
- Invariant #5: WebAuthn Hardware Approvals over tx digest.
- Invariant #6: Asymmetric Policy Evolution (deny/cancel = 1 authorized person instant; approval = quorum of 2 distinct approvers).
- Invariant #7: Immutable Audit Trail.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status

from services.bitguard.approvals.hold_store import hold_store
from services.bitguard.approvals.models import (
    ApproveHoldRequest,
    ApproveHoldResponse,
    DenyHoldRequest,
    DenyHoldResponse,
    HoldViewResponse,
)
from services.bitguard.approvals.service import approval_service
from services.bitguard.models import (
    CancelHoldRequest,
    CancelHoldResponse,
    HoldTicket,
    Permission,
    UserResponse,
)
from services.bitguard.rbac import require_permission

router = APIRouter(prefix="/holds", tags=["Quorum Approvals & Quarantine Holds"])


@router.get(
    "",
    response_model=list[HoldTicket],
    summary="List quarantined hold tickets",
    description="Returns active quarantined hold tickets optionally filtered by state (requires READ_DECISIONS).",
)
def list_holds(
    limit: int = Query(50, ge=1, le=200, description="Maximum tickets to return"),
    state: str | None = Query(None, description="Optional state filter (PENDING, APPROVED, DENIED, EXPIRED, CANCELLED, RELEASED)"),
    current_user: UserResponse = Depends(require_permission(Permission.READ_DECISIONS)),
) -> list[HoldTicket]:
    """Retrieves list of active and recent hold tickets."""
    return hold_store.list_active(limit=limit, state=state)


@router.get(
    "/{hold_id}/view",
    response_model=HoldViewResponse,
    summary="Ground-truth console view for quarantined hold ticket",
    description=(
        "Recomputes the decoded transaction directly from raw unsigned bytes, "
        "providing the operator/approver with ground truth payload and risk reasons."
    ),
)
def view_hold(
    hold_id: str,
    current_user: UserResponse = Depends(require_permission(Permission.READ_DECISIONS)),
) -> HoldViewResponse:
    """Returns console payload view with ground-truth decoded transaction."""
    return approval_service.view_hold(hold_id=hold_id)


@router.get(
    "/{hold_id}",
    response_model=HoldTicket,
    summary="Get single quarantined hold ticket by ID",
    description="Retrieves the hold ticket by ID including decoded transaction, reasons, state, and approvals.",
)
def get_hold(
    hold_id: str,
    current_user: UserResponse = Depends(require_permission(Permission.READ_DECISIONS)),
) -> HoldTicket:
    """Retrieves a single hold ticket by ID."""
    ticket = hold_store.get(hold_id)
    if ticket is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Hold ticket '{hold_id}' not found",
        )
    return ticket


@router.post(
    "/{hold_id}/approve",
    response_model=ApproveHoldResponse,
    summary="Submit WebAuthn hardware key approval for hold ticket",
    description=(
        "Submits a WebAuthn assertion whose challenge equals the hold transaction digest. "
        "Enforces quorum of 2 distinct approvers. Once quorum is reached, atomically releases "
        "one-time approval token and signs via signer shim."
    ),
)
async def approve_hold(
    hold_id: str,
    payload: ApproveHoldRequest,
    current_user: UserResponse = Depends(require_permission(Permission.APPROVE_HOLD)),
) -> ApproveHoldResponse:
    """Submits hardware WebAuthn approval towards release quorum."""
    return await approval_service.approve_hold(
        hold_id=hold_id,
        approver_user=current_user,
        assertion=payload.assertion,
    )


@router.post(
    "/{hold_id}/deny",
    response_model=DenyHoldResponse,
    summary="Deny and tighten quarantined hold ticket immediately",
    description=(
        "Invariant #6: Any single Approver can deny and tighten immediately, "
        "canceling limit reservations and locking the ticket into DENIED."
    ),
)
def deny_hold(
    hold_id: str,
    payload: DenyHoldRequest = DenyHoldRequest(),
    current_user: UserResponse = Depends(require_permission(Permission.APPROVE_HOLD)),
) -> DenyHoldResponse:
    """Denies quarantined transaction immediately."""
    return approval_service.deny_hold(
        hold_id=hold_id,
        approver_user=current_user,
        reason=payload.reason,
    )


@router.post(
    "/{hold_id}/cancel",
    response_model=CancelHoldResponse,
    summary="Cancel quarantined hold ticket (tighten policy)",
    description=(
        "Invariant #6: Operator or SecOps cancels and tightens immediately. "
        "Releases limit reservations and marks the ticket CANCELLED."
    ),
)
def cancel_hold(
    hold_id: str,
    payload: CancelHoldRequest = CancelHoldRequest(),
    current_user: UserResponse = Depends(require_permission(Permission.POLICY_TIGHTEN)),
) -> CancelHoldResponse:
    """Cancels a quarantined hold ticket immediately."""
    return approval_service.cancel_hold(
        hold_id=hold_id,
        cancelled_by_user=current_user,
        reason=payload.reason,
    )
