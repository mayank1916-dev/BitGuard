"""V1 API Router for Quorum Approvals and Hold Tickets (Milestone S16 / F10).

Invariants:
- Invariant #4: Raw Byte Source of Truth (independent decode).
- Invariant #5: WebAuthn Hardware Approvals over tx digest.
- Invariant #6: Asymmetric Policy Evolution (deny = 1 approver instant; approval = quorum of 2 distinct approvers).
- Invariant #7: Immutable Audit Trail.
"""

from fastapi import APIRouter, Depends, Query

from services.bitguard.approvals.hold_store import hold_store
from services.bitguard.approvals.models import (
    ApproveHoldRequest,
    ApproveHoldResponse,
    DenyHoldRequest,
    DenyHoldResponse,
    HoldViewResponse,
)
from services.bitguard.approvals.service import approval_service
from services.bitguard.models import HoldTicket, Permission, UserResponse
from services.bitguard.rbac import require_permission

router = APIRouter(prefix="/holds", tags=["Quorum Approvals & Quarantine Holds"])


@router.get(
    "",
    response_model=list[HoldTicket],
    summary="List quarantined hold tickets",
    description="Returns active quarantined hold tickets (requires READ_DECISIONS).",
)
def list_holds(
    limit: int = Query(50, ge=1, le=200, description="Maximum tickets to return"),
    current_user: UserResponse = Depends(require_permission(Permission.READ_DECISIONS)),
) -> list[HoldTicket]:
    """Retrieves list of active and recent hold tickets."""
    return hold_store.list_active(limit=limit)


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
