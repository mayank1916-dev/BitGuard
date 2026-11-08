"""REST API Router for Emergency Break-Glass Overrides (Milestone S24 / F17)."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from services.bitguard.break_glass import BreakGlassManifest, break_glass_store
from services.bitguard.models import Role, UserResponse
from services.bitguard.rbac import require_role

logger = logging.getLogger("bitguard.break_glass.router")

router = APIRouter(prefix="/break-glass", tags=["Break-Glass"])


class ProposeBreakGlassRequest(BaseModel):
    """Payload to initiate a two-person break-glass degraded mode request."""

    reason: str = Field(..., description="Operational emergency rationale for break-glass override")
    allowed_destinations: list[str] = Field(
        ...,
        min_length=1,
        description="Pre-approved destination addresses permitted during override",
    )
    duration_seconds: int = Field(
        default=3600,
        ge=300,
        le=14400,
        description="Time-box duration in seconds (5m to 4h)",
    )


class ApproveBreakGlassRequest(BaseModel):
    """Payload to provide an authorized signature/approval for break-glass override."""

    webauthn_assertion: dict[str, Any] | None = Field(
        default=None,
        description="WebAuthn hardware key assertion data",
    )


class RevokeBreakGlassRequest(BaseModel):
    """Payload to instantly terminate break-glass override."""

    reason: str = Field(default="Emergency resolved or manual override revoked")


@router.post(
    "/propose",
    response_model=BreakGlassManifest,
    status_code=status.HTTP_201_CREATED,
    summary="Propose an emergency break-glass override",
    description="Initiates a time-boxed degraded mode request requiring two distinct approvers.",
)
async def propose_break_glass(
    req: ProposeBreakGlassRequest,
    current_user: UserResponse = Depends(require_role([Role.ADMIN, Role.SECOPS])),
) -> BreakGlassManifest:
    """Creates a pending break-glass request."""
    try:
        return break_glass_store.propose(
            reason=req.reason,
            proposed_by=current_user.id,
            allowed_destinations=req.allowed_destinations,
            duration_seconds=req.duration_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/{override_id}/approve",
    response_model=BreakGlassManifest,
    summary="Approve break-glass request",
    description="Second approver transitions request to ACTIVE for the specified time window.",
)
async def approve_break_glass(
    override_id: str,
    req: ApproveBreakGlassRequest,
    current_user: UserResponse = Depends(require_role([Role.ADMIN, Role.SECOPS])),
) -> BreakGlassManifest:
    """Registers approval. Separation of duties: proposer cannot approve own request."""
    try:
        return break_glass_store.approve(
            manifest_id=override_id,
            approver_id=current_user.id,
            role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            webauthn_assertion=req.webauthn_assertion,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Break-glass request '{override_id}' not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/{override_id}/revoke",
    response_model=BreakGlassManifest,
    summary="Revoke break-glass override",
    description="Instantly cancels or deactivates break-glass override (tightening: single operator).",
)
async def revoke_break_glass(
    override_id: str,
    req: RevokeBreakGlassRequest,
    current_user: UserResponse = Depends(require_role([Role.ADMIN, Role.SECOPS])),
) -> BreakGlassManifest:
    """Revokes the break-glass request."""
    try:
        return break_glass_store.revoke(
            manifest_id=override_id,
            revoked_by=current_user.id,
            reason=req.reason,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Break-glass request '{override_id}' not found") from exc


@router.get(
    "/active",
    response_model=BreakGlassManifest | None,
    summary="Get active break-glass override",
    description="Returns current active unexpired override if any, or null.",
)
async def get_active_break_glass() -> BreakGlassManifest | None:
    """Retrieves current active break-glass override."""
    return break_glass_store.get_active()


@router.get(
    "/{override_id}",
    response_model=BreakGlassManifest,
    summary="Get break-glass request by ID",
)
async def get_break_glass_by_id(override_id: str) -> BreakGlassManifest:
    """Retrieves a break-glass request by ID."""
    manifest = break_glass_store.get(override_id)
    if not manifest:
        raise HTTPException(status_code=404, detail=f"Break-glass request '{override_id}' not found")
    return manifest
