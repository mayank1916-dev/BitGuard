"""FastAPI router for Versioned Policy Management (Milestone S20 / Section D).

Invariants:
- Invariant #6: Asymmetric Policy Evolution (tightening = single operator, instant; loosening = 2 WebAuthn approvers + cool-down + backtest report).
- Invariant #7: Immutable Audit Trail.
- Invariant #8: Explicit Data Provenance (data_label REAL).
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status

from services.bitguard.models import Role, UserResponse
from services.bitguard.policy.models import (
    ActivatePolicyRequest,
    ApprovePolicyRequest,
    PolicyIntegrityResponse,
    PolicyVersion,
    ProposePolicyRequest,
    RollbackPolicyRequest,
)
from services.bitguard.policy.service import policy_service
from services.bitguard.policy.store import policy_store
from services.bitguard.rbac import get_current_user, require_role

logger = logging.getLogger("bitguard.policy.router")

router = APIRouter(tags=["Policy Management"])


@router.post(
    "/policies",
    response_model=PolicyVersion,
    status_code=status.HTTP_201_CREATED,
    summary="Propose new versioned policy manifest",
    description="Proposes a new declarative policy version. Automatically classifies change as TIGHTEN, LOOSEN, or MIXED, and schedules governance requirements.",
)
def propose_policy(
    payload: ProposePolicyRequest,
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.OPERATOR)),
) -> PolicyVersion:
    """Proposes a new policy manifest."""
    try:
        return policy_service.propose_policy(request=payload, author_user=current_user)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "/policies",
    response_model=list[PolicyVersion],
    summary="List all policy versions",
    description="Returns all versioned policy manifests sorted by creation time descending.",
)
def list_policies(
    limit: int = Query(default=50, ge=1, le=200, description="Max versions to return"),
    current_user: UserResponse = Depends(get_current_user),
) -> list[PolicyVersion]:
    """Lists policy manifests."""
    return policy_store.list_all(limit=limit)


@router.get(
    "/policies/active",
    response_model=PolicyVersion,
    summary="Get currently active policy version",
    description="Returns the currently active, verified policy version governing the decision engines.",
)
def get_active_policy(
    current_user: UserResponse = Depends(get_current_user),
) -> PolicyVersion:
    """Retrieves active policy version."""
    active = policy_store.get_active() or policy_service.get_or_create_baseline()
    return active


@router.get(
    "/policies/{version_id}",
    response_model=PolicyVersion,
    summary="Get policy version details by ID",
    description="Retrieves a specific policy version including content, hash, classification, approvals, and signatures.",
)
def get_policy(
    version_id: str,
    current_user: UserResponse = Depends(get_current_user),
) -> PolicyVersion:
    """Retrieves a policy version by ID."""
    pv = policy_store.get(version_id) or policy_store.get_by_version(version_id)
    if not pv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy version '{version_id}' not found",
        )
    return pv


@router.post(
    "/policies/{version_id}/approve",
    response_model=PolicyVersion,
    summary="Approve policy change with WebAuthn hardware key",
    description="Submits an authorized WebAuthn assertion over policy content hash. Enforces separation of duties (author cannot approve).",
)
def approve_policy(
    version_id: str,
    payload: ApprovePolicyRequest,
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.APPROVER)),
) -> PolicyVersion:
    """Submits WebAuthn approval signature for a pending policy change."""
    try:
        return policy_service.approve_policy(
            version_id=version_id,
            approver_user=current_user,
            assertion=payload.assertion,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/policies/{version_id}/activate",
    response_model=PolicyVersion,
    summary="Activate policy change and hot-reload engines",
    description="Activates a policy version after verifying signature, content hash, approval quorum, and cool-down delay. Hot-reloads decision engine memory.",
)
def activate_policy(
    version_id: str,
    payload: ActivatePolicyRequest | None = None,
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.OPERATOR)),
) -> PolicyVersion:
    """Activates a verified policy version."""
    sig_override = payload.ed25519_signature if payload else None
    try:
        return policy_service.activate_policy(
            version_id=version_id,
            activator_user=current_user,
            ed25519_sig_override=sig_override,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/policies/{version_id}/rollback",
    response_model=PolicyVersion,
    summary="Rollback active policy to previous version",
    description="Rolls back from an active policy version to the previous verified healthy version.",
)
def rollback_policy(
    version_id: str,
    payload: RollbackPolicyRequest,
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN)),
) -> PolicyVersion:
    """Rolls back an active policy."""
    try:
        return policy_service.auto_rollback(
            version_id=version_id,
            reason=f"Operator rollback by {current_user.email}: {payload.reason}",
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/policies/integrity-check",
    response_model=PolicyIntegrityResponse,
    summary="Execute policy integrity scan across engine memory and database",
    description="Compares engine memory loaded hash against database active record and cryptographic release signature. Direct DB tampering triggers fail-closed remediation.",
)
def check_policy_integrity(
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.OPERATOR)),
) -> PolicyIntegrityResponse:
    """Runs periodic policy integrity check."""
    return policy_service.run_integrity_check()
