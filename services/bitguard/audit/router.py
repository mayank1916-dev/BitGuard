"""FastAPI router for cryptographic audit trail verification and anchoring (Milestone S21 / F18).

Invariants:
- Invariant #7: Immutable Audit Trail.
- Invariant #8: Explicit Data Provenance.
"""

import logging

from fastapi import APIRouter, Depends, Query

from services.bitguard.audit.models import (
    AuditEntryModel,
    AuditVerifyResponse,
    ManualAnchorResponse,
)
from services.bitguard.audit.service import audit_service
from services.bitguard.models import DataLabel, Permission, Role, UserResponse
from services.bitguard.rbac import require_permission, require_role

logger = logging.getLogger("bitguard.audit.router")

router = APIRouter(prefix="/audit", tags=["Audit Chain"])


@router.get(
    "/verify",
    response_model=AuditVerifyResponse,
    summary="Cryptographically verify entire audit ledger",
    description=(
        "Recomputes the complete SHA-256 hash chain from genesis to head, "
        "checks sequential contiguity, compares against external WORM object-lock anchors, "
        "and identifies the exact sequence number of any tampering or deletion."
    ),
)
def verify_audit_ledger(
    current_user: UserResponse = Depends(require_permission(Permission.READ_AUDIT)),
) -> AuditVerifyResponse:
    """Recomputes whole hash chain and verifies against stored object-lock anchors."""
    return audit_service.verify_chain()


@router.get(
    "/entries",
    response_model=list[AuditEntryModel],
    summary="List paginated audit trail entries",
    description="Returns recorded audit log entries with cryptographic hash chain metadata.",
)
def list_audit_entries(
    limit: int = Query(default=50, ge=1, le=500),
    action: str | None = None,
    actor: str | None = None,
    current_user: UserResponse = Depends(require_permission(Permission.READ_AUDIT)),
) -> list[AuditEntryModel]:
    """Retrieves audit entries filtered by action or actor."""
    all_entries = audit_service.get_entries()
    filtered = all_entries
    if action:
        filtered = [e for e in filtered if e.action == action]
    if actor:
        filtered = [e for e in filtered if e.actor == actor]

    # Return the most recent entries up to limit
    slice_entries = filtered[-limit:]
    return [
        AuditEntryModel(
            seq=e.seq,
            ts=e.ts,
            actor=e.actor,
            action=e.action,
            payload=e.payload,
            prev_hash=e.prev_hash,
            entry_hash=e.entry_hash,
            data_label=e.data_label,
        )
        for e in slice_entries
    ]


@router.post(
    "/anchor",
    response_model=ManualAnchorResponse,
    summary="Trigger immediate external object-lock anchor checkpoint",
    description="Writes the active chain head {head_hash, seq, ts} to the WORM object-lock bucket.",
)
def create_manual_anchor(
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.COMPLIANCE)),
) -> ManualAnchorResponse:
    """Creates a new external object-lock checkpoint."""
    receipt = audit_service.anchor_head()
    return ManualAnchorResponse(
        status="ANCHORED",
        anchor=receipt,
        data_label=DataLabel.REAL,
    )
