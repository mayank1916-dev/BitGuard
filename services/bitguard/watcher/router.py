"""API router for WatchedAddress CRUD and Watcher block inspection (Milestone S17 / F6).

Invariants:
- Role RBAC: SecOps role to add/manage, any Operator/Viewer can view.
- Invariant #7: Immutable Audit Trail.
- Invariant #8: Explicit Data Provenance (data_label REAL).
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status

from services.bitguard.models import (
    CreateWatchedAddressRequest,
    Permission,
    UpdateWatchedAddressRequest,
    UserResponse,
    WatchedAddress,
    WatcherAlert,
)
from services.bitguard.rbac import require_permission
from services.bitguard.watcher.store import watched_address_store
from services.bitguard.watcher.worker import delegation_watcher

router = APIRouter(tags=["Delegation Watcher & Watched Addresses"])


@router.post(
    "/watched-addresses",
    response_model=WatchedAddress,
    status_code=status.HTTP_201_CREATED,
    summary="Register a hot wallet address for delegation watching",
    description="Registers an internal hot wallet address for bytecode, delegation, and nonce monitoring. Requires SecOps role.",
)
def create_watched_address(
    payload: CreateWatchedAddressRequest,
    current_user: UserResponse = Depends(require_permission(Permission.MANAGE_WATCHED_ADDRESSES)),
) -> WatchedAddress:
    """Registers a new hot wallet address under monitoring."""
    return watched_address_store.create(payload)


@router.get(
    "/watched-addresses",
    response_model=list[WatchedAddress],
    summary="List all watched hot wallet addresses",
    description="Returns all registered watched addresses with delegation state, provider agreement, and recent alerts. Any Operator or Viewer can view.",
)
def list_watched_addresses(
    current_user: UserResponse = Depends(require_permission(Permission.READ_WATCHED_ADDRESSES)),
) -> list[WatchedAddress]:
    """Lists all monitored addresses with enriched delegation and alert telemetry."""
    addresses = watched_address_store.list_all()
    recent_alerts = delegation_watcher.recent_alerts

    for item in addresses:
        addr_lower = item.address.lower()
        matched_alerts = [a for a in recent_alerts if a.address.lower() == addr_lower]
        item.recent_alerts = matched_alerts

        # Check provider agreement status
        has_disagreement = any(a.alert_code == "PROVIDER_DISAGREEMENT" for a in matched_alerts)
        item.provider_agreement = "disagree" if has_disagreement else "all agree"

        # Check delegation state
        unapproved_alert = next((a for a in matched_alerts if a.severity == "CRITICAL" and "DELEGATION" in a.alert_code), None)
        if unapproved_alert:
            item.delegation_state = "UNAPPROVED"
            item.delegate_address = unapproved_alert.details.get("delegate", item.delegate_address)
            item.delegate_code_hash = unapproved_alert.details.get("delegate_code_hash", item.delegate_code_hash)
        elif item.delegate_address or (item.allowed_delegates and item.delegation_state == "allowed delegate"):
            item.delegation_state = "allowed delegate"
        else:
            if not item.delegation_state or item.delegation_state not in ["allowed delegate", "UNAPPROVED"]:
                item.delegation_state = "none"

        # Update last scanned block
        if delegation_watcher.last_scanned_block and not item.last_scanned_block:
            item.last_scanned_block = delegation_watcher.last_scanned_block

    return addresses


@router.get(
    "/watched-addresses/{watched_id}",
    response_model=WatchedAddress,
    summary="Get single watched address details",
    description="Retrieves a watched address by ID. Requires READ_WATCHED_ADDRESSES.",
)
def get_watched_address(
    watched_id: str,
    current_user: UserResponse = Depends(require_permission(Permission.READ_WATCHED_ADDRESSES)),
) -> WatchedAddress:
    """Retrieves monitored address by ID."""
    entry = watched_address_store.get(watched_id)
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Watched address '{watched_id}' not found",
        )
    return entry


@router.put(
    "/watched-addresses/{watched_id}",
    response_model=WatchedAddress,
    summary="Update watched address configuration",
    description="Updates allowlisted delegates, expected code hash, or status. Requires SecOps role.",
)
def update_watched_address(
    watched_id: str,
    payload: UpdateWatchedAddressRequest,
    current_user: UserResponse = Depends(require_permission(Permission.MANAGE_WATCHED_ADDRESSES)),
) -> WatchedAddress:
    """Updates watched address properties."""
    updates = payload.model_dump(exclude_unset=True)
    updated = watched_address_store.update(watched_id, updates)
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Watched address '{watched_id}' not found",
        )
    return updated


@router.delete(
    "/watched-addresses/{watched_id}",
    summary="Delete a watched address",
    description="Removes a watched address from monitoring. Requires SecOps role.",
)
def delete_watched_address(
    watched_id: str,
    current_user: UserResponse = Depends(require_permission(Permission.MANAGE_WATCHED_ADDRESSES)),
) -> dict[str, str]:
    """Deletes monitored address."""
    deleted = watched_address_store.delete(watched_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Watched address '{watched_id}' not found",
        )
    return {"status": "deleted", "id": watched_id}


@router.post(
    "/watcher/scan",
    response_model=list[WatcherAlert],
    summary="Trigger a block scan for watched addresses",
    description="Scans the specified block (or latest block) across multi-provider RPC nodes.",
)
def scan_blocks(
    block_number: int | None = Query(None, description="Block number to scan (defaults to latest)"),
    current_user: UserResponse = Depends(require_permission(Permission.MANAGE_WATCHED_ADDRESSES)),
) -> list[WatcherAlert]:
    """Triggers an on-demand watcher scan."""
    return delegation_watcher.scan_block(block_number=block_number)


@router.get(
    "/watcher/alerts",
    response_model=list[WatcherAlert],
    summary="List recent watcher security alerts",
    description="Returns recent alerts generated during on-chain block and bytecode inspection.",
)
def list_watcher_alerts(
    current_user: UserResponse = Depends(require_permission(Permission.READ_WATCHED_ADDRESSES)),
) -> list[WatcherAlert]:
    """Retrieves all recent security alerts."""
    return delegation_watcher.recent_alerts
