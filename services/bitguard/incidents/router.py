"""FastAPI router for Incident response, Runbook execution, and Escalation (Milestone S19 / F14).

Invariants:
- Invariant #5: WebAuthn Hardware Approvals. Approval steps require hardware key WebAuthn assertions over the challenge.
- Invariant #6: Asymmetric Policy Evolution. Containment is instant and automatic; unlock/release requires WebAuthn approval.
- Invariant #7: Immutable Audit Trail.
- Invariant #8: Explicit Data Provenance (data_label REAL).
- Invariant #11: Strict Wording: 'Reduces and contains unauthorized signing'. Target p99 under 15 ms, measured.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status

from services.bitguard.incidents.escalation import escalation_manager
from services.bitguard.incidents.executor import runbook_executor
from services.bitguard.incidents.models import (
    AcknowledgeIncidentRequest,
    ApproveIncidentStepRequest,
    Incident,
    Runbook,
    TickChecklistRequest,
    TriggerRunbookRequest,
)
from services.bitguard.incidents.store import incident_store
from services.bitguard.models import Role, UserResponse
from services.bitguard.rbac import get_current_user, require_role

logger = logging.getLogger("bitguard.incidents.router")

router = APIRouter(tags=["Incidents & Runbooks"])


@router.get(
    "/incidents",
    response_model=list[Incident],
    summary="List security incidents and automated containment records",
    description="Returns all active and resolved security incidents, including detection latency, timeline events, and containment status.",
)
def list_incidents(
    status_filter: str | None = Query(default=None, alias="status", description="Filter by status (OPEN, CONTAINED, RESOLVED, ESCALATED)"),
    trigger_filter: str | None = Query(default=None, alias="trigger", description="Filter by trigger type"),
    limit: int = Query(default=50, ge=1, le=500, description="Max incidents to return"),
    current_user: UserResponse = Depends(get_current_user),
) -> list[Incident]:
    """Retrieves security incidents and their containment metrics."""
    return incident_store.list_all(status=status_filter, trigger=trigger_filter, limit=limit)


@router.get(
    "/incidents/{incident_id}",
    response_model=Incident,
    summary="Get incident details by ID",
    description="Returns full incident details including audit timeline events, checklist items, and approval gates.",
)
def get_incident(
    incident_id: str,
    current_user: UserResponse = Depends(get_current_user),
) -> Incident:
    """Retrieves an incident record by ID."""
    incident = incident_store.get(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return incident


@router.post(
    "/incidents/trigger",
    response_model=Incident,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger runbook containment manually or via security signal",
    description="Initiates automated containment runbook steps (circuit breaker escalation, token revocation, on-call alert) and creates an incident record.",
)
def trigger_incident_runbook(
    payload: TriggerRunbookRequest,
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.OPERATOR)),
) -> Incident:
    """Executes a declarative runbook for an incident trigger."""
    context = dict(payload.context)
    context.setdefault("triggered_by", current_user.email)
    return runbook_executor.trigger_runbook(trigger=payload.trigger, context=context)


@router.post(
    "/incidents/{incident_id}/checklist/{action}/tick",
    response_model=Incident,
    summary="Mark manual remediation checklist item as completed",
    description="Marks a manual remediation task (e.g., rotate deposit addresses, neutralise delegation, sweep to cold) as completed with operator attribution and timestamp.",
)
def tick_checklist_item(
    incident_id: str,
    action: str,
    payload: TickChecklistRequest | None = None,
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.OPERATOR)),
) -> Incident:
    """Completes a manual checklist action item."""
    ticked_by = (payload and payload.ticked_by) or current_user.email
    notes = payload.notes if payload else None

    try:
        return runbook_executor.tick_checklist_item(
            incident_id=incident_id,
            action=action,
            ticked_by=ticked_by,
            notes=notes,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/incidents/{incident_id}/acknowledge",
    response_model=Incident,
    summary="Acknowledge on-call incident alert",
    description="Acknowledges an on-call paging notification to halt automatic tiered escalation.",
)
async def acknowledge_incident(
    incident_id: str,
    payload: AcknowledgeIncidentRequest | None = None,
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.OPERATOR, Role.APPROVER)),
) -> Incident:
    """Acknowledges an on-call page."""
    ack_by = (payload and payload.acknowledged_by) or current_user.email
    try:
        return await escalation_manager.acknowledge_incident(
            incident_id=incident_id,
            acknowledged_by=ack_by,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post(
    "/incidents/{incident_id}/escalate",
    response_model=Incident,
    summary="Manually advance incident escalation tier",
    description="Manually advances an incident to the next on-call escalation level and dispatches pages.",
)
async def manually_escalate_incident(
    incident_id: str,
    reason: str = Query(default="Manual operator escalation", description="Reason for escalation"),
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.OPERATOR)),
) -> Incident:
    """Manually elevates the escalation tier."""
    try:
        return await escalation_manager.manual_escalate(
            incident_id=incident_id,
            reason=reason,
            escalated_by=current_user.email,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post(
    "/incidents/{incident_id}/approve",
    response_model=Incident,
    summary="Approve incident gate with WebAuthn hardware key",
    description="Submits a hardware WebAuthn signature assertion to satisfy an approval gate (such as breaker de-escalation).",
)
def approve_incident_gate(
    incident_id: str,
    payload: ApproveIncidentStepRequest,
    step_action: str | None = Query(default=None, description="Action name of the approval gate"),
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.APPROVER)),
) -> Incident:
    """Verifies WebAuthn assertion and authorizes approval gate."""
    incident = incident_store.get(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    target_action = payload.action or step_action
    if not target_action:
        # Default to first pending approval gate
        pending_approvals = [a for a in incident.approvals if a.status == "PENDING"]
        if not pending_approvals:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No pending approval gates found in this incident",
            )
        target_action = pending_approvals[0].action

    try:
        return runbook_executor.approve_step(
            incident_id=incident_id,
            step_action=target_action,
            approver_user=current_user,
            assertion=payload.assertion,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/incidents/check-escalations",
    response_model=list[Incident],
    summary="Trigger on-call escalation check for active incidents",
    description="Evaluates all active incidents and escalates any whose acknowledgment deadline has passed.",
)
async def check_escalations(
    ack_timeout_seconds: int | None = Query(default=None, description="Optional override timeout seconds"),
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.OPERATOR)),
) -> list[Incident]:
    """Runs on-call deadline escalation checks."""
    return await escalation_manager.check_and_escalate_incidents(
        ack_timeout_seconds=ack_timeout_seconds
    )


@router.get(
    "/runbooks",
    response_model=list[Runbook],
    summary="List available declarative runbooks",
    description="Returns all loaded runbook specifications loaded from policy/runbooks/*.yaml.",
)
def list_runbooks(
    current_user: UserResponse = Depends(get_current_user),
) -> list[Runbook]:
    """Retrieves all registered runbook definitions."""
    unique_runbooks: dict[str, Runbook] = {}
    for rb in runbook_executor.runbooks.values():
        unique_runbooks[rb.id] = rb
    return list(unique_runbooks.values())


@router.get(
    "/runbooks/{runbook_id}",
    response_model=Runbook,
    summary="Get runbook specification by ID",
    description="Returns an individual runbook specification and step sequence.",
)
def get_runbook(
    runbook_id: str,
    current_user: UserResponse = Depends(get_current_user),
) -> Runbook:
    """Retrieves runbook manifest by ID."""
    rb = runbook_executor.runbooks.get(runbook_id) or runbook_executor.runbooks.get(runbook_id.upper())
    if not rb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Runbook '{runbook_id}' not found",
        )
    return rb
