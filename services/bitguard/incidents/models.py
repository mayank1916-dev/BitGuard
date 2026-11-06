"""Domain models and schemas for Incident Runbook Automation (Milestone S19 / F14)."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from services.bitguard.approvals.models import WebAuthnAssertion
from services.bitguard.models import DataLabel, Role


class StepType(StrEnum):
    """Execution type of an individual runbook step."""

    AUTOMATIC = "automatic"
    APPROVAL = "approval"
    MANUAL = "manual"


class StepOnFail(StrEnum):
    """Behavior when a step times out or returns failure."""

    ABORT = "abort"
    CONTINUE = "continue"
    ESCALATE = "escalate"


class IncidentStatus(StrEnum):
    """Operational status of an active or historical incident."""

    OPEN = "OPEN"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"


class RunbookStep(BaseModel):
    """Single step specification within a runbook."""

    id: str
    name: str
    type: StepType
    action: str
    params: dict[str, Any] = Field(default_factory=dict)
    timeout: int = 60
    on_fail: StepOnFail = StepOnFail.CONTINUE
    required_role: str | None = None


class Runbook(BaseModel):
    """Complete declarative runbook manifest loaded from policy/runbooks/*.yaml."""

    id: str
    name: str
    description: str
    trigger: str
    severity: str = "CRITICAL"
    target_time_to_contain_ms: float = 100.0
    steps: list[RunbookStep] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    """Immutable sequential timeline milestone of an incident."""

    id: str = Field(default_factory=lambda: f"tle-{uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ChecklistItem(BaseModel):
    """Actionable manual remediation task for response engineers."""

    id: str
    action: str
    description: str
    ticked: bool = False
    ticked_at: datetime | None = None
    ticked_by: str | None = None
    notes: str | None = None


class IncidentApproval(BaseModel):
    """Approval gate requiring WebAuthn hardware key authorization from an authorized role."""

    id: str = Field(default_factory=lambda: f"appr-{uuid4().hex[:12]}")
    action: str
    required_role: Role = Role.SECOPS
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED
    challenge: str = ""
    approved_by: str | None = None
    approved_at: datetime | None = None
    webauthn_assertion_ref: str | None = None


class Incident(BaseModel):
    """Comprehensive incident record tracking detection, containment, timeline, and remediation."""

    id: str = Field(default_factory=lambda: f"inc-{uuid4().hex[:12]}")
    trigger: str
    status: IncidentStatus = IncidentStatus.OPEN
    severity: str = "CRITICAL"
    runbook_id: str | None = None
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    contained_at: datetime | None = None
    time_to_contain_ms: float | None = None
    resolved_at: datetime | None = None
    timeline: list[TimelineEvent] = Field(default_factory=list)
    checklist: list[ChecklistItem] = Field(default_factory=list)
    approvals: list[IncidentApproval] = Field(default_factory=list)
    escalation_level: int = 1
    acknowledged: bool = False
    acknowledged_at: datetime | None = None
    acknowledged_by: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    data_label: DataLabel = DataLabel.REAL


class TickChecklistRequest(BaseModel):
    """Payload to mark a manual remediation checklist item as completed."""

    ticked_by: str | None = None
    notes: str | None = None


class AcknowledgeIncidentRequest(BaseModel):
    """Payload to acknowledge an on-call notification page."""

    acknowledged_by: str | None = None


class TriggerRunbookRequest(BaseModel):
    """Payload to initiate a runbook execution manually or via internal event."""

    trigger: str
    context: dict[str, Any] = Field(default_factory=dict)


class ApproveIncidentStepRequest(BaseModel):
    """Payload providing WebAuthn hardware assertion for an approval gate."""

    action: str | None = None
    assertion: WebAuthnAssertion
