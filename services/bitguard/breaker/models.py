"""Pydantic data models for circuit breaker operations (Milestone S18 / F9, F14)."""

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from services.bitguard.approvals.models import WebAuthnAssertion
from services.bitguard.models import BreakerStateEnum, DataLabel

BREAKER_STATE_RANKS: dict[BreakerStateEnum, int] = {
    BreakerStateEnum.NORMAL: 0,
    BreakerStateEnum.ELEVATED: 1,
    BreakerStateEnum.HOLD: 2,
    BreakerStateEnum.LOCKDOWN: 3,
}


class BreakerStatusResponse(BaseModel):
    """Detailed operational status of the circuit breaker."""

    model_config = ConfigDict(populate_by_name=True)

    state: BreakerStateEnum
    reason: str | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_by: str = "system"
    token_epoch: int = 1
    active_deescalation_request_id: str | None = None
    data_label: DataLabel = DataLabel.REAL


class EscalateRequest(BaseModel):
    """Payload to escalate the circuit breaker state instantly."""

    target_state: BreakerStateEnum = Field(
        description="Target elevated breaker state (strictly higher than current state)"
    )
    reason: str = Field(
        min_length=3,
        description="Operational justification for escalating circuit breaker",
    )


class DeescalateRequestCreate(BaseModel):
    """Payload to initiate a state lowering proposal requiring 2-approver quorum."""

    target_state: BreakerStateEnum = Field(
        description="Target lower breaker state (strictly lower than current state)"
    )
    reason: str = Field(
        min_length=5,
        description="Investigation summary and justification for de-escalating breaker",
    )


class DeescalateApproveRequest(BaseModel):
    """Payload for submitting a WebAuthn approval over the de-escalation challenge."""

    request_id: str = Field(description="Unique identifier of de-escalation request")
    assertion: WebAuthnAssertion = Field(
        description="Cryptographic WebAuthn assertion signed by authorized approver hardware key"
    )


class DeescalationApprovalModel(BaseModel):
    """Recorded approver signature assertion."""

    approver_id: str
    timestamp: float
    signature: str


class DeescalationRequestModel(BaseModel):
    """Complete de-escalation proposal record with challenge and recorded approvals."""

    id: str
    current_state: BreakerStateEnum
    target_state: BreakerStateEnum
    reason: str
    requested_by: str
    challenge: str
    status: str
    approvals: list[DeescalationApprovalModel] = Field(default_factory=list)
    created_at: datetime
    resolved_at: datetime | None = None
    required_approvals: int = 2
    data_label: DataLabel = DataLabel.REAL


class DeescalateApprovalResult(BaseModel):
    """Response returned upon submitting a de-escalation approval."""

    request_id: str
    status: str
    approvals_count: int
    required_approvals: int = 2
    message: str
    new_breaker_state: BreakerStateEnum | None = None
    data_label: DataLabel = DataLabel.REAL
