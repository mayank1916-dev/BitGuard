"""API request and response models for Quorum WebAuthn Approvals (Milestone S16 / F10)."""

from typing import Any

from pydantic import BaseModel, Field

from services.bitguard.models import Approval, DataLabel, DecisionReason, DecodedTx


class WebAuthnAssertion(BaseModel):
    """Client WebAuthn hardware security key assertion payload."""

    credential_id: str = Field(description="Base64url or hex encoded credential identifier")
    client_data_json: str = Field(description="Base64url or UTF-8 encoded clientDataJSON string")
    authenticator_data: str = Field(description="Base64url or hex encoded authenticatorData bytes")
    signature: str = Field(description="Base64url, hex, or DER encoded digital signature")
    user_handle: str | None = Field(default=None, description="Optional user handle from authenticator")


class ApproveHoldRequest(BaseModel):
    """Payload to approve a quarantined transaction using WebAuthn."""

    assertion: WebAuthnAssertion = Field(description="Hardware WebAuthn cryptographic assertion")


class ApproveHoldResponse(BaseModel):
    """Result of processing an approval against a hold ticket."""

    status: str = Field(description="Status: PENDING_QUORUM or RELEASED")
    hold_id: str
    request_id: str
    approvals_count: int
    required_approvals: int = 2
    signature: str | None = Field(default=None, description="Signed transaction signature from shim if released")
    tx_hash: str | None = Field(default=None, description="Broadcast transaction hash if released")
    message: str
    data_label: DataLabel = DataLabel.REAL


class DenyHoldRequest(BaseModel):
    """Payload to deny a quarantined transaction immediately."""

    reason: str = Field(default="Rejected during manual security review", description="Reason for denial")


class DenyHoldResponse(BaseModel):
    """Result of denying a quarantined transaction."""

    status: str = "DENIED"
    hold_id: str
    reason: str
    data_label: DataLabel = DataLabel.REAL


class HoldViewResponse(BaseModel):
    """Console view of a quarantined hold ticket containing ground-truth decoded payload."""

    hold_id: str
    request_id: str
    status: str
    tx_digest: str
    raw_tx: str
    chain: str
    wallet: str | None
    amount_usd: float
    requester_id: str | None
    risk_score: int
    reasons: list[DecisionReason]
    decoded_tx: DecodedTx | None = None
    seconds_remaining: int
    is_expired: bool
    approvals: list[Approval] = Field(default_factory=list)
    signed_result: dict[str, Any] | None = None
    data_label: DataLabel = DataLabel.REAL
