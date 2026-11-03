"""Canonical Pydantic models and schemas for BitGuard Firewall."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Verdict(StrEnum):
    """Firewall decision verdicts."""

    ALLOW = "ALLOW"
    HOLD = "HOLD"
    DENY = "DENY"


class DataLabel(StrEnum):
    """Explicit data provenance classifications (Invariant #8)."""

    REAL = "REAL"
    SYNTHETIC = "SYNTHETIC"
    REPORTED = "REPORTED"


class BreakerStateEnum(StrEnum):
    """Circuit breaker states."""

    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    HOLD = "HOLD"
    LOCKDOWN = "LOCKDOWN"


class OperationMode(StrEnum):
    """BitGuard operational mode."""

    SIMULATION = "SIMULATION"
    SHADOW = "SHADOW"
    ENFORCE = "ENFORCE"


class CallItem(BaseModel):
    """Sub-call in a batch or multicall transaction."""

    to: str
    value: str = "0"
    data: str | None = None


class AuthorizationItem(BaseModel):
    """EIP-7702 authorization tuple."""

    chain_id: int
    address: str
    nonce: int


class FeeDetail(BaseModel):
    """Transaction fee parameters."""

    gas_limit: int | None = None
    max_fee_per_gas: str | None = None
    max_priority_fee_per_gas: str | None = None


class DecisionReason(BaseModel):
    """Detailed justification code and metadata for policy decisions."""

    code: str
    weight: int = Field(ge=0, le=100)
    detail: str


class SigningRequest(BaseModel):
    """Incoming transaction signing request dispatched to BitGuard."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    raw_tx: str = Field(description="Raw unsigned transaction hex bytes (source of truth)")
    chain: str
    wallet: str
    intent_id: str | None = Field(default=None, description="Correlated withdrawal intent ID")
    mode: OperationMode = OperationMode.SIMULATION
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DecodedTx(BaseModel):
    """Canonical decoded transaction structure extracted strictly from raw bytes."""

    model_config = ConfigDict(populate_by_name=True)

    chain: str
    from_address: str = Field(alias="from")
    to_address: str | None = Field(default=None, alias="to")
    asset: str
    amount: str
    calls: list[CallItem] = Field(default_factory=list)
    authorizations: list[AuthorizationItem] = Field(default_factory=list)
    fee: FeeDetail = Field(default_factory=FeeDetail)
    digest: str = Field(description="Keccak256 hash or EIP-712 signing digest")


class Decision(BaseModel):
    """Deterministic evaluation outcome issued by BitGuard Decision Point."""

    request_id: str
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    reasons: list[DecisionReason] = Field(default_factory=list)
    mode: OperationMode
    policy_version: str
    data_label: DataLabel
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    evaluation_latency_ms: float | None = None


class HoldTicket(BaseModel):
    """Durable quarantine record for transactions placed in HOLD."""

    id: str
    request_id: str
    tx_digest: str
    reasons: list[DecisionReason] = Field(default_factory=list)
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED, EXPIRED
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Approval(BaseModel):
    """Hardware-bound approval signature record (WebAuthn)."""

    id: str
    hold_ticket_id: str
    approver_id: str
    tx_digest: str
    webauthn_signature: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PolicyVersion(BaseModel):
    """Cryptographically signed, versioned policy manifest."""

    id: str
    version: str
    author: str
    rules: dict[str, Any]
    signature: str | None = None
    is_active: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AuditEntry(BaseModel):
    """Cryptographically chained tamper-evident audit record."""

    index: int
    timestamp: float
    event_type: str
    request_id: str
    verdict: str
    prev_hash: str
    entry_hash: str
    data_label: DataLabel


class WatchedAddress(BaseModel):
    """Internal hot wallet address registered for code hash and delegation watching."""

    id: str
    address: str
    chain: str
    label: str
    expected_code_hash: str | None = None
    allowed_delegates: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class BreakerState(BaseModel):
    """Active circuit breaker status."""

    state: BreakerStateEnum
    reason: str | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    data_label: DataLabel = DataLabel.REAL
