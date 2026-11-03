"""Canonical Pydantic models and schemas for BitGuard Firewall."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

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
    selector: str | None = None
    call_type: str = "NATIVE_TRANSFER"
    recipient: str | None = None
    amount: str | None = None
    sender: str | None = None
    is_unlimited_approval: bool = False
    flag: str | None = None


class AuthorizationItem(BaseModel):
    """EIP-7702 authorization tuple."""

    chain_id: int
    address: str
    nonce: int
    authority: str | None = None


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

    id: str = Field(default_factory=lambda: f"req-{uuid4().hex[:12]}")
    raw_tx: str = Field(description="Raw unsigned transaction hex bytes (source of truth)")
    chain: str = Field(default="ethereum", description="Target blockchain identifier")
    wallet: str = Field(default="", description="Originating wallet address (optional if extracted from raw tx)")
    wallet_group: str | None = Field(default=None, description="Assigned hot wallet group identifier")
    intent_id: str | None = Field(default=None, description="Correlated withdrawal intent ID")
    mode: OperationMode | None = Field(
        default=None,
        description="Optional mode override; defaults to the wallet group configured mode",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DecodedTx(BaseModel):
    """Canonical decoded transaction structure extracted strictly from raw bytes."""

    model_config = ConfigDict(populate_by_name=True)

    chain: str
    from_address: str = Field(validation_alias="from", serialization_alias="from")
    to_address: str | None = Field(default=None, validation_alias="to", serialization_alias="to")
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
    would_have_verdict: Verdict | None = Field(
        default=None,
        description="Hypothetical binding verdict if evaluated under ENFORCE mode (used in SHADOW mode)",
    )
    risk_score: int = Field(ge=0, le=100)
    reasons: list[DecisionReason] = Field(default_factory=list)
    mode: OperationMode
    policy_version: str
    data_label: DataLabel
    wallet_group: str = "default"
    is_false_positive: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    evaluation_latency_ms: float | None = None
    timings: dict[str, float] = Field(
        default_factory=dict,
        description="Stage execution latencies in milliseconds",
    )
    reservation_id: str | None = Field(default=None, description="Active limit reservation ID if reserved")
    decoded_tx: DecodedTx | None = Field(default=None, description="Decoded transaction payload if available")
    wallet: str | None = Field(default=None, description="Originating wallet address")
    chain: str | None = Field(default=None, description="Target blockchain identifier")


class Approval(BaseModel):
    """Hardware-bound approval signature record (WebAuthn)."""

    id: str
    hold_ticket_id: str
    approver_id: str
    approver_role: str = "Approver"
    tx_digest: str
    webauthn_signature: str
    assertion_data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class HoldTicket(BaseModel):
    """Durable quarantine record for transactions placed in HOLD."""

    id: str
    request_id: str
    tx_digest: str
    raw_tx: str | None = None
    chain: str = "ethereum"
    wallet: str | None = None
    amount_usd: float = 0.0
    requester_id: str | None = None
    reservation_id: str | None = None
    risk_score: int = 0
    reasons: list[DecisionReason] = Field(default_factory=list)
    status: str = "PENDING"  # PENDING, APPROVED, DENIED, EXPIRED
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    approvals: list[Approval] = Field(default_factory=list)
    signed_result: dict[str, Any] | None = None
    data_label: DataLabel = DataLabel.REAL


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
    """Cryptographically chained tamper-evident audit record (Milestone S21 / F18)."""

    seq: int = 0
    ts: float = 0.0
    actor: str = "system"
    action: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    entry_hash: str
    data_label: DataLabel = DataLabel.REAL

    # Backward-compatible fields
    index: int = 0
    timestamp: float = 0.0
    event_type: str = ""
    request_id: str = ""
    verdict: str = ""

    def __init__(self, **data: Any) -> None:
        if "seq" not in data and "index" in data:
            data["seq"] = data["index"]
        elif "index" not in data and "seq" in data:
            data["index"] = data["seq"]

        if "ts" not in data and "timestamp" in data:
            data["ts"] = data["timestamp"]
        elif "timestamp" not in data and "ts" in data:
            data["timestamp"] = data["ts"]

        if "action" not in data and "event_type" in data:
            data["action"] = data["event_type"]
        elif "event_type" not in data and "action" in data:
            data["event_type"] = data["action"]

        if "payload" not in data:
            payload = {}
            if "request_id" in data:
                payload["request_id"] = data["request_id"]
            if "verdict" in data:
                payload["verdict"] = data["verdict"]
            data["payload"] = payload
        else:
            if "request_id" not in data:
                data["request_id"] = str(data["payload"].get("request_id", ""))
            if "verdict" not in data:
                data["verdict"] = str(data["payload"].get("verdict", ""))

        super().__init__(**data)


class WatchedAddress(BaseModel):
    """Internal hot wallet address registered for code hash and delegation watching."""

    id: str
    address: str
    chain: str = "ethereum"
    label: str
    expected_code_hash: str | None = None
    allowed_delegates: list[str] = Field(default_factory=list)
    last_known_nonce: int = 0
    signed_count: int = 0
    last_scanned_block: int | None = None
    status: str = "ACTIVE"
    data_label: DataLabel = DataLabel.REAL
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CreateWatchedAddressRequest(BaseModel):
    """Payload to register a new hot wallet address for delegation monitoring."""

    address: str
    chain: str = "ethereum"
    label: str
    expected_code_hash: str | None = None
    allowed_delegates: list[str] = Field(default_factory=list)
    initial_nonce: int = 0


class UpdateWatchedAddressRequest(BaseModel):
    """Payload to update an existing watched address configuration."""

    label: str | None = None
    expected_code_hash: str | None = None
    allowed_delegates: list[str] | None = None
    status: str | None = None


class WatcherAlert(BaseModel):
    """Security alert emitted when the delegation watcher detects anomalies."""

    id: str
    alert_code: str
    severity: str  # "SUSPICIOUS", "HIGH", "CRITICAL"
    address: str
    chain: str
    block_number: int
    block_timestamp: float
    detection_timestamp: float = Field(default_factory=lambda: datetime.now(UTC).timestamp())
    latency_blocks: int = 0
    latency_seconds: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)
    breaker_tripped: bool = False
    data_label: DataLabel = DataLabel.REAL


class BreakerState(BaseModel):
    """Active circuit breaker status."""

    state: BreakerStateEnum
    reason: str | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    data_label: DataLabel = DataLabel.REAL
    updated_by: str = "system"
    token_epoch: int = 1
    active_deescalation_request_id: str | None = None


# --- Mode & Wallet Group Models (Milestone S04 / F7) ---


class WalletGroupConfig(BaseModel):
    """Policy configuration for an individual hot wallet group."""

    id: str = "default"
    name: str = "Default Hot Wallets"
    mode: OperationMode = OperationMode.SIMULATION
    wallets: list[str] = Field(default_factory=list)
    shadow_started_at: datetime | None = None
    enforce_started_at: datetime | None = None
    unexplained_decode_failures: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PolicyConfig(BaseModel):
    """Global BitGuard policy configuration containing mode and wallet group mappings."""

    version: str = "v1.0.0"
    mode: OperationMode = OperationMode.SIMULATION
    wallet_groups: dict[str, WalletGroupConfig] = Field(default_factory=dict)
    shadow_min_days: int = 14
    shadow_max_false_positive_rate: float = 0.001


class DailyGroupMetrics(BaseModel):
    """Counters per wallet group and per day (Milestone S04)."""

    wallet_group: str
    date: str  # YYYY-MM-DD
    would_have_blocked_count: int = 0
    would_have_blocked_value: float = 0.0
    allowed_count: int = 0
    would_have_allowed_value: float = 0.0
    false_positive_count: int = 0


class PromotionCheckItem(BaseModel):
    """Individual promotion gate check status."""

    name: str
    passed: bool
    details: dict[str, Any] = Field(default_factory=dict)


class PromotionChecklistResponse(BaseModel):
    """Checklist response evaluating whether a wallet group can promote to ENFORCE."""

    wallet_group: str
    current_mode: OperationMode
    can_promote: bool
    checks: dict[str, PromotionCheckItem]
    summary: str


class WalletGroupModeUpdate(BaseModel):
    """Request payload to promote or change a wallet group mode."""

    mode: OperationMode
    override: bool = False
    override_reason: str | None = None
    operator_id: str = "operator"


class FalsePositiveRequest(BaseModel):
    """Request payload to flag a blocked transaction as a false positive."""

    reason: str | None = None
    operator_id: str = "operator"


# --- RBAC Models (Milestone S05 / F9 basic) ---


class Role(StrEnum):
    """Development-grade RBAC Roles."""

    VIEWER = "Viewer"
    OPERATOR = "Operator"
    SECOPS = "SecOps"
    COMPLIANCE = "Compliance"
    APPROVER = "Approver"
    ADMIN = "Admin"


class Permission(StrEnum):
    """Fine-grained RBAC permissions mapped in the permission matrix."""

    # Read access
    READ_DECISIONS = "decisions:read"
    READ_METRICS = "metrics:read"
    READ_CHECKLIST = "checklist:read"
    READ_BREAKER = "breaker:read"
    READ_WALLET_GROUPS = "wallet_groups:read"
    READ_AUDIT = "audit:read"
    READ_REPORTS = "reports:read"
    READ_WATCHED_ADDRESSES = "watched_addresses:read"

    # Operational operations
    EVALUATE_TX = "tx:evaluate"
    SUBMIT_SIGN_REQUEST = "tx:sign"
    LABEL_FALSE_POSITIVE = "decisions:false_positive"
    POLICY_TIGHTEN = "policy:tighten"
    POLICY_LOOSEN = "policy:loosen"
    CONTROL_BREAKER = "breaker:control"
    APPROVE_HOLD = "hold:approve"
    MANAGE_USERS = "users:manage"
    PROMOTE_GROUP_OVERRIDE = "group:override"
    MANAGE_WATCHED_ADDRESSES = "watched_addresses:manage"


class UserResponse(BaseModel):
    """User profile and active role representation."""

    id: str
    email: str
    name: str
    role: Role
    permissions: list[Permission] = Field(default_factory=list)


class DevLoginRequest(BaseModel):
    """Development login payload to request signed JWT for seeded test users."""

    role: Role = Role.VIEWER
    user_id: str | None = None


class DevLoginResponse(BaseModel):
    """Signed short-lived JWT token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600
    user: UserResponse

