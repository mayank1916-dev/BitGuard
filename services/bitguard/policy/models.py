"""Domain models and schemas for Versioned Policy Management (Milestone S20 / Section D).

Invariants:
- Invariant #6: Asymmetric Policy Evolution (tightening = instant/single operator; loosening = 2 WebAuthn approvers + cool-down + backtest report).
- Invariant #7: Immutable Audit Trail (every policy proposal, approval, activation, rollback is hash-chained).
- Invariant #8: Explicit Data Provenance (data_label REAL).
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from services.bitguard.approvals.models import WebAuthnAssertion
from services.bitguard.models import DataLabel, OperationMode, Role


class ChangeClassification(StrEnum):
    """Classification of changes between two policy versions."""

    TIGHTEN = "TIGHTEN"
    LOOSEN = "LOOSEN"
    MIXED = "MIXED"


class PolicyStatus(StrEnum):
    """Lifecycle state of a versioned policy manifest."""

    DRAFT = "DRAFT"
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    ROLLED_BACK = "ROLLED_BACK"


class WalletGroupPolicy(BaseModel):
    """Operational mode and address membership for a wallet group."""

    mode: OperationMode = OperationMode.SIMULATION
    wallets: list[str] = Field(default_factory=list)


class TimeLockPolicy(BaseModel):
    """Configuration for delayed high-value transfer time-locks (Milestone S30 / F12)."""

    timelock_threshold: dict[str, float] = Field(
        default_factory=lambda: {"ETH": 50.0, "BTC": 2.0, "USDC": 100_000.0, "USD": 100_000.0},
        description="Per-asset threshold at or above which transfers become TIMELOCKED",
    )
    timelock_minutes: int = Field(
        default=30,
        description="Base time-lock delay in minutes (default 30 min; lab 1 min)",
    )
    delay_multipliers: dict[str, float] = Field(
        default_factory=lambda: {"NORMAL": 1.0, "ELEVATED": 2.0, "HOLD": 4.0},
        description="Delay multiplier by circuit breaker state (ELEVATED x2, HOLD x4)",
    )
    min_amount_usd: float = 100_000.0
    delay_seconds: int = 1800
    cancellable_by_roles: list[Role] = Field(
        default_factory=lambda: [Role.OPERATOR, Role.SECOPS, Role.APPROVER, Role.ADMIN]
    )


class LimitsPolicy(BaseModel):
    """Multi-tiered financial spending limits across scopes."""

    global_daily_usd: float = 1_000_000.0
    global_single_tx_usd: float = 100_000.0
    global_velocity_limit_usd: float = 500_000.0
    wallet_daily_usd: dict[str, float] = Field(default_factory=dict)
    asset_daily_limits: dict[str, float] = Field(default_factory=dict)
    chain_daily_limits: dict[str, float] = Field(default_factory=dict)
    asset_unit_limits: dict[str, float] = Field(
        default_factory=dict,
        description="Native-unit caps per asset (e.g. {'ETH': 100.0, 'WBTC': 5.0}) enforced by limit store",
    )


class ThresholdsPolicy(BaseModel):
    """Dynamic risk and quarantine trigger thresholds."""

    single_tx_usd: float = 50_000.0
    velocity_spike_multiplier: float = 3.0
    hold_score: int = Field(default=50, ge=0, le=100)


class WalletExposurePolicy(BaseModel):
    """Exposure reduction balance limits per wallet (Milestone S29 / F11)."""

    max_hot_balance: float = Field(
        default=100_000.0,
        description="Upper threshold above which sweep to cold is triggered",
    )
    target_hot_balance: float = Field(
        default=50_000.0,
        description="Target equilibrium balance after sweep or top-up",
    )
    top_up_threshold: float = Field(
        default=20_000.0,
        description="Lower threshold below which top-up from cold is triggered",
    )


class PricingPolicy(BaseModel):
    """Configuration for pricing sanity, oracle deviation and unpriced token rules (Milestone S31 / F13)."""

    max_price_deviation_pct: float = Field(
        default=5.0,
        description="Max allowed price deviation % between sources before flagging PRICE_DEVIATION and using higher price",
    )
    max_price_age_seconds: int = Field(
        default=300,
        description="Max allowable price staleness in seconds",
    )
    unpriced_action: str = Field(
        default="HOLD",
        description="Action when token is unpriced, stale or missing: HOLD or DENY",
    )
    enabled: bool = True


class BaselinePolicy(BaseModel):
    """Configuration for per-wallet behavioral baselines and anomaly thresholds (Milestone S32 / F15)."""

    enabled: bool = True
    min_history_days: int = Field(
        default=7,
        description="Minimum days of transaction history required before evaluating baselines (cold-start window)",
    )
    low_history_weight: int = Field(
        default=0,
        description="Risk weight added when wallet has < min_history_days of history",
    )
    volume_multiplier_threshold: float = Field(
        default=3.0,
        description="Multiplier Nx over historical p50 hourly volume triggering BASELINE_VOLUME_HIGH",
    )
    volume_high_weight: int = Field(
        default=35,
        description="Risk weight for BASELINE_VOLUME_HIGH",
    )
    new_destination_burst_threshold: int = Field(
        default=5,
        description="Count of distinct new destinations in 24h triggering BASELINE_NEW_DESTINATION_BURST",
    )
    new_destination_burst_weight: int = Field(
        default=30,
        description="Risk weight for BASELINE_NEW_DESTINATION_BURST",
    )
    size_outlier_percentile: float = Field(
        default=99.0,
        description="Percentile threshold above which transaction size triggers BASELINE_SIZE_OUTLIER",
    )
    size_outlier_weight: int = Field(
        default=25,
        description="Risk weight for BASELINE_SIZE_OUTLIER",
    )
    off_hours: list[int] = Field(
        default_factory=lambda: [1, 2, 3, 4, 5],
        description="Hours of day (0-23 UTC) designated as off-hours",
    )
    off_hours_threshold_usd: float = Field(
        default=1000.0,
        description="Minimum USD transfer amount during off-hours triggering BASELINE_OFF_HOURS",
    )
    off_hours_weight: int = Field(
        default=20,
        description="Risk weight for BASELINE_OFF_HOURS",
    )


class CallerAttestationPolicy(BaseModel):
    """Configuration for caller identity, build attestation, and SPIFFE verification (Milestone S33 / F16)."""

    enabled: bool = True
    require_attestation: bool = False
    allowed_images_path: str = "policy/allowed_images.json"
    allowed_digests: list[str] = Field(default_factory=list)
    recent_deploy_window_seconds: int = Field(
        default=3600,
        description="Window in seconds during which a newly deployed caller is flagged as CALLER_RECENT_DEPLOY",
    )
    recent_deploy_weight: int = Field(
        default=25,
        description="Risk weight for CALLER_RECENT_DEPLOY",
    )
    unknown_digest_weight: int = Field(
        default=60,
        description="Risk weight for CALLER_UNKNOWN_DIGEST (guarantees HOLD)",
    )
    allowed_source_networks: list[str] = Field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128"],
        description="Allowed source CIDR networks for callers",
    )
    unusual_source_weight: int = Field(
        default=40,
        description="Risk weight for CALLER_UNUSUAL_SOURCE",
    )


class PolicyDocument(BaseModel):
    """Complete, self-contained declarative policy manifest document."""

    version: str = "v1.0.0"
    description: str = "BitGuard Core Defensive Signing Policy"
    limits: LimitsPolicy = Field(default_factory=LimitsPolicy)
    thresholds: ThresholdsPolicy = Field(default_factory=ThresholdsPolicy)
    wallet_groups: dict[str, WalletGroupPolicy] = Field(default_factory=dict)
    wallet_exposure: dict[str, WalletExposurePolicy] = Field(default_factory=dict)
    delegate_allowlist: list[str] = Field(default_factory=list)  # allowed bytecode hashes
    owned_addresses: list[str] = Field(default_factory=list)  # internal monitored hot addresses
    time_lock: TimeLockPolicy = Field(default_factory=TimeLockPolicy)
    pricing: PricingPolicy = Field(default_factory=PricingPolicy)
    baselines: BaselinePolicy = Field(default_factory=BaselinePolicy)
    attestation: CallerAttestationPolicy = Field(default_factory=CallerAttestationPolicy)
    risk_weights: dict[str, int] = Field(default_factory=dict)  # rule code -> risk weight (0-100)


class PolicyApproval(BaseModel):
    """Cryptographic approval by an authorized approver with WebAuthn."""

    id: str = Field(default_factory=lambda: f"pappr-{uuid4().hex[:12]}")
    approver_id: str
    approver_email: str
    approver_role: Role
    approved_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    webauthn_assertion: WebAuthnAssertion
    assertion_hash: str = ""


class PolicyVersion(BaseModel):
    """Cryptographically signed, versioned policy manifest record."""

    id: str = Field(default_factory=lambda: f"pv-{uuid4().hex[:12]}")
    version: str
    author: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: PolicyStatus = PolicyStatus.DRAFT
    content: PolicyDocument
    content_hash: str
    change_type: ChangeClassification = ChangeClassification.TIGHTEN
    ed25519_signature: str | None = None
    signatures: list[dict[str, Any]] = Field(default_factory=list)
    approvals: list[PolicyApproval] = Field(default_factory=list)
    backtest_report_id: str | None = None
    cool_down_until: datetime | None = None
    activated_at: datetime | None = None
    rolled_back_at: datetime | None = None
    rollback_reason: str | None = None
    data_label: DataLabel = DataLabel.REAL


class ProposePolicyRequest(BaseModel):
    """Payload to propose a new policy version."""

    version: str
    content: PolicyDocument
    backtest_report_id: str | None = None
    ed25519_signature: str | None = None


class ApprovePolicyRequest(BaseModel):
    """Payload to approve a policy version with WebAuthn hardware key."""

    assertion: WebAuthnAssertion


class ActivatePolicyRequest(BaseModel):
    """Payload to activate a policy version."""

    ed25519_signature: str | None = None


class RollbackPolicyRequest(BaseModel):
    """Payload to manually or automatically rollback an active policy version."""

    reason: str


class PolicyIntegrityResponse(BaseModel):
    """Result of active policy integrity verification against database and engine memory."""

    valid: bool
    active_version_id: str
    active_version_hash: str
    memory_version_hash: str
    db_version_hash: str
    ed25519_verified: bool
    details: str
    data_label: DataLabel = DataLabel.REAL


class ClassifyPolicyRequest(BaseModel):
    """Payload to classify a proposed draft policy against the active baseline."""

    draft: dict[str, Any] | PolicyDocument
    baseline_version_id: str | None = None


class PolicyRequirements(BaseModel):
    """Governance requirements required to activate a policy version."""

    approvers_required: int = 1
    cooldown_seconds: int = 0
    backtest_required: bool = False
    can_instant_activate: bool = True


class ClassifyPolicyResponse(BaseModel):
    """Outcome of policy change classification."""

    classification: ChangeClassification
    badge: str = Field(description="Clear classification badge: TIGHTENS, LOOSENS, or MIXED")
    diff: dict[str, Any] = Field(default_factory=dict, description="Structured diff of modified fields")
    text_diff: str = Field(default="", description="Unified text diff of active vs draft policy")
    requirements: PolicyRequirements
    active_version: str
    active_id: str
    draft_hash: str
    draft_doc: dict[str, Any] = Field(default_factory=dict)
    data_label: DataLabel = DataLabel.REAL


class DraftBacktestRequest(BaseModel):
    """Request payload to execute S22 backtesting on a draft policy."""

    draft_policy: dict[str, Any] | PolicyDocument | None = None
    draft_policy_id: str | None = None
    scenarios: list[str] = Field(default_factory=lambda: ["split_under_limit", "rapid_velocity"])

