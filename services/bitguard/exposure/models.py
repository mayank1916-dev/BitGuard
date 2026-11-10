"""Data models for hot wallet balance tracking, exposure caps, and proposals (Milestone S29 / F11).

Invariants:
- Invariant #8: Explicit Data Provenance. Every value returned is explicitly labelled REAL, SYNTHETIC, or REPORTED.
- Invariant #11: Strict Wording & Claims: 'reduces and contains unauthorized signing'.
"""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from services.bitguard.models import DataLabel


class ExposureStatus(StrEnum):
    """Operational status of a hot wallet's on-chain exposure."""

    NORMAL = "NORMAL"
    TOP_UP_NEEDED = "TOP_UP_NEEDED"
    CAP_EXCEEDED = "CAP_EXCEEDED"
    DIVERGENCE_ALERT = "DIVERGENCE_ALERT"


class ProposalType(StrEnum):
    """Proposal types for rebalancing exposure between cold storage and hot wallets."""

    SWEEP = "SWEEP"
    TOP_UP = "TOP_UP"


class BalanceRecord(BaseModel):
    """On-chain balance snapshot recorded by the balance poller."""

    wallet: str = Field(description="Hot wallet address")
    chain: str = Field(default="ethereum", description="Target blockchain identifier")
    balance_wei: int = Field(description="On-chain balance in smallest integer units (wei)")
    balance_ether: float = Field(description="On-chain balance in ether/standard units")
    committed_limit_volume: int = Field(default=0, description="Cumulative committed limit volume in the sliding window")
    divergence_wei: int = Field(default=0, description="Divergence between expected and on-chain balance in wei")
    block_number: int | None = Field(default=None, description="Blockchain block height at time of poll")
    polled_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    data_label: DataLabel = Field(default=DataLabel.REAL, description="Explicit data provenance")


class ExposureAlert(BaseModel):
    """Divergence or cap breach alert emitted by the exposure service."""

    id: str = Field(description="Unique alert identifier")
    alert_code: str = Field(description="Alert classification code (BALANCE_DIVERGENCE, EXPOSURE_CAP_EXCEEDED, etc.)")
    severity: str = Field(default="HIGH", description="Alert severity: INFO, HIGH, CRITICAL")
    wallet: str = Field(description="Monitored hot wallet address")
    chain: str = Field(default="ethereum", description="Target blockchain identifier")
    on_chain_balance: float = Field(description="Observed on-chain balance")
    committed_volume: float = Field(default=0.0, description="Committed limit store volume")
    divergence: float = Field(default=0.0, description="Measured divergence amount")
    threshold: float | None = Field(default=None, description="Configured limit/cap threshold breached")
    detail: str = Field(description="Human-readable forensic detail")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    data_label: DataLabel = Field(default=DataLabel.REAL, description="Explicit data provenance")


class WalletExposureItem(BaseModel):
    """Per-wallet balance, cap, headroom, and exposure status (Milestone S29 / F11)."""

    wallet: str = Field(description="Monitored hot wallet address")
    chain: str = Field(default="ethereum", description="Target blockchain identifier")
    balance: float = Field(description="Current on-chain balance (labeled REAL or REPORTED)")
    cap: float = Field(description="Maximum hot wallet balance threshold (max_hot_balance)")
    target_balance: float = Field(description="Target equilibrium balance after rebalancing")
    top_up_threshold: float = Field(description="Low-balance threshold triggering cold-to-hot top-up")
    headroom: float = Field(description="Remaining balance capacity before the max cap is reached")
    exposure_at_risk: float = Field(description="Total funds currently at risk in this hot wallet")
    status: ExposureStatus = Field(default=ExposureStatus.NORMAL, description="Current operational exposure status")
    last_polled_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    data_label: DataLabel = Field(default=DataLabel.REAL, description="Explicit data provenance (REAL or REPORTED)")


class ExposureSummaryResponse(BaseModel):
    """Consolidated exposure report exposed by GET /v1/exposure."""

    total_exposure_at_risk: float = Field(description="Aggregate value of hot wallet balances exposed on-chain")
    total_headroom: float = Field(description="Aggregate headroom remaining before caps are breached")
    wallets_monitored: int = Field(description="Count of actively tracked hot wallets")
    proposals_pending: int = Field(default=0, description="Count of active quarantine sweep or top-up proposals")
    data_label: DataLabel = Field(default=DataLabel.REAL, description="Explicit data provenance (REAL or REPORTED)")
    wallets: list[WalletExposureItem] = Field(default_factory=list, description="Per-wallet exposure metrics")
    divergence_alerts: list[ExposureAlert] = Field(default_factory=list, description="Recent balance divergence alerts")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
