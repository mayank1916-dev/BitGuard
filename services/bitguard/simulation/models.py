"""Pre-sign transaction simulation models and flags (Milestone S28 / F5)."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SimulationFlag(StrEnum):
    """Diagnostic flags emitted by transaction pre-flight simulation."""

    SIM_BALANCE_MISMATCH = "SIM_BALANCE_MISMATCH"
    SIM_UNLIMITED_APPROVAL = "SIM_UNLIMITED_APPROVAL"
    SIM_CALLS_UNKNOWN_CODE = "SIM_CALLS_UNKNOWN_CODE"
    SIM_REVERT = "SIM_REVERT"
    SIM_TIMEOUT = "SIM_TIMEOUT"


class BalanceDelta(BaseModel):
    """Tracked balance change for a hot wallet or monitored address."""

    address: str
    asset: str = "ETH"  # "ETH" or token address/symbol
    token_address: str | None = None
    delta: int = 0  # Signed wei / base unit delta (negative = outflow, positive = inflow)
    before_balance: int = 0
    after_balance: int = 0
    formatted_amount: str | None = None


class SimulationResult(BaseModel):
    """Complete pre-sign simulation outcome for a raw transaction."""

    success: bool = True
    reverted: bool = False
    revert_reason: str | None = None
    flags: list[SimulationFlag] = Field(default_factory=list)
    balance_deltas: list[BalanceDelta] = Field(default_factory=list)
    risk_weight: int = Field(default=0, ge=0, le=100)
    timed_out: bool = False
    cached: bool = False
    chain: str = "ethereum"
    block_number: int = 0
    tx_digest: str = ""
    execution_time_ms: float = 0.0
    detail: str | None = None
    raw_logs: list[dict[str, Any]] = Field(default_factory=list)
