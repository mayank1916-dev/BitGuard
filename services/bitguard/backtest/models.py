"""Pydantic models for Policy Backtesting and Replay Logs (Milestone S22 / F8 preview)."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from services.bitguard.models import Decision


class BacktestMeta(BaseModel):
    """Metadata describing a historical or synthetic backtest dataset."""

    id: str
    name: str
    description: str
    events_count: int
    source: str = "incident_export"  # 'incident_export' | 'synthetic_generator' | 'lab_scenario'
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class StepEvent(BaseModel):
    """Single step event in the comparative replay pipeline."""

    request_id: str
    ts: float
    chain: str
    wallet: str
    kind: str
    asset: str = "ETH"
    amount_usd: float
    scenario: str = "normal"  # 'normal' | 'attack'
    unprotected_action: str = "allow"
    protected_decision: Decision
    cumulative_unprotected_loss_usd: float
    cumulative_protected_loss_usd: float
    data_label: str = "SYNTHETIC"  # 'SYNTHETIC' | 'REAL'


class BacktestRunResponse(BaseModel):
    """Result of streaming a backtest dataset through the real decision engine."""

    backtest_id: str
    total_events: int
    allowed_count: int
    held_count: int
    denied_count: int
    unprotected_loss_usd: float
    protected_loss_usd: float
    loss_prevented_usd: float
    steps: list[StepEvent]
    summary: dict[str, Any] = Field(default_factory=dict)
