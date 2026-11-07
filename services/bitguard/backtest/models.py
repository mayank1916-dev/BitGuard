"""Pydantic models for Policy Backtesting and Replay Logs (Milestone S22 / F8)."""

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
    scenario: str = "normal"  # 'normal' | 'attack' | scenario_type
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


class BacktestImportRequest(BaseModel):
    """Request payload for POST /v1/backtests importing historical events."""

    draft_policy_id: str = Field(description="Policy version ID to backtest against")
    data: str | None = Field(default=None, description="Raw JSONL or CSV string payload")
    format: str = Field(default="jsonl", description="'jsonl' or 'csv'")
    scenarios: list[str] = Field(
        default_factory=list,
        description="List of scenario pattern IDs to inject (e.g. split_under_limit, rapid_velocity)",
    )
    baseline_policy_id: str | None = Field(
        default=None,
        description="Optional baseline policy ID to diff against (defaults to active policy)",
    )


class ScenarioPattern(BaseModel):
    """Data schema describing an attack/anomaly pattern for injection."""

    id: str
    name: str
    description: str
    pattern_type: str
    target_wallet: str
    chain: str = "ethereum"
    asset: str = "ETH"
    count: int = 5
    amount_usd_per_event: float = 10000.0
    interval_seconds: float = 5.0
    destinations: list[str] = Field(default_factory=list)
    delegate_address: str | None = None
    delegate_code_hash: str | None = None
    intent_id: str | None = None
    simulate_intent_mismatch: bool = False
    data_label: str = "SYNTHETIC"


class BacktestReport(BaseModel):
    """Comprehensive backtest report stored in backtest_reports table."""

    id: str = Field(description="Unique backtest report identifier (e.g. btr-...)")
    draft_policy_id: str = Field(description="ID of the draft policy under evaluation")
    draft_policy_hash: str = Field(description="Cryptographic content hash of the draft policy")
    baseline_policy_id: str | None = Field(default=None, description="Baseline policy ID diffed against")
    baseline_policy_hash: str | None = Field(default=None, description="Baseline policy hash")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    total_events: int
    real_events_count: int
    synthetic_events_count: int
    allowed_count: int
    held_count: int
    denied_count: int
    holds_per_day: float
    estimated_false_positives: int = Field(
        description="Count of REAL events that would be held or denied under the draft policy"
    )
    synthetic_loss_prevented_usd: float = Field(
        description="USD volume of synthetic attack loss contained by the policy"
    )
    synthetic_loss_allowed_usd: float = Field(
        description="USD volume of synthetic attack loss allowed through"
    )
    policy_diff: dict[str, Any] = Field(
        default_factory=dict,
        description="Diff against the active/baseline policy",
    )
    summary: dict[str, Any] = Field(default_factory=dict)
    steps: list[StepEvent] = Field(default_factory=list)
