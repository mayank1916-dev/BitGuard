"""Data models and schemas for Behavioral Baselines (Milestone S32 / F15).

Invariants:
- Invariant #3: Fail-Closed Default. Unknown or malformed baseline configurations default to safe strict behavior.
- Invariant #4: Raw Byte Source of Truth. Base volumes and transaction values on decoded amounts.
- Invariant #8: Explicit Data Provenance. Baseline metrics carry explicit REAL or SYNTHETIC tags.
- Invariant #11: Strict Wording: 'reduces and contains', 'target p99 under 15 ms, measured'.
"""

from typing import Any

from pydantic import BaseModel, Field

from services.bitguard.models import DataLabel, DecisionReason


class HourlyVolumeStats(BaseModel):
    """Hourly volume distribution statistics over a rolling 28-day window for an hour-of-day (0-23 UTC)."""

    hour: int = Field(ge=0, le=23, description="Hour of the day in UTC (0-23)")
    p50: float = Field(default=0.0, description="Median hourly volume in USD over 28 days")
    p95: float = Field(default=0.0, description="95th percentile hourly volume in USD over 28 days")
    p99: float = Field(default=0.0, description="99th percentile hourly volume in USD over 28 days")
    mean: float = Field(default=0.0, description="Mean hourly volume in USD")
    total_volume: float = Field(default=0.0, description="Total historical volume recorded in this hour bucket")
    sample_count: int = Field(default=0, description="Number of hourly buckets recorded")


class DailyDestinationStats(BaseModel):
    """Daily distinct destination address statistics."""

    p50_distinct_per_day: float = Field(default=0.0, description="Median distinct destinations transacted per day")
    p95_distinct_per_day: float = Field(default=0.0, description="95th percentile distinct destinations per day")
    total_unique_destinations: int = Field(default=0, description="Total unique destination addresses ever transacted with")


class TransactionSizePercentiles(BaseModel):
    """Transaction size distribution percentiles in USD over the rolling window."""

    p50: float = Field(default=0.0, description="Median transaction size in USD")
    p95: float = Field(default=0.0, description="95th percentile transaction size in USD")
    p99: float = Field(default=0.0, description="99th percentile transaction size in USD")
    max_observed: float = Field(default=0.0, description="Maximum single transaction size observed")
    count: int = Field(default=0, description="Total transactions in the sample set")


class WalletBaselineProfile(BaseModel):
    """Rolling behavioral baseline profile for a monitored hot wallet."""

    wallet: str = Field(description="Wallet address (checksummed or lowercase hex)")
    first_seen_ts: float = Field(description="Earliest observed transaction timestamp in seconds")
    last_seen_ts: float = Field(description="Most recently observed transaction timestamp in seconds")
    history_days: float = Field(default=0.0, description="Number of days elapsed between first and latest activity")
    total_transactions: int = Field(default=0, description="Total transaction count observed across window")
    hourly_volumes: dict[int, HourlyVolumeStats] = Field(
        default_factory=dict,
        description="Statistics keyed by UTC hour (0-23)",
    )
    destination_stats: DailyDestinationStats = Field(
        default_factory=DailyDestinationStats,
        description="Destination distinctness statistics",
    )
    size_percentiles: TransactionSizePercentiles = Field(
        default_factory=TransactionSizePercentiles,
        description="Transaction size percentiles",
    )
    known_destinations: list[str] = Field(
        default_factory=list,
        description="List of known destination addresses observed historically",
    )
    data_label: DataLabel = Field(
        default=DataLabel.REAL,
        description="REAL or SYNTHETIC provenance tag (Invariant #8)",
    )


class BaselineEvaluationResult(BaseModel):
    """Outcome of evaluating a proposed transaction against wallet behavioral baselines."""

    wallet: str
    reasons: list[DecisionReason] = Field(default_factory=list)
    total_risk_weight: int = Field(default=0, ge=0, le=100)
    is_cold_start: bool = Field(default=False)
    details: dict[str, Any] = Field(default_factory=dict)
