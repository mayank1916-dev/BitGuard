"""Abstract base definitions and data models for token price sanity (Milestone S31 / F13).

Invariants:
- Invariant #3: Fail-Closed Default (unknown, missing, or stale prices are treated as UNPRICED; never zero).
- Invariant #4: Raw Byte Source of Truth (pricing converts raw transaction units to USD for limit checks).
- Invariant #8: Explicit Data Provenance.
"""

from abc import ABC, abstractmethod
from datetime import UTC, datetime

from pydantic import BaseModel, Field


class PriceQuote(BaseModel):
    """Normalized price quote from a pricing oracle or exchange source."""

    asset: str = Field(description="Normalized asset symbol (e.g. ETH, BTC, USDC)")
    price_usd: float = Field(description="USD unit price of the asset")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Observation timestamp of the price quote",
    )
    source: str = Field(description="Identifier of the emitting price source")


class PriceResolutionResult(BaseModel):
    """Aggregate result from multi-source price sanity evaluation."""

    asset: str
    price_usd: float | None = Field(
        default=None,
        description="Median or average baseline price from sources",
    )
    effective_price_usd: float | None = Field(
        default=None,
        description="Effective price used for limit enforcement (higher price if deviated; never zero)",
    )
    is_unpriced: bool = Field(
        default=False,
        description="True if asset cannot be safely priced (unknown, stale, missing)",
    )
    unpriced_reason: str | None = Field(
        default=None,
        description="Reason code: UNKNOWN_TOKEN, STALE_PRICE, MISSING_PRICE, INVALID_PRICE",
    )
    deviation_pct: float = Field(
        default=0.0,
        description="Calculated percentage deviation between sources",
    )
    is_deviated: bool = Field(
        default=False,
        description="True if price deviation between sources exceeds policy threshold",
    )
    source_a_price: float | None = None
    source_b_price: float | None = None
    used_higher_price: bool = Field(
        default=False,
        description="True if the higher price quote was chosen due to deviation",
    )


class PriceSource(ABC):
    """Abstract interface for external and mock token pricing sources."""

    @abstractmethod
    def get_price(self, asset: str, now: datetime | None = None) -> PriceQuote | None:
        """Returns the current USD price quote for the asset, or None if unavailable/unknown."""
        ...
