"""Price sanity service coordinating multi-source oracle validation and deviation handling (Milestone S31 / F13).

Invariants:
- Invariant #3: Fail-Closed Default (unknown, stale, or missing prices are treated as UNPRICED; never zero).
- Invariant #4: Raw Byte Source of Truth (converts raw asset units to USD for limit checks).
- Invariant #8: Explicit Data Provenance.
"""

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from services.bitguard.policy.models import PricingPolicy
from services.bitguard.pricing.adapter import RealPriceSourceAdapter
from services.bitguard.pricing.base import (
    PriceResolutionResult,
    PriceSource,
)
from services.bitguard.pricing.sources import (
    MockPriceSourceA,
    MockPriceSourceB,
)

logger = logging.getLogger("bitguard.pricing.service")


class PriceService:
    """Coordinates price resolution across multiple deterministic sources and adapters."""

    def __init__(
        self,
        source_a: PriceSource | None = None,
        source_b: PriceSource | None = None,
        real_adapter: PriceSource | None = None,
    ) -> None:
        self.source_a = source_a or MockPriceSourceA()
        self.source_b = source_b or MockPriceSourceB()
        self.real_adapter = real_adapter or RealPriceSourceAdapter()

    def resolve_price(
        self,
        asset: str,
        now: datetime | None = None,
        policy: PricingPolicy | None = None,
    ) -> PriceResolutionResult:
        """Evaluates price sanity across two sources according to policy rules.

        Rules:
        - USD fiat or pegged stablecoins default to 1.0 USD if not explicitly quoted.
        - USD value uses the median of two sources only if they deviate less than policy.max_price_deviation_pct.
        - Otherwise flags PRICE_DEVIATION and uses the HIGHER value for limit checks.
        - Unknown token, stale price, or missing price => never zero. Treat as UNPRICED (HOLD or DENY).
        """
        current_now = now or datetime.now(UTC)
        normalized_asset = asset.upper().strip()
        if policy is not None:
            pricing_policy = policy
        else:
            from services.bitguard.policy.models import PricingPolicy

            pricing_policy = PricingPolicy()

        # Direct USD representation
        if normalized_asset == "USD":
            return PriceResolutionResult(
                asset="USD",
                price_usd=1.0,
                effective_price_usd=1.0,
                is_unpriced=False,
                deviation_pct=0.0,
                is_deviated=False,
                source_a_price=1.0,
                source_b_price=1.0,
                used_higher_price=False,
            )

        # Query Source A and Source B
        quote_a = self.source_a.get_price(normalized_asset, now=current_now)
        quote_b = self.source_b.get_price(normalized_asset, now=current_now)

        # Fallback to configured real adapter if one mock source is missing
        if (quote_a is None or quote_b is None) and isinstance(self.real_adapter, RealPriceSourceAdapter) and self.real_adapter.is_configured:
            real_quote = self.real_adapter.get_price(normalized_asset, now=current_now)
            if real_quote:
                if quote_a is None:
                    quote_a = real_quote
                elif quote_b is None:
                    quote_b = real_quote

        # 1. Missing or unknown token check (Never zero)
        if quote_a is None and quote_b is None:
            logger.info("unpriced_token_unknown: asset=%s", normalized_asset)
            return PriceResolutionResult(
                asset=normalized_asset,
                price_usd=None,
                effective_price_usd=None,
                is_unpriced=True,
                unpriced_reason="UNKNOWN_TOKEN",
            )

        if quote_a is None or quote_b is None:
            logger.info(
                "unpriced_token_missing_source: asset=%s has_a=%s has_b=%s",
                normalized_asset,
                quote_a is not None,
                quote_b is not None,
            )
            return PriceResolutionResult(
                asset=normalized_asset,
                price_usd=None,
                effective_price_usd=None,
                is_unpriced=True,
                unpriced_reason="MISSING_PRICE",
                source_a_price=quote_a.price_usd if quote_a else None,
                source_b_price=quote_b.price_usd if quote_b else None,
            )

        # 2. Non-positive or invalid price check
        if quote_a.price_usd <= 0 or quote_b.price_usd <= 0:
            logger.warning(
                "unpriced_token_non_positive: asset=%s price_a=%s price_b=%s",
                normalized_asset,
                quote_a.price_usd,
                quote_b.price_usd,
            )
            return PriceResolutionResult(
                asset=normalized_asset,
                price_usd=None,
                effective_price_usd=None,
                is_unpriced=True,
                unpriced_reason="INVALID_PRICE",
                source_a_price=quote_a.price_usd,
                source_b_price=quote_b.price_usd,
            )

        # 3. Staleness check: verify quote age does not exceed max_price_age_seconds
        max_age = pricing_policy.max_price_age_seconds
        age_a = (current_now - quote_a.timestamp).total_seconds()
        age_b = (current_now - quote_b.timestamp).total_seconds()

        if age_a > max_age or age_b > max_age:
            logger.info(
                "unpriced_token_stale_price: asset=%s age_a=%.1fs age_b=%.1fs max_age=%ds",
                normalized_asset,
                age_a,
                age_b,
                max_age,
            )
            return PriceResolutionResult(
                asset=normalized_asset,
                price_usd=None,
                effective_price_usd=None,
                is_unpriced=True,
                unpriced_reason="STALE_PRICE",
                source_a_price=quote_a.price_usd,
                source_b_price=quote_b.price_usd,
            )

        # 4. Multi-source price sanity and deviation check
        p_a = quote_a.price_usd
        p_b = quote_b.price_usd
        min_p = min(p_a, p_b)
        max_p = max(p_a, p_b)
        median_price = (p_a + p_b) / 2.0

        deviation_pct = round(((max_p - min_p) / min_p) * 100.0, 4) if min_p > 0 else 0.0
        max_dev = pricing_policy.max_price_deviation_pct

        if deviation_pct > max_dev:
            # Deviation exceeded: Add PRICE_DEVIATION weight and use HIGHER price for limit checks
            logger.warning(
                "price_deviation_exceeded: asset=%s p_a=%.2f p_b=%.2f dev=%.2f%% max_dev=%.2f%% -> using higher price %.2f",
                normalized_asset,
                p_a,
                p_b,
                deviation_pct,
                max_dev,
                max_p,
            )
            return PriceResolutionResult(
                asset=normalized_asset,
                price_usd=median_price,
                effective_price_usd=max_p,
                is_unpriced=False,
                deviation_pct=deviation_pct,
                is_deviated=True,
                source_a_price=p_a,
                source_b_price=p_b,
                used_higher_price=True,
            )

        # Within acceptable deviation: use median of two sources
        return PriceResolutionResult(
            asset=normalized_asset,
            price_usd=median_price,
            effective_price_usd=median_price,
            is_unpriced=False,
            deviation_pct=deviation_pct,
            is_deviated=False,
            source_a_price=p_a,
            source_b_price=p_b,
            used_higher_price=False,
        )

    def reset(self) -> None:
        """Resets mock price sources to baseline defaults."""
        if hasattr(self.source_a, "reset"):
            self.source_a.reset()
        if hasattr(self.source_b, "reset"):
            self.source_b.reset()


# Global singleton instance
price_service = PriceService()
