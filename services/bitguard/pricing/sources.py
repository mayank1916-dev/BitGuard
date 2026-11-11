"""Deterministic mock price sources for testing and local operation (Milestone S31 / F13)."""

import threading
from datetime import UTC, datetime

from services.bitguard.pricing.base import PriceQuote, PriceSource


class MockPriceSourceA(PriceSource):
    """Deterministic Mock Price Source A."""

    def __init__(self, initial_prices: dict[str, float] | None = None) -> None:
        self._lock = threading.Lock()
        self._prices: dict[str, float] = initial_prices.copy() if initial_prices else {
            "ETH": 2500.0,
            "BTC": 60000.0,
            "USDC": 1.0,
            "USDT": 1.0,
        }
        self._timestamps: dict[str, datetime] = {}

    def set_price(
        self,
        asset: str,
        price_usd: float,
        timestamp: datetime | None = None,
    ) -> None:
        """Sets or updates price and optional observation timestamp for an asset."""
        with self._lock:
            key = asset.upper()
            self._prices[key] = price_usd
            if timestamp is not None:
                self._timestamps[key] = timestamp
            elif key in self._timestamps:
                del self._timestamps[key]

    def remove_price(self, asset: str) -> None:
        """Removes an asset to simulate unknown/missing token."""
        with self._lock:
            key = asset.upper()
            self._prices.pop(key, None)
            self._timestamps.pop(key, None)

    def reset(self) -> None:
        """Resets to baseline deterministic defaults."""
        with self._lock:
            self._prices = {
                "ETH": 2500.0,
                "BTC": 60000.0,
                "USDC": 1.0,
                "USDT": 1.0,
            }
            self._timestamps.clear()

    def get_price(self, asset: str, now: datetime | None = None) -> PriceQuote | None:
        """Returns price quote for asset, or None if unknown."""
        key = asset.upper()
        with self._lock:
            if key not in self._prices:
                return None
            price = self._prices[key]
            ts = self._timestamps.get(key) or (now or datetime.now(UTC))
            return PriceQuote(
                asset=key,
                price_usd=price,
                timestamp=ts,
                source="mock_source_a",
            )


class MockPriceSourceB(PriceSource):
    """Deterministic Mock Price Source B."""

    def __init__(self, initial_prices: dict[str, float] | None = None) -> None:
        self._lock = threading.Lock()
        self._prices: dict[str, float] = initial_prices.copy() if initial_prices else {
            "ETH": 2500.0,
            "BTC": 60000.0,
            "USDC": 1.0,
            "USDT": 1.0,
        }
        self._timestamps: dict[str, datetime] = {}

    def set_price(
        self,
        asset: str,
        price_usd: float,
        timestamp: datetime | None = None,
    ) -> None:
        """Sets or updates price and optional observation timestamp for an asset."""
        with self._lock:
            key = asset.upper()
            self._prices[key] = price_usd
            if timestamp is not None:
                self._timestamps[key] = timestamp
            elif key in self._timestamps:
                del self._timestamps[key]

    def remove_price(self, asset: str) -> None:
        """Removes an asset to simulate unknown/missing token."""
        with self._lock:
            key = asset.upper()
            self._prices.pop(key, None)
            self._timestamps.pop(key, None)

    def reset(self) -> None:
        """Resets to baseline deterministic defaults."""
        with self._lock:
            self._prices = {
                "ETH": 2500.0,
                "BTC": 60000.0,
                "USDC": 1.0,
                "USDT": 1.0,
            }
            self._timestamps.clear()

    def get_price(self, asset: str, now: datetime | None = None) -> PriceQuote | None:
        """Returns price quote for asset, or None if unknown."""
        key = asset.upper()
        with self._lock:
            if key not in self._prices:
                return None
            price = self._prices[key]
            ts = self._timestamps.get(key) or (now or datetime.now(UTC))
            return PriceQuote(
                asset=key,
                price_usd=price,
                timestamp=ts,
                source="mock_source_b",
            )
