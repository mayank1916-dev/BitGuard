"""Adapter skeleton for external real-world pricing oracle services (Milestone S31 / F13).

Invariants:
- Invariant #3: Fail-Closed Default (outages or network failures return None -> UNPRICED, never zero).
- Invariant #9: Environment & Safety Boundary (external connections strictly controlled via env vars).
"""

import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from services.bitguard.config import settings
from services.bitguard.pricing.base import PriceQuote, PriceSource

logger = logging.getLogger("bitguard.pricing.adapter")


class RealPriceSourceAdapter(PriceSource):
    """Adapter skeleton for a production price feed (e.g. Pyth, CoinGecko, Chainlink HTTP gateway)."""

    def __init__(
        self,
        api_url: str | None = None,
        api_key: str | None = None,
        provider_name: str | None = None,
        timeout: float = 3.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.api_url = (api_url or settings.price_api_url).rstrip("/")
        self.api_key = api_key or settings.price_api_key
        self.provider_name = provider_name or settings.price_provider_name or "external_oracle"
        self.timeout = timeout
        self.transport = transport

    @property
    def is_configured(self) -> bool:
        """Returns True if the external pricing oracle URL and configuration are populated."""
        return bool(self.api_url)

    def get_price(self, asset: str, now: datetime | None = None) -> PriceQuote | None:
        """Fetches live price quote from the configured external provider or returns None."""
        if not self.is_configured:
            logger.debug(
                "real_price_adapter_not_configured: provider=%s asset=%s",
                self.provider_name,
                asset,
            )
            return None

        normalized_asset = asset.upper()
        current_time = now or datetime.now(UTC)

        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "BitGuard-PriceAdapter/1.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            headers["X-API-Key"] = self.api_key

        try:
            with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
                url = f"{self.api_url}/v1/prices/{normalized_asset}"
                resp = client.get(url, headers=headers)
                if resp.status_code != 200:
                    logger.warning(
                        "real_price_adapter_http_error: status=%d url=%s asset=%s",
                        resp.status_code,
                        url,
                        asset,
                    )
                    return None

                data: dict[str, Any] = resp.json()
                price_val = float(data.get("price_usd") or data.get("price") or 0.0)
                if price_val <= 0:
                    return None

                ts_str = data.get("timestamp")
                quote_ts = (
                    datetime.fromisoformat(ts_str) if ts_str else current_time
                )
                if quote_ts.tzinfo is None:
                    quote_ts = quote_ts.replace(tzinfo=UTC)

                return PriceQuote(
                    asset=normalized_asset,
                    price_usd=price_val,
                    timestamp=quote_ts,
                    source=self.provider_name,
                )
        except Exception as exc:
            logger.warning(
                "real_price_adapter_exception: provider=%s asset=%s error=%s",
                self.provider_name,
                asset,
                exc,
            )
            return None
