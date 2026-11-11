"""In-memory and Redis-backed store for wallet behavioral baselines (Milestone S32 / F15).

Maintains rolling 28-day behavioral statistics per wallet:
- Hourly volume distributions by hour-of-day (p50, p95, p99).
- Distinct destinations per day.
- Transaction size percentiles (p50, p95, p99, max).
- Tracking of known destination address sets and 24h new destination bursts.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from services.bitguard.baselines.models import (
    DailyDestinationStats,
    HourlyVolumeStats,
    TransactionSizePercentiles,
    WalletBaselineProfile,
)
from services.bitguard.models import DataLabel, SigningRequest

logger = logging.getLogger("bitguard.baselines.store")

ROLLING_WINDOW_SECONDS = 28 * 86400.0  # 28 days


def compute_percentiles(values: list[float]) -> tuple[float, float, float, float]:
    """Computes (p50, p95, p99, max) using linear interpolation."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)

    def _pct(p: float) -> float:
        if n == 1:
            return sorted_vals[0]
        k = (n - 1) * (p / 100.0)
        f = int(k)
        c = min(f + 1, n - 1)
        d = k - f
        return sorted_vals[f] + d * (sorted_vals[c] - sorted_vals[f])

    return _pct(50.0), _pct(95.0), _pct(99.0), sorted_vals[-1]


class WalletBaselineData:
    """Internal mutable tracking state for a single wallet."""

    def __init__(self, wallet: str) -> None:
        self.wallet: str = wallet.lower()
        self.first_seen_ts: float = 0.0
        self.last_seen_ts: float = 0.0
        self.total_transactions: int = 0
        self.data_label: DataLabel = DataLabel.REAL

        # hour (0..23) -> dict[day_str, total_volume_for_that_hour_on_that_day]
        self.hourly_day_volumes: dict[int, dict[str, float]] = defaultdict(lambda: defaultdict(float))

        # List of (ts, amount_usd) over rolling 28 days
        self.recent_txs: list[tuple[float, float]] = []

        # day_str -> set of destination addresses
        self.destinations_by_day: dict[str, set[str]] = defaultdict(set)

        # Complete set of all known destination addresses
        self.known_destinations: set[str] = set()

        # Rolling 24h new destination records: list of (ts, dest)
        self.recent_new_destinations: list[tuple[float, str]] = []

        # Current rolling hour window volume: (current_hour_key, volume)
        self.current_hour_volume: dict[str, float] = defaultdict(float)


class BaselineStore:
    """Thread-safe store for wallet behavioral baselines with optional Redis backing."""

    def __init__(self, redis_client: Any = None) -> None:
        self._lock = threading.Lock()
        self._wallets: dict[str, WalletBaselineData] = {}
        self._redis_client = redis_client
        self._key_prefix = "baselines:profile:"

    def set_redis_client(self, client: Any) -> None:
        """Injects Redis client for test isolation or persistent caching."""
        with self._lock:
            self._redis_client = client

    def reset(self) -> None:
        """Clears all in-memory baseline profiles and Redis keys."""
        with self._lock:
            self._wallets.clear()
            if self._redis_client is not None:
                try:
                    keys = self._redis_client.keys(f"{self._key_prefix}*")
                    if keys:
                        self._redis_client.delete(*keys)
                except Exception as exc:
                    logger.warning("Failed to reset baselines in Redis: %s", exc)

    def _get_or_create(self, wallet: str) -> WalletBaselineData:
        key = wallet.lower()
        if key not in self._wallets:
            self._wallets[key] = WalletBaselineData(key)
        return self._wallets[key]

    def record_transaction(
        self,
        wallet: str,
        amount_usd: float,
        destination: str,
        timestamp: float | None = None,
        data_label: DataLabel = DataLabel.REAL,
    ) -> None:
        """Records an observed transaction into rolling statistics."""
        now_ts = timestamp if timestamp is not None else time.time()
        clean_dest = destination.lower()
        dt = datetime.fromtimestamp(now_ts, tz=UTC)
        day_str = dt.strftime("%Y-%m-%d")
        hour = dt.hour
        hour_key = dt.strftime("%Y-%m-%d-%H")

        with self._lock:
            data = self._get_or_create(wallet)
            if data.first_seen_ts == 0.0 or now_ts < data.first_seen_ts:
                data.first_seen_ts = now_ts
            if now_ts > data.last_seen_ts:
                data.last_seen_ts = now_ts

            data.total_transactions += 1
            data.data_label = data_label

            # 1. Hourly volume accumulation
            data.hourly_day_volumes[hour][day_str] += amount_usd
            data.current_hour_volume[hour_key] += amount_usd

            # 2. Transaction size collection
            data.recent_txs.append((now_ts, amount_usd))

            # 3. Destination tracking
            if clean_dest not in data.known_destinations:
                data.recent_new_destinations.append((now_ts, clean_dest))
                data.known_destinations.add(clean_dest)
            data.destinations_by_day[day_str].add(clean_dest)

            # 4. Prune records older than 28 days
            cutoff_ts = now_ts - ROLLING_WINDOW_SECONDS
            cutoff_day = datetime.fromtimestamp(cutoff_ts, tz=UTC).strftime("%Y-%m-%d")

            data.recent_txs = [item for item in data.recent_txs if item[0] >= cutoff_ts]

            # Prune 24h new destination records
            cutoff_24h = now_ts - 86400.0
            data.recent_new_destinations = [
                item for item in data.recent_new_destinations if item[0] >= cutoff_24h
            ]

            # Prune older days from day volumes and destination day maps
            for h in list(data.hourly_day_volumes.keys()):
                old_days = [d for d in data.hourly_day_volumes[h] if d < cutoff_day]
                for d in old_days:
                    del data.hourly_day_volumes[h][d]

            old_dest_days = [d for d in data.destinations_by_day if d < cutoff_day]
            for d in old_dest_days:
                del data.destinations_by_day[d]

    def get_profile(self, wallet: str) -> WalletBaselineProfile | None:
        """Computes and returns the comprehensive WalletBaselineProfile."""
        clean_wallet = wallet.lower()
        with self._lock:
            data = self._wallets.get(clean_wallet)
            if not data or data.total_transactions == 0:
                return None

            history_seconds = max(0.0, data.last_seen_ts - data.first_seen_ts)
            history_days = history_seconds / 86400.0

            # Hourly volume statistics
            hourly_volumes: dict[int, HourlyVolumeStats] = {}
            for h in range(24):
                daily_samples = list(data.hourly_day_volumes[h].values())
                p50, p95, p99, max_val = compute_percentiles(daily_samples)
                mean = sum(daily_samples) / len(daily_samples) if daily_samples else 0.0
                total = sum(daily_samples)
                hourly_volumes[h] = HourlyVolumeStats(
                    hour=h,
                    p50=round(p50, 2),
                    p95=round(p95, 2),
                    p99=round(p99, 2),
                    mean=round(mean, 2),
                    total_volume=round(total, 2),
                    sample_count=len(daily_samples),
                )

            # Destination statistics
            daily_counts = [float(len(dests)) for dests in data.destinations_by_day.values()]
            d_p50, d_p95, _, _ = compute_percentiles(daily_counts)
            dest_stats = DailyDestinationStats(
                p50_distinct_per_day=round(d_p50, 1),
                p95_distinct_per_day=round(d_p95, 1),
                total_unique_destinations=len(data.known_destinations),
            )

            # Transaction size percentiles
            sizes = [amt for _, amt in data.recent_txs]
            s_p50, s_p95, s_p99, s_max = compute_percentiles(sizes)
            size_stats = TransactionSizePercentiles(
                p50=round(s_p50, 2),
                p95=round(s_p95, 2),
                p99=round(s_p99, 2),
                max_observed=round(s_max, 2),
                count=len(sizes),
            )

            profile = WalletBaselineProfile(
                wallet=clean_wallet,
                first_seen_ts=data.first_seen_ts,
                last_seen_ts=data.last_seen_ts,
                history_days=round(history_days, 2),
                total_transactions=data.total_transactions,
                hourly_volumes=hourly_volumes,
                destination_stats=dest_stats,
                size_percentiles=size_stats,
                known_destinations=sorted(data.known_destinations),
                data_label=data.data_label,
            )

            # Persist to Redis if available
            if self._redis_client is not None:
                try:
                    self._redis_client.set(
                        f"{self._key_prefix}{clean_wallet}",
                        profile.model_dump_json(),
                        ex=86400,
                    )
                except Exception as exc:
                    logger.debug("Redis cache write ignored: %s", exc)

            return profile

    def get_hourly_rolling_volume(self, wallet: str, timestamp: float | None = None) -> float:
        """Returns accumulated volume for the wallet in the current hour window."""
        now_ts = timestamp if timestamp is not None else time.time()
        dt = datetime.fromtimestamp(now_ts, tz=UTC)
        hour_key = dt.strftime("%Y-%m-%d-%H")
        clean_wallet = wallet.lower()
        with self._lock:
            data = self._wallets.get(clean_wallet)
            if not data:
                return 0.0
            return data.current_hour_volume.get(hour_key, 0.0)

    def get_new_destinations_count_24h(self, wallet: str, timestamp: float | None = None) -> int:
        """Returns the number of distinct new destinations observed in the rolling 24-hour window."""
        now_ts = timestamp if timestamp is not None else time.time()
        cutoff_24h = now_ts - 86400.0
        clean_wallet = wallet.lower()
        with self._lock:
            data = self._wallets.get(clean_wallet)
            if not data:
                return 0
            recent_new = [dest for ts, dest in data.recent_new_destinations if ts >= cutoff_24h]
            return len(set(recent_new))

    def is_known_destination(self, wallet: str, destination: str) -> bool:
        """Checks if a destination has been previously observed for this wallet."""
        clean_wallet = wallet.lower()
        clean_dest = destination.lower()
        with self._lock:
            data = self._wallets.get(clean_wallet)
            if not data:
                return False
            return clean_dest in data.known_destinations

    def backfill_from_events(self, events: Sequence[dict[str, Any] | SigningRequest]) -> int:
        """Replays historical events in timestamp order to populate baseline profiles."""
        processed = 0
        parsed_events: list[tuple[float, str, float, str, DataLabel]] = []

        for ev in events:
            if isinstance(ev, SigningRequest):
                ts = float(ev.metadata.get("ts", time.time()))
                wallet = ev.wallet
                amt = float(ev.metadata.get("amount_usd", 0.0))
                dest = str(ev.metadata.get("destination") or ev.metadata.get("to") or "")
                label_val = ev.metadata.get("data_label", "REAL")
                data_label = DataLabel.REAL if label_val == "REAL" else DataLabel.SYNTHETIC
                parsed_events.append((ts, wallet, amt, dest, data_label))
            elif isinstance(ev, dict):
                ts = float(ev.get("ts") or ev.get("timestamp") or time.time())
                wallet = str(ev.get("wallet") or ev.get("from_address") or "")
                amt = float(ev.get("amount_usd") or ev.get("amount") or 0.0)
                dest = str(ev.get("destination") or ev.get("to") or ev.get("to_address") or "")
                label_val = ev.get("data_label", "REAL")
                data_label = DataLabel.REAL if label_val == "REAL" else DataLabel.SYNTHETIC
                parsed_events.append((ts, wallet, amt, dest, data_label))

        # Sort by timestamp ascending
        parsed_events.sort(key=lambda x: x[0])

        for ts, wallet, amt, dest, label in parsed_events:
            if wallet and amt > 0:
                self.record_transaction(
                    wallet=wallet,
                    amount_usd=amt,
                    destination=dest,
                    timestamp=ts,
                    data_label=label,
                )
                processed += 1

        return processed


# Global singleton baseline store
baseline_store = BaselineStore()
