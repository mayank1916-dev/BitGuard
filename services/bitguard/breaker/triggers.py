"""Automated circuit breaker triggers and anomaly detection (Milestone S18 / F9, F14).

Invariants:
- Invariant #3: Fail-Closed Default (anomalies tighten operational restrictions immediately).
- Invariant #6: Asymmetric Policy Evolution (tightening is instantaneous and automated).
"""

import logging
import threading
import time
from collections import deque
from typing import Any

from services.bitguard.breaker.models import BREAKER_STATE_RANKS, BreakerStateEnum
from services.bitguard.breaker.store import distributed_breaker_store
from services.bitguard.config import settings

logger = logging.getLogger("bitguard.breaker.triggers")


class BreakerTriggerManager:
    """Monitors operational telemetry and triggers automated circuit breaker state escalations."""

    def __init__(
        self,
        denials_threshold: int | None = None,
        unmatched_intents_threshold: int | None = None,
        velocity_spike_threshold_usd: float | None = None,
        window_seconds: float = 60.0,
        enabled: bool | None = None,
    ) -> None:
        self.enabled: bool = (
            enabled
            if enabled is not None
            else getattr(settings, "breaker_auto_triggers_enabled", False)
        )
        self.denials_threshold = (
            denials_threshold
            if denials_threshold is not None
            else getattr(settings, "breaker_denials_threshold", 5)
        )
        self.unmatched_intents_threshold = (
            unmatched_intents_threshold
            if unmatched_intents_threshold is not None
            else getattr(settings, "breaker_unmatched_intents_threshold", 3)
        )
        self.velocity_spike_threshold_usd = (
            velocity_spike_threshold_usd
            if velocity_spike_threshold_usd is not None
            else getattr(settings, "breaker_velocity_spike_threshold_usd", 1_000_000.0)
        )
        self.window_seconds = window_seconds

        self._lock = threading.Lock()
        self._denials: deque[float] = deque()
        self._unmatched_intents: deque[float] = deque()
        self._trigger_history: list[dict[str, Any]] = []

    def _purge_old_events(self, dq: deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

    def record_denial(self, decision_id: str, reason: str = "") -> None:
        """Records a policy denial event and checks against velocity threshold."""
        if not self.enabled:
            return
        with self._lock:
            now = time.time()
            self._denials.append(now)
            self._purge_old_events(self._denials, now)
            count = len(self._denials)

            if count >= self.denials_threshold:
                current_state = distributed_breaker_store.get_state()
                target_state = BreakerStateEnum.ELEVATED if current_state == BreakerStateEnum.NORMAL else BreakerStateEnum.HOLD
                if BREAKER_STATE_RANKS[target_state] > BREAKER_STATE_RANKS[current_state]:
                    logger.warning(
                        "breaker_trigger_repeated_denials: count=%d in %.1fs, escalating to %s",
                        count,
                        self.window_seconds,
                        target_state.value,
                    )
                    self._trigger_history.append({
                        "trigger": "REPEATED_DENIALS",
                        "count": count,
                        "timestamp": now,
                        "target_state": target_state.value,
                    })
                    distributed_breaker_store.escalate(
                        target_state=target_state,
                        reason=f"Automated trigger: {count} policy denials within {self.window_seconds}s window",
                        updated_by="trigger:repeated_denials",
                    )

    def record_unmatched_intent(self, intent_id: str | None, reason: str = "") -> None:
        """Records an unmatched intent event and checks against threshold."""
        if not self.enabled:
            return
        with self._lock:
            now = time.time()
            self._unmatched_intents.append(now)
            self._purge_old_events(self._unmatched_intents, now)
            count = len(self._unmatched_intents)

            if count >= self.unmatched_intents_threshold:
                current_state = distributed_breaker_store.get_state()
                if BREAKER_STATE_RANKS[BreakerStateEnum.HOLD] > BREAKER_STATE_RANKS[current_state]:
                    logger.warning(
                        "breaker_trigger_unmatched_intents: count=%d in %.1fs, escalating to HOLD",
                        count,
                        self.window_seconds,
                    )
                    self._trigger_history.append({
                        "trigger": "MULTIPLE_UNMATCHED_INTENTS",
                        "count": count,
                        "timestamp": now,
                        "target_state": "HOLD",
                    })
                    distributed_breaker_store.escalate(
                        target_state=BreakerStateEnum.HOLD,
                        reason=f"Automated trigger: {count} unmatched withdrawal intents within {self.window_seconds}s window",
                        updated_by="trigger:unmatched_intents",
                    )

    def record_velocity(self, amount_usd: float, wallet: str = "") -> None:
        """Evaluates single transaction volume against catastrophic velocity spike threshold."""
        if not self.enabled:
            return
        if amount_usd >= self.velocity_spike_threshold_usd:
            current_state = distributed_breaker_store.get_state()
            if BREAKER_STATE_RANKS[BreakerStateEnum.HOLD] > BREAKER_STATE_RANKS[current_state]:
                logger.warning(
                    "breaker_trigger_velocity_spike: amount_usd=%.2f exceeds threshold %.2f, escalating to HOLD",
                    amount_usd,
                    self.velocity_spike_threshold_usd,
                )
                self._trigger_history.append({
                    "trigger": "VELOCITY_SPIKE",
                    "amount_usd": amount_usd,
                    "timestamp": time.time(),
                    "target_state": "HOLD",
                })
                distributed_breaker_store.escalate(
                    target_state=BreakerStateEnum.HOLD,
                    reason=f"Automated trigger: Velocity spike USD {amount_usd:,.2f} exceeds threshold",
                    updated_by="trigger:velocity_spike",
                )

    def on_watcher_critical_alert(self, alert_type: str, details: str = "") -> None:
        """Escalates circuit breaker to HOLD on critical EIP-7702 or watcher detection."""
        if not self.enabled:
            return
        current_state = distributed_breaker_store.get_state()
        if BREAKER_STATE_RANKS[BreakerStateEnum.HOLD] > BREAKER_STATE_RANKS[current_state]:
            logger.critical("breaker_trigger_watcher_critical: alert=%s details=%s", alert_type, details)
            distributed_breaker_store.escalate(
                target_state=BreakerStateEnum.HOLD,
                reason=f"Automated trigger: Watcher CRITICAL alert '{alert_type}': {details}",
                updated_by="trigger:watcher_critical",
            )

    def reset(self) -> None:
        with self._lock:
            self._denials.clear()
            self._unmatched_intents.clear()
            self._trigger_history.clear()


# Global singleton instance
breaker_triggers = BreakerTriggerManager()
