"""Metrics collection for withdrawal intent reconciliation (Milestone S08 / F2)."""

import threading

from pydantic import BaseModel, Field


class IntentMetricsResponse(BaseModel):
    """Dashboard-facing metrics for withdrawal intent reconciliation."""

    total_intent_checks: int = Field(default=0, description="Total transactions evaluated through intent check stage")
    unmatched_intent_checks: int = Field(default=0, description="Count of requests failing intent reconciliation")
    matched_intent_checks: int = Field(default=0, description="Count of requests matching approved intent")
    unmatched_request_rate: float = Field(default=0.0, description="Ratio of unmatched to total intent checks (0.0 to 1.0)")
    reasons_breakdown: dict[str, int] = Field(default_factory=dict, description="Counts broken down by failure code")


class IntentMetricsTracker:
    """Thread-safe tracker for intent reconciliation metrics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total_checks: int = 0
        self._unmatched_checks: int = 0
        self._matched_checks: int = 0
        self._reasons: dict[str, int] = {}

    def record_matched(self) -> None:
        """Records a successful intent reconciliation match."""
        with self._lock:
            self._total_checks += 1
            self._matched_checks += 1

    def record_unmatched(self, reason_code: str) -> None:
        """Records an unmatched intent reconciliation failure."""
        with self._lock:
            self._total_checks += 1
            self._unmatched_checks += 1
            self._reasons[reason_code] = self._reasons.get(reason_code, 0) + 1

    def get_metrics(self) -> IntentMetricsResponse:
        """Returns snapshot of intent reconciliation metrics."""
        with self._lock:
            total = self._total_checks
            unmatched = self._unmatched_checks
            rate = round(unmatched / total, 4) if total > 0 else 0.0
            return IntentMetricsResponse(
                total_intent_checks=total,
                unmatched_intent_checks=unmatched,
                matched_intent_checks=self._matched_checks,
                unmatched_request_rate=rate,
                reasons_breakdown=dict(self._reasons),
            )

    def reset(self) -> None:
        """Resets counters (test utility)."""
        with self._lock:
            self._total_checks = 0
            self._unmatched_checks = 0
            self._matched_checks = 0
            self._reasons.clear()


# Global singleton instance
intent_metrics = IntentMetricsTracker()
