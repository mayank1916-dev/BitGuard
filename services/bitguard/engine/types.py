"""Data structures and context types for the BitGuard Decision Engine (Milestone S10)."""

import time
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from services.bitguard.models import (
    DecisionReason,
    DecodedTx,
    OperationMode,
    SigningRequest,
    Verdict,
)


class DecisionEngineConfig(BaseModel):
    """Runtime configuration thresholds for decision engine policy evaluation."""

    model_config = ConfigDict(populate_by_name=True)

    hold_risk_threshold: int = Field(default=50, description="Risk score threshold triggering HOLD verdict")
    single_tx_usd_threshold: float = Field(default=50_000.0, description="USD single transfer limit triggering HOLD")
    enrichment_timeout_seconds: float = Field(default=1.0, description="Max timeout for asynchronous enrichment hooks")
    policy_version: str = Field(default="v1.0.0", description="Active policy version identifier")


@dataclass
class StageTimer:
    """Utility to measure execution latency per pipeline stage."""

    timings: dict[str, float] = field(default_factory=dict)
    _start_times: dict[str, float] = field(default_factory=dict)
    _pipeline_start: float = field(default_factory=time.perf_counter)

    def start_stage(self, stage_name: str) -> None:
        self._start_times[stage_name] = time.perf_counter()

    def end_stage(self, stage_name: str) -> float:
        start = self._start_times.get(stage_name)
        if start is not None:
            elapsed_ms = round((time.perf_counter() - start) * 1000.0, 3)
            self.timings[stage_name] = elapsed_ms
            return elapsed_ms
        return 0.0

    def finish_total(self) -> float:
        total_ms = round((time.perf_counter() - self._pipeline_start) * 1000.0, 3)
        self.timings["total"] = total_ms
        return total_ms


@dataclass
class PipelineContext:
    """State carried through the 6-stage decision pipeline."""

    request: SigningRequest
    is_dry_run: bool
    active_mode: OperationMode
    wallet_group: str
    timer: StageTimer = field(default_factory=StageTimer)
    decoded_tx: DecodedTx | None = None
    reservation_id: str | None = None
    reasons: list[DecisionReason] = field(default_factory=list)
    risk_score: int = 0
    hard_deny: bool = False
    is_alert: bool = False
    tentative_verdict: Verdict = Verdict.ALLOW
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_reason(self, code: str, weight: int, detail: str, is_hard_deny: bool = False) -> None:
        """Appends a decision reason and adjusts aggregate risk score."""
        self.reasons.append(DecisionReason(code=code, weight=weight, detail=detail))
        self.risk_score = min(100, self.risk_score + weight)
        if is_hard_deny or weight >= 90:
            self.hard_deny = True
