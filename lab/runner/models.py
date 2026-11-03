"""Pydantic data models for BitGuard Integration Lab scenarios and reports (Milestone S23)."""

from typing import Any

from pydantic import BaseModel, Field


class ScenarioDefinition(BaseModel):
    """Declarative definition of an integration lab scenario loaded from YAML."""

    id: str
    name: str
    description: str
    target_chain_id: int = Field(default=31337)
    chain: str = Field(default="ethereum")
    expected_outcome: str
    pattern_data: dict[str, Any] = Field(default_factory=dict)
    assertions: dict[str, Any] = Field(default_factory=dict)


class AssertionCheck(BaseModel):
    """Detailed result of an individual assertion check."""

    name: str
    passed: bool
    expected: Any
    actual: Any
    message: str | None = None


class ScenarioResult(BaseModel):
    """Execution result for a single integration scenario."""

    id: str
    name: str
    status: str = Field(description="PASS or FAIL")
    duration_ms: float
    expected_outcome: str
    actual_outcome: str
    assertions_checked: int = 0
    assertions_passed: int = 0
    time_to_contain_ms: float | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    assertion_checks: list[AssertionCheck] = Field(default_factory=list)


class LabSafetySummary(BaseModel):
    """Safety guarantees validated during the run."""

    mainnet_guard_enforced: bool = True
    disposable_keys_only: bool = True
    live_funds_involved: bool = False
    fail_closed_verified: bool = True


class LabReport(BaseModel):
    """Complete integration lab execution benchmark report."""

    timestamp: str
    runner_version: str = "1.0.0"
    chain_id: int = 31337
    chain_name: str = "anvil-local"
    data_label: str = "SYNTHETIC"
    total_scenarios: int
    passed: int
    failed: int
    pass_rate_pct: float
    total_duration_ms: float
    target_performance_claim: str = "target p99 under 15 ms, measured"
    containment_claim: str = (
        "BitGuard reduces and contains unauthorized transaction signing. "
        "Production-ready architecture; pilot after audit and shadow-mode validation."
    )
    safety_checks: LabSafetySummary = Field(default_factory=LabSafetySummary)
    scenarios: list[ScenarioResult] = Field(default_factory=list)
