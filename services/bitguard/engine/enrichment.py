"""Cached enrichment interfaces (address profiler, EVM simulation) (Milestone S10)."""

import logging
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from services.bitguard.engine.types import PipelineContext

logger = logging.getLogger("bitguard.engine.enrichment")


class EnrichmentResult(BaseModel):
    """Outcome of an external enrichment inspection hook."""

    configured: bool = Field(default=False, description="True if the enricher is configured and active")
    risk_weight: int = Field(default=0, ge=0, le=100, description="Risk increment to add if anomaly detected")
    reason_code: str | None = Field(default=None, description="Diagnostic reason code")
    detail: str | None = Field(default=None, description="Human-readable explanation")
    timed_out: bool = Field(default=False, description="True if hook timed out")
    data: dict[str, Any] = Field(default_factory=dict)


class ProfilerEnricher(ABC):
    """Interface for address profiling, reputation, and sanction list lookups."""

    @abstractmethod
    def enrich(self, context: PipelineContext) -> EnrichmentResult:
        """Inspects recipient and sender address profiles."""
        ...


class SimulationEnricher(ABC):
    """Interface for pre-flight state simulation and asset balance change verification."""

    @abstractmethod
    def simulate(self, context: PipelineContext) -> EnrichmentResult:
        """Executes transaction simulation and returns balance delta analysis."""
        ...


class DefaultProfilerEnricher(ProfilerEnricher):
    """Default stub returning 'not configured' reason."""

    def enrich(self, context: PipelineContext) -> EnrichmentResult:
        return EnrichmentResult(
            configured=False,
            risk_weight=0,
            reason_code="PROFILER_NOT_CONFIGURED",
            detail="Address profiler hook is not configured in this environment.",
        )


class DefaultSimulationEnricher(SimulationEnricher):
    """Default stub returning 'not configured' reason."""

    def simulate(self, context: PipelineContext) -> EnrichmentResult:
        return EnrichmentResult(
            configured=False,
            risk_weight=0,
            reason_code="SIMULATION_NOT_CONFIGURED",
            detail="Pre-flight simulation hook is not configured in this environment.",
        )


class MockTimeoutEnricher(SimulationEnricher):
    """Test helper simulating an enrichment timeout."""

    def simulate(self, context: PipelineContext) -> EnrichmentResult:
        return EnrichmentResult(
            configured=True,
            risk_weight=30,
            reason_code="ELEVATED_RISK_TIMEOUT",
            detail="Simulation service timed out after deadline; elevated risk applied.",
            timed_out=True,
        )
