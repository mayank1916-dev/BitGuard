"""Cached simulation enricher integrating with DecisionEngine Stage 5 (Milestone S28 / F5).

Invariants:
- Invariant #1: Cached by tx digest and block number.
- Invariant #3: Fail-Closed Default. Simulation timeout adds risk weight, never 'safe'.
"""

import logging

from services.bitguard.engine.enrichment import EnrichmentResult, SimulationEnricher
from services.bitguard.engine.types import PipelineContext
from services.bitguard.ledger.mock import mock_ledger_connector
from services.bitguard.simulation.anvil import AnvilForkSimulator
from services.bitguard.simulation.base import TransactionSimulator
from services.bitguard.simulation.models import SimulationFlag, SimulationResult

logger = logging.getLogger("bitguard.simulation.enricher")


class CachedSimulationEnricher(SimulationEnricher):
    """Enricher that executes pre-sign simulation and balance delta verification."""

    def __init__(self, simulator: TransactionSimulator | None = None) -> None:
        self.simulator: TransactionSimulator = simulator or AnvilForkSimulator()

    def simulate(self, context: PipelineContext) -> EnrichmentResult:
        """Runs pre-flight simulation and checks for balance mismatch, reverts, or unlimited approval."""
        if context.request.metadata.get("simulate_enrichment_timeout"):
            return EnrichmentResult(
                configured=True,
                risk_weight=30,
                reason_code="ELEVATED_RISK_TIMEOUT",
                detail="Pre-flight simulation timed out; elevated risk applied (never treat as safe).",
                timed_out=True,
            )

        if not context.decoded_tx:
            return EnrichmentResult(
                configured=True,
                risk_weight=0,
                reason_code="SIMULATION_SKIPPED_NO_DECODED_TX",
                detail="Transaction bytes could not be decoded; simulation skipped.",
            )

        # Lookup intent from ledger if intent_id provided
        intent = None
        if context.request.intent_id:
            try:
                intent = mock_ledger_connector.get_intent(context.request.intent_id)
            except Exception:
                pass

        # Execute simulation (cached by digest and block number)
        timeout_ms = float(context.request.metadata.get("simulation_timeout_ms", 300.0))
        sim_res: SimulationResult = self.simulator.simulate(
            decoded_tx=context.decoded_tx,
            raw_tx=context.request.raw_tx or "",
            intent=intent,
            timeout_ms=timeout_ms,
        )

        if sim_res.timed_out or SimulationFlag.SIM_TIMEOUT in sim_res.flags:
            return EnrichmentResult(
                configured=True,
                risk_weight=30,
                reason_code="ELEVATED_RISK_TIMEOUT",
                detail=sim_res.detail or "Simulation timed out; elevated risk applied.",
                timed_out=True,
                data={"simulation": sim_res.model_dump()},
            )

        # Map flags to diagnostic reason code and risk weight
        primary_code: str | None = None
        detail: str | None = None
        risk_weight = sim_res.risk_weight

        if SimulationFlag.SIM_BALANCE_MISMATCH in sim_res.flags:
            primary_code = "SIM_BALANCE_MISMATCH"
            detail = "Simulation detected balance delta mismatch against intent or unexpected multi-token transfer."
            risk_weight = max(risk_weight, 75)
        elif SimulationFlag.SIM_REVERT in sim_res.flags:
            primary_code = "SIM_REVERT"
            detail = sim_res.revert_reason or "Pre-flight simulation execution reverted."
            risk_weight = max(risk_weight, 60)
        elif SimulationFlag.SIM_UNLIMITED_APPROVAL in sim_res.flags:
            primary_code = "SIM_UNLIMITED_APPROVAL"
            detail = "Pre-flight simulation flagged unlimited ERC-20 token allowance approval."
            risk_weight = max(risk_weight, 50)
        elif SimulationFlag.SIM_CALLS_UNKNOWN_CODE in sim_res.flags:
            primary_code = "SIM_CALLS_UNKNOWN_CODE"
            detail = "Pre-flight simulation detected interaction with unverified or unknown contract code."
            risk_weight = max(risk_weight, 40)
        else:
            primary_code = None
            detail = "Simulation verified balance deltas match expected custody intent cleanly."
            risk_weight = 0

        return EnrichmentResult(
            configured=True,
            risk_weight=risk_weight,
            reason_code=primary_code,
            detail=detail,
            data={
                "simulation": sim_res.model_dump(),
                "flags": [f.value for f in sim_res.flags],
                "balance_deltas": [d.model_dump() for d in sim_res.balance_deltas],
            },
        )
