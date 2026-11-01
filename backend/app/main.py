from typing import Optional, Union, Any
from fastapi import FastAPI, Query
from pydantic import BaseModel, Field

from backend.app.models import SigningRequest, Decision
from backend.app.core.policy import PolicyEngine
from backend.app.core.replay import (
    ReplayRunner,
    ReplayReport,
    ReplayMetrics,
    StepEvent,
    SensitivityPoint,
    run_sensitivity_matrix,
    create_engine_with_overrides,
)
from backend.app.core.radar import (
    RadarScanner,
    RadarScanResult,
    Type4Finding,
)


class ReplayBatchRequest(BaseModel):
    """
    Request payload for /api/replay.
    Supports supplying custom event batches and policy parameter overrides.
    If events is omitted, runs the default synthetic Binance attack timeline dataset.
    """
    events: Optional[list[SigningRequest]] = None
    policy_overrides: Optional[dict[str, Any]] = None


class EnhancedReplayResponse(BaseModel):
    """
    Replay response containing full step-by-step stream, aggregate summary metrics,
    and backwards-compatible summary counts.
    """
    summary: ReplayMetrics
    steps: list[StepEvent]
    # Backwards-compatible fields for Milestone 1 test suites
    results: list[Decision]
    breaker_state: str
    total_evaluated: int
    allowed_count: int
    held_count: int
    denied_count: int


class SensitivityRequest(BaseModel):
    base_limits: Optional[dict[str, Any]] = None
    multipliers: Optional[list[float]] = None


class SensitivityResponse(BaseModel):
    matrix: list[SensitivityPoint]
    base_limits: dict[str, Any]


def create_app(engine: Optional[PolicyEngine] = None) -> FastAPI:
    app = FastAPI(
        title="BitGuard Firewall, Replay & 7702 Radar",
        description="Autonomous signing-request firewall, incident-replay lab, and EIP-7702 live radar for exchange hot wallets",
        version="0.3.0",
    )

    app.state.engine = engine or PolicyEngine()
    app.state.radar_scanner = RadarScanner()

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "service": "bitguard",
            "version": "0.3.0",
            "breaker_state": app.state.engine.breaker.state,
        }

    @app.post("/api/evaluate", response_model=Decision)
    def evaluate(request: SigningRequest) -> Decision:
        return app.state.engine.evaluate(request)

    @app.post("/api/replay", response_model=EnhancedReplayResponse)
    def replay(
        payload: Optional[Union[ReplayBatchRequest, list[SigningRequest]]] = None,
    ) -> EnhancedReplayResponse:
        events: Optional[list[SigningRequest]] = None
        policy_overrides: Optional[dict[str, Any]] = None

        if isinstance(payload, list):
            events = payload
        elif isinstance(payload, ReplayBatchRequest):
            events = payload.events
            policy_overrides = payload.policy_overrides

        # Instantiate ReplayRunner
        runner = ReplayRunner(
            requests=events,
            policy_overrides=policy_overrides,
        )
        report: ReplayReport = runner.run()

        results = [s.protected_decision for s in report.steps]
        allowed = sum(1 for r in results if r.action == "allow")
        held = sum(1 for r in results if r.action == "hold")
        denied = sum(1 for r in results if r.action == "deny")

        return EnhancedReplayResponse(
            summary=report.summary,
            steps=report.steps,
            results=results,
            breaker_state=report.summary.breaker_final_state,
            total_evaluated=len(results),
            allowed_count=allowed,
            held_count=held,
            denied_count=denied,
        )

    @app.get("/api/radar", response_model=RadarScanResult)
    def get_radar(
        n_blocks: int = Query(default=5, ge=1, le=20),
        force_cached: bool = Query(default=False),
    ) -> RadarScanResult:
        """
        Polls recent Ethereum blocks for Type-4 (EIP-7702) transactions,
        scoring authorization pattern heuristics.
        Seamlessly falls back to cached offline dataset if RPC is unreachable.
        """
        scanner: RadarScanner = app.state.radar_scanner
        return scanner.scan_recent_blocks(n_blocks=n_blocks, force_cached=force_cached)

    @app.post("/api/policy/sensitivity", response_model=SensitivityResponse)
    def get_sensitivity(payload: Optional[SensitivityRequest] = None) -> SensitivityResponse:
        """
        Runs sensitivity analysis across limit multipliers, charting capital saved vs false positives.
        """
        base = (payload.base_limits if payload else None) or {
            "single_tx_usd": 50_000.0,
            "wallet_limit_usd": 100_000.0,
            "global_limit_usd": 500_000.0,
            "new_recipient_usd": 10_000.0,
        }
        multipliers = payload.multipliers if payload and payload.multipliers else [0.25, 0.5, 1.0, 1.5, 2.0]
        matrix = run_sensitivity_matrix(multipliers=multipliers, base_limits=base)
        return SensitivityResponse(matrix=matrix, base_limits=base)

    @app.post("/api/reset")
    def reset():
        app.state.engine.reset()
        return {
            "status": "reset",
            "breaker_state": app.state.engine.breaker.state,
        }

    return app


app = create_app()
