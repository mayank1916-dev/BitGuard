from typing import Optional, Union, Any
from fastapi import FastAPI
from pydantic import BaseModel, Field

from backend.app.models import SigningRequest, Decision
from backend.app.core.policy import PolicyEngine
from backend.app.core.replay import (
    ReplayRunner,
    ReplayReport,
    ReplayMetrics,
    StepEvent,
    create_engine_with_overrides,
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


def create_app(engine: Optional[PolicyEngine] = None) -> FastAPI:
    app = FastAPI(
        title="BitGuard Firewall & Replay Engine",
        description="Autonomous signing-request firewall and incident-replay lab for exchange hot wallets",
        version="0.2.0",
    )

    app.state.engine = engine or PolicyEngine()

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "service": "bitguard",
            "version": "0.2.0",
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

        # Update global app engine state with the replay's final breaker state if desired
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

    @app.post("/api/reset")
    def reset():
        app.state.engine.reset()
        return {
            "status": "reset",
            "breaker_state": app.state.engine.breaker.state,
        }

    return app


app = create_app()
