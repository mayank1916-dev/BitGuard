from typing import Optional, Union
from fastapi import FastAPI
from pydantic import BaseModel

from backend.app.models import SigningRequest, Decision
from backend.app.core.policy import PolicyEngine


class ReplayBatchRequest(BaseModel):
    events: list[SigningRequest]


class ReplayBatchResponse(BaseModel):
    results: list[Decision]
    breaker_state: str
    total_evaluated: int
    allowed_count: int
    held_count: int
    denied_count: int


def create_app(engine: Optional[PolicyEngine] = None) -> FastAPI:
    app = FastAPI(
        title="BitGuard Firewall",
        description="Autonomous signing-request firewall and incident-replay lab for exchange hot wallets",
        version="0.1.0",
    )

    app.state.engine = engine or PolicyEngine()

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "service": "bitguard",
            "version": "0.1.0",
            "breaker_state": app.state.engine.breaker.state,
        }

    @app.post("/api/evaluate", response_model=Decision)
    def evaluate(request: SigningRequest) -> Decision:
        return app.state.engine.evaluate(request)

    @app.post("/api/replay", response_model=ReplayBatchResponse)
    def replay(
        payload: Union[ReplayBatchRequest, list[SigningRequest]]
    ) -> ReplayBatchResponse:
        events = payload.events if isinstance(payload, ReplayBatchRequest) else payload
        results = app.state.engine.replay(events)
        allowed = sum(1 for r in results if r.action == "allow")
        held = sum(1 for r in results if r.action == "hold")
        denied = sum(1 for r in results if r.action == "deny")
        return ReplayBatchResponse(
            results=results,
            breaker_state=app.state.engine.breaker.state,
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
