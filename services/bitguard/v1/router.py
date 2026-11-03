"""V1 API Router defining core BitGuard Decision Point contracts."""

from datetime import UTC, datetime

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from services.bitguard.models import (
    BreakerState,
    BreakerStateEnum,
    DataLabel,
    Decision,
    DecisionReason,
    SigningRequest,
    Verdict,
)

router = APIRouter(tags=["V1 Policy Decision Point"])


@router.post(
    "/evaluate",
    response_model=Decision,
    summary="Evaluate transaction signing request (dry run)",
    description=(
        "Simulates policy evaluation over raw transaction bytes without persisting state "
        "or issuing signing tokens. Fails closed by default if the engine is not implemented."
    ),
)
async def evaluate_transaction(request: SigningRequest) -> Decision:
    """Dry-run policy evaluation failing closed by default."""
    return Decision(
        request_id=request.id,
        verdict=Verdict.DENY,
        risk_score=100,
        reasons=[
            DecisionReason(
                code="ENGINE_NOT_IMPLEMENTED",
                weight=100,
                detail="Core policy evaluation engine not yet implemented; failing closed by default.",
            )
        ],
        mode=request.mode,
        policy_version="v0.1.0-genesis",
        data_label=DataLabel.SYNTHETIC,
        created_at=datetime.now(UTC),
        evaluation_latency_ms=0.5,
    )


@router.post(
    "/sign-requests",
    response_model=Decision,
    summary="Submit transaction signing request",
    description=(
        "Primary signing request entrypoint. Evaluates raw transaction bytes against "
        "active policy and generates a single-use approval token if permitted. "
        "Fails closed by default if the engine is not implemented."
    ),
)
async def submit_sign_request(request: SigningRequest) -> Decision:
    """Production signing request evaluation failing closed by default."""
    return Decision(
        request_id=request.id,
        verdict=Verdict.DENY,
        risk_score=100,
        reasons=[
            DecisionReason(
                code="ENGINE_NOT_IMPLEMENTED",
                weight=100,
                detail="Core policy evaluation engine not yet implemented; failing closed by default.",
            )
        ],
        mode=request.mode,
        policy_version="v0.1.0-genesis",
        data_label=DataLabel.SYNTHETIC,
        created_at=datetime.now(UTC),
        evaluation_latency_ms=0.5,
    )


@router.get(
    "/decisions",
    response_model=list[Decision],
    summary="Query policy decision history",
    description="Returns recorded policy decisions ordered by timestamp descending.",
)
async def list_decisions(
    limit: int = Query(default=50, ge=1, le=500, description="Max decisions to retrieve"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
) -> list[Decision]:
    """Retrieve decision log (empty stub before engine persistence)."""
    return []


@router.get(
    "/breaker",
    response_model=BreakerState,
    summary="Get circuit breaker operational state",
    description="Returns current circuit breaker operational state and data provenance label.",
)
async def get_breaker_state() -> BreakerState:
    """Retrieve active circuit breaker state."""
    return BreakerState(
        state=BreakerStateEnum.NORMAL,
        reason="All operational thresholds nominal",
        updated_at=datetime.now(UTC),
        data_label=DataLabel.REAL,
    )


@router.websocket("/stream")
async def websocket_event_stream(websocket: WebSocket) -> None:
    """Real-time event stream for decision notifications and breaker status changes."""
    await websocket.accept()
    try:
        await websocket.send_json(
            {
                "type": "connected",
                "service": "bitguard",
                "channel": "events",
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )
        while True:
            text = await websocket.receive_text()
            if text == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
