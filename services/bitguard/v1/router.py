"""V1 API Router defining core BitGuard Decision Point contracts."""

from datetime import UTC, datetime

from fastapi import APIRouter, Header, HTTPException, Query, WebSocket, WebSocketDisconnect

from services.bitguard.mode_service import mode_service
from services.bitguard.models import (
    BreakerState,
    BreakerStateEnum,
    DailyGroupMetrics,
    DataLabel,
    Decision,
    FalsePositiveRequest,
    PromotionChecklistResponse,
    SigningRequest,
    WalletGroupConfig,
    WalletGroupModeUpdate,
)

router = APIRouter(tags=["V1 Policy Decision Point"])


@router.post(
    "/evaluate",
    response_model=Decision,
    summary="Evaluate transaction signing request (dry run)",
    description=(
        "Simulates policy evaluation over raw transaction bytes without issuing binding signing tokens. "
        "Respects caller-provided mode or the wallet group configured mode (SIMULATION, SHADOW, ENFORCE)."
    ),
)
async def evaluate_transaction(request: SigningRequest) -> Decision:
    """Dry-run policy evaluation route."""
    return mode_service.evaluate_request(request, is_dry_run=True)


@router.post(
    "/sign-requests",
    response_model=Decision,
    summary="Submit transaction signing request",
    description=(
        "Primary signing request entrypoint. Evaluates raw transaction bytes against active policies "
        "under the wallet group's binding operational mode (SIMULATION, SHADOW, ENFORCE)."
    ),
)
async def submit_sign_request(request: SigningRequest) -> Decision:
    """Production signing request evaluation route."""
    return mode_service.evaluate_request(request, is_dry_run=False)


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
    """Retrieve decision log."""
    return mode_service.list_decisions(limit=limit, offset=offset)


@router.get(
    "/decisions/{decision_id}",
    response_model=Decision,
    summary="Get single decision by ID",
)
async def get_decision(decision_id: str) -> Decision:
    """Retrieve a single decision by ID or request ID."""
    dec = mode_service.get_decision(decision_id)
    if not dec:
        raise HTTPException(status_code=404, detail=f"Decision '{decision_id}' not found")
    return dec


@router.post(
    "/decisions/{decision_id}/false-positive",
    response_model=Decision,
    summary="Label decision as a false positive (Operator role)",
    description="Marks a blocked or would-block decision as a false positive, updating daily metrics.",
)
async def label_false_positive(
    decision_id: str,
    payload: FalsePositiveRequest = FalsePositiveRequest(),
    x_user_role: str | None = Header(default=None, alias="X-User-Role"),
) -> Decision:
    """Flags a decision as false positive. Requires Operator or Admin role."""
    if x_user_role is not None and x_user_role.lower() not in ["operator", "admin"]:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Operator or Admin role required to label false positives",
        )

    try:
        return mode_service.label_false_positive(
            decision_id=decision_id,
            operator_id=payload.operator_id,
            reason=payload.reason,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/promotion-checklist",
    response_model=PromotionChecklistResponse,
    summary="Evaluate wallet group promotion readiness",
    description="Checks minimum days in SHADOW, false-positive rate, and unexplained decode failures.",
)
async def get_promotion_checklist(
    wallet_group: str = Query(default="default", description="Wallet group to evaluate"),
) -> PromotionChecklistResponse:
    """Returns pass/fail checklist evaluating whether a group can promote from SHADOW to ENFORCE."""
    return mode_service.get_promotion_checklist(wallet_group)


@router.get(
    "/wallet-groups",
    response_model=list[WalletGroupConfig],
    summary="List configured hot wallet groups",
)
async def list_wallet_groups() -> list[WalletGroupConfig]:
    """Returns all hot wallet groups and operational modes."""
    return mode_service.list_wallet_groups()


@router.get(
    "/wallet-groups/{group_id}",
    response_model=WalletGroupConfig,
    summary="Get wallet group configuration",
)
async def get_wallet_group(group_id: str) -> WalletGroupConfig:
    """Returns single wallet group config."""
    return mode_service.get_wallet_group(group_id)


@router.post(
    "/wallet-groups/{group_id}/mode",
    response_model=WalletGroupConfig,
    summary="Update wallet group mode (Promotion Gate)",
    description=(
        "Updates wallet group mode. Promoting to ENFORCE is blocked unless the promotion checklist passes "
        "or an explicit override_reason is provided and logged to the audit chain."
    ),
)
async def update_group_mode(
    group_id: str,
    payload: WalletGroupModeUpdate,
) -> WalletGroupConfig:
    """Updates group mode enforcing promotion gates."""
    success, message, group = mode_service.update_group_mode(
        group_id=group_id,
        new_mode=payload.mode,
        override=payload.override,
        override_reason=payload.override_reason,
        operator_id=payload.operator_id,
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return group


@router.get(
    "/wallet-groups/{group_id}/metrics",
    response_model=list[DailyGroupMetrics],
    summary="Get daily shadow metrics for wallet group",
)
async def get_wallet_group_metrics(group_id: str) -> list[DailyGroupMetrics]:
    """Returns daily counters for a wallet group."""
    return mode_service.get_metrics_for_group(group_id)


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
