"""V1 API Router defining core BitGuard Decision Point contracts."""

import asyncio
from datetime import UTC, datetime
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from pydantic import BaseModel

from services.bitguard.approvals.router import router as approvals_router
from services.bitguard.audit import router as audit_router
from services.bitguard.auth.router import router as auth_router
from services.bitguard.auth.step_up import log_admin_action_audit
from services.bitguard.backtest import backtest_router
from services.bitguard.breaker import breaker_router
from services.bitguard.decision_store import decision_store
from services.bitguard.exposure import exposure_router
from services.bitguard.incidents import incidents_router
from services.bitguard.ledger.metrics import IntentMetricsResponse, intent_metrics
from services.bitguard.mode_service import mode_service
from services.bitguard.models import (
    DailyGroupMetrics,
    Decision,
    FalsePositiveRequest,
    Permission,
    PromotionChecklistResponse,
    Role,
    SigningRequest,
    UserResponse,
    Verdict,
    WalletGroupConfig,
    WalletGroupModeUpdate,
)
from services.bitguard.policy import policy_router
from services.bitguard.rbac import (
    PERMISSION_MATRIX,
    decode_access_token,
    require_permission,
    require_role,
)
from services.bitguard.reports import reports_router
from services.bitguard.stream.broadcaster import stream_broadcaster
from services.bitguard.timelock.store import TimelockItem, timelock_store
from services.bitguard.v1.break_glass_router import router as break_glass_router
from services.bitguard.watcher.router import router as watcher_router

router = APIRouter(tags=["V1 Policy Decision Point"])
router.include_router(approvals_router)
router.include_router(watcher_router)
router.include_router(breaker_router)
router.include_router(audit_router)
router.include_router(backtest_router)
router.include_router(auth_router)
router.include_router(incidents_router)
router.include_router(policy_router)
router.include_router(break_glass_router)
router.include_router(exposure_router)
router.include_router(reports_router)


# --- Core Policy Evaluation & Signing Endpoints ---


@router.post(
    "/evaluate",
    response_model=Decision,
    summary="Evaluate transaction signing request (dry run)",
    description=(
        "Simulates policy evaluation over raw transaction bytes without issuing binding signing tokens. "
        "Respects caller-provided mode or the wallet group configured mode (SIMULATION, SHADOW, ENFORCE)."
    ),
    dependencies=[Depends(require_permission(Permission.EVALUATE_TX))],
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
    dependencies=[Depends(require_permission(Permission.SUBMIT_SIGN_REQUEST))],
)
async def submit_sign_request(request: SigningRequest) -> Decision:
    """Production signing request evaluation route."""
    return mode_service.evaluate_request(request, is_dry_run=False)


@router.get(
    "/decisions",
    response_model=list[Decision],
    summary="Query policy decision history",
    description="Returns recorded policy decisions ordered by timestamp descending with filtering and cursor pagination.",
    dependencies=[Depends(require_permission(Permission.READ_DECISIONS))],
)
async def list_decisions(
    start_time: datetime | None = Query(default=None, description="Start timestamp filter (ISO 8601)"),
    end_time: datetime | None = Query(default=None, description="End timestamp filter (ISO 8601)"),
    verdict: Verdict | None = Query(default=None, description="Verdict filter (ALLOW, HOLD, DENY)"),
    wallet: str | None = Query(default=None, description="Wallet address filter"),
    chain: str | None = Query(default=None, description="Blockchain identifier filter"),
    cursor: str | None = Query(default=None, description="Cursor pointer for pagination"),
    limit: int = Query(default=50, ge=1, le=500, description="Max decisions to retrieve"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
) -> list[Decision]:
    """Retrieve decision log with multi-field filtering and cursor pagination."""
    decisions, _next_cursor = mode_service.list_decisions(
        start_time=start_time,
        end_time=end_time,
        verdict=verdict,
        wallet=wallet,
        chain=chain,
        cursor=cursor,
        limit=limit,
        offset=offset,
    )
    return decisions


@router.get(
    "/decisions/{decision_id}",
    response_model=Decision,
    summary="Get single decision by ID",
    dependencies=[Depends(require_permission(Permission.READ_DECISIONS))],
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
    dependencies=[Depends(require_permission(Permission.LABEL_FALSE_POSITIVE))],
)
async def label_false_positive(
    request: Request,
    decision_id: str,
    payload: FalsePositiveRequest = FalsePositiveRequest(),
    current_user: UserResponse = Depends(require_permission(Permission.LABEL_FALSE_POSITIVE)),
) -> Decision:
    """Flags a decision as false positive. Requires Operator or Admin role."""
    try:
        operator_name = payload.operator_id or current_user.email
        res = mode_service.label_false_positive(
            decision_id=decision_id,
            operator_id=operator_name,
            reason=payload.reason,
        )
        assertion_ref = getattr(request.state, "webauthn_assertion_ref", None)
        log_admin_action_audit(
            user=current_user,
            action="LABEL_FALSE_POSITIVE",
            assertion_ref=assertion_ref,
            details={"decision_id": decision_id, "reason": payload.reason},
        )
        return res
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/promotion-checklist",
    response_model=PromotionChecklistResponse,
    summary="Evaluate wallet group promotion readiness",
    description="Checks minimum days in SHADOW, false-positive rate, and unexplained decode failures.",
    dependencies=[Depends(require_permission(Permission.READ_CHECKLIST))],
)
async def get_promotion_checklist(
    wallet_group: str = Query(default="default", description="Wallet group to evaluate"),
) -> PromotionChecklistResponse:
    """Returns pass/fail checklist evaluating whether a group can promote from SHADOW to ENFORCE."""
    return mode_service.get_promotion_checklist(wallet_group)


@router.get(
    "/mode",
    response_model=dict[str, Any],
    summary="Get current operational mode",
    tags=["V1 Policy Decision Point"],
)
async def get_current_mode() -> dict[str, Any]:
    """Returns the primary operational mode (SIMULATION, SHADOW, or ENFORCE)."""
    default_group = mode_service.get_wallet_group("default")
    return {
        "mode": default_group.mode.value,
        "wallet_group": default_group.id,
    }


@router.get(
    "/metrics/shadow",
    response_model=dict[str, Any],
    summary="Get aggregated shadow mode metrics and would_have counters (Milestone S04 / U2)",
    tags=["V1 Policy Decision Point"],
)
async def get_shadow_metrics(wallet_group: str = "default") -> dict[str, Any]:
    """Returns aggregated would_have_* counters from S04."""
    return mode_service.get_shadow_counters(wallet_group)


@router.get(
    "/wallet-groups",
    response_model=list[WalletGroupConfig],
    summary="List configured hot wallet groups",
    dependencies=[Depends(require_permission(Permission.READ_WALLET_GROUPS))],
)
async def list_wallet_groups() -> list[WalletGroupConfig]:
    """Returns all hot wallet groups and operational modes."""
    return mode_service.list_wallet_groups()


@router.get(
    "/wallet-groups/{group_id}",
    response_model=WalletGroupConfig,
    summary="Get wallet group configuration",
    dependencies=[Depends(require_permission(Permission.READ_WALLET_GROUPS))],
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
    dependencies=[Depends(require_permission(Permission.POLICY_TIGHTEN))],
)
async def update_group_mode(
    request: Request,
    group_id: str,
    payload: WalletGroupModeUpdate,
    current_user: UserResponse = Depends(require_permission(Permission.POLICY_TIGHTEN)),
) -> WalletGroupConfig:
    """Updates group mode enforcing promotion gates."""
    operator_name = payload.operator_id or current_user.email
    success, message, group = mode_service.update_group_mode(
        group_id=group_id,
        new_mode=payload.mode,
        override=payload.override,
        override_reason=payload.override_reason,
        operator_id=operator_name,
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    assertion_ref = getattr(request.state, "webauthn_assertion_ref", None)
    log_admin_action_audit(
        user=current_user,
        action="UPDATE_WALLET_GROUP_MODE",
        assertion_ref=assertion_ref,
        details={"group_id": group_id, "new_mode": payload.mode.value, "override": payload.override},
    )
    return group


@router.get(
    "/wallet-groups/{group_id}/metrics",
    response_model=list[DailyGroupMetrics],
    summary="Get daily shadow metrics for wallet group",
    dependencies=[Depends(require_permission(Permission.READ_METRICS))],
)
async def get_wallet_group_metrics(group_id: str) -> list[DailyGroupMetrics]:
    """Returns daily counters for a wallet group."""
    return mode_service.get_metrics_for_group(group_id)


@router.get(
    "/metrics/intent",
    response_model=IntentMetricsResponse,
    summary="Get withdrawal intent reconciliation metrics",
    description="Exposes total intent checks, unmatched count, and unmatched_request_rate for dashboard visualization.",
    dependencies=[Depends(require_permission(Permission.READ_METRICS))],
)
async def get_intent_metrics() -> IntentMetricsResponse:
    """Returns withdrawal intent reconciliation metrics."""
    return intent_metrics.get_metrics()


@router.websocket("/stream")
async def websocket_event_stream(websocket: WebSocket) -> None:
    """Real-time event stream for decision notifications, breaker status changes, and outflow aggregates.

    Requires a valid JWT with at least Viewer role.
    On connect: sends last 50 decisions, then pushes live decisions, breaker changes,
    and 5-second per-chain outflow aggregates. Enforces queue-based backpressure.
    """
    token = websocket.query_params.get("token")
    if not token:
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1]

    is_unauth = (
        websocket.headers.get("x-anonymous") == "true"
        or websocket.query_params.get("anonymous") == "true"
    )

    if is_unauth or not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication credentials required")
        return

    try:
        payload = decode_access_token(token)
        role_val = payload.get("role")
        user_role = None
        for r in Role:
            if r.value.lower() == str(role_val).lower():
                user_role = r
                break
        if not user_role:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Unrecognized role in token")
            return

        user_perms = PERMISSION_MATRIX.get(user_role, set())
        if Permission.READ_DECISIONS not in user_perms:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Role lacks Viewer read permissions")
            return
    except Exception as exc:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason=f"Invalid or expired JWT: {exc}")
        return

    await websocket.accept()

    # Replay last 50 decisions on connect
    last_50 = decision_store.get_last_n_decisions(50)
    await websocket.send_json(
        {
            "type": "connected",
            "service": "bitguard",
            "channel": "events",
            "data_label": "REAL",
            "payload": {
                "last_decisions": [d.model_dump(mode="json") for d in last_50],
                "count": len(last_50),
            },
        }
    )

    client = stream_broadcaster.register_client(websocket)

    async def writer() -> None:
        try:
            while client.is_alive:
                event = await client.queue.get()
                await websocket.send_json(event)
                client.queue.task_done()
        except (asyncio.CancelledError, WebSocketDisconnect, Exception):
            client.is_alive = False

    async def reader() -> None:
        try:
            while client.is_alive:
                text = await websocket.receive_text()
                if text == "ping":
                    await websocket.send_text("pong")
        except (asyncio.CancelledError, WebSocketDisconnect, Exception):
            client.is_alive = False

    w_task = asyncio.create_task(writer())
    r_task = asyncio.create_task(reader())

    try:
        done, pending = await asyncio.wait(
            [w_task, r_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
    finally:
        client.is_alive = False
        stream_broadcaster.unregister_client(client.id)


@router.get(
    "/outflows",
    summary="Get 5-second per-chain outflow aggregates",
    description="Returns current cumulative outflow aggregates across all supported blockchains.",
    dependencies=[Depends(require_permission(Permission.READ_METRICS))],
)
def get_outflows() -> dict[str, Any]:
    return {
        "outflows": stream_broadcaster.get_chain_outflows(),
        "timestamp": datetime.now(UTC).isoformat(),
        "data_label": "REAL",
    }


class CancelTimelockRequest(BaseModel):
    reason: str = "Operator manual cancellation"


@router.get(
    "/timelocks",
    response_model=list[TimelockItem],
    summary="List queued time-locked withdrawals",
    description="Returns queued delayed transactions awaiting cooldown expiration.",
    dependencies=[Depends(require_permission(Permission.READ_DECISIONS))],
)
def list_timelocks() -> list[TimelockItem]:
    return timelock_store.list_all()


@router.post(
    "/timelocks/{item_id}/cancel",
    response_model=TimelockItem,
    summary="Cancel time-locked withdrawal",
    description="Cancels a queued withdrawal before the time-lock window expires.",
    dependencies=[Depends(require_role(Role.OPERATOR, Role.SECOPS, Role.APPROVER, Role.ADMIN))],
)
def cancel_timelock(
    item_id: str,
    payload: CancelTimelockRequest = CancelTimelockRequest(),
    current_user: UserResponse = Depends(require_role(Role.OPERATOR, Role.SECOPS, Role.APPROVER, Role.ADMIN)),
) -> TimelockItem:
    try:
        return timelock_store.cancel(item_id, reason=payload.reason, user_id=current_user.id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

