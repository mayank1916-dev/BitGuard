"""Unit and integration tests for Decision persistence and WebSocket event streaming (Milestone S13).

Requirements:
- Persist every Decision (timings, reasons, mode, policy_version, data_label) in Postgres with indexes on time and verdict.
- GET /v1/decisions with filters (time range, verdict, wallet, chain) and cursor pagination.
- WebSocket /v1/stream: requires valid JWT with at least Viewer role; on connect sends last 50 decisions,
  then pushes new decisions and breaker-state changes as typed events {type, payload, data_label}.
- 5-second per-chain outflow aggregates.
- Backpressure: drops slow clients rather than blocking the gateway.
- Tests: client receives events in order; unauthenticated client rejected; killing stream never affects decisions.
"""

import asyncio
import time
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from services.bitguard.database import set_engine
from services.bitguard.decision_store import decision_store
from services.bitguard.main import app
from services.bitguard.models import (
    DataLabel,
    Decision,
    DecisionReason,
    OperationMode,
    Role,
    Verdict,
)
from services.bitguard.rbac import SEEDED_USERS, create_access_token
from services.bitguard.stream.broadcaster import stream_broadcaster

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_persistence_test_db():
    """Sets up an in-memory SQLite database for deterministic persistence and indexing tests."""
    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=sa.pool.StaticPool,
    )
    set_engine(engine)
    decision_store.clear()
    stream_broadcaster._clients.clear()
    stream_broadcaster._chain_outflows.clear()
    yield
    decision_store.clear()
    stream_broadcaster._clients.clear()
    stream_broadcaster._chain_outflows.clear()


def make_test_decision(
    req_id: str,
    verdict: Verdict = Verdict.ALLOW,
    wallet: str = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    chain: str = "ethereum",
    risk_score: int = 10,
    created_at: datetime | None = None,
    amount_usd: float = 100.0,
) -> Decision:
    """Helper creating a complete Decision domain model with realistic timings and reasons."""
    return Decision(
        request_id=req_id,
        verdict=verdict,
        risk_score=risk_score,
        reasons=[DecisionReason(code="TEST_REASON", weight=risk_score, detail="Test diagnostic")],
        mode=OperationMode.ENFORCE,
        policy_version="v1.0.0",
        data_label=DataLabel.REAL,
        wallet_group="default",
        wallet=wallet,
        chain=chain,
        evaluation_latency_ms=4.2,
        timings={"decode": 0.5, "limits": 1.2, "decide": 0.3, "total": 4.2, "amount_usd": amount_usd},
        created_at=created_at or datetime.now(UTC),
    )


def test_decision_persistence_all_fields_and_sql_query():
    """Verify every Decision is persisted to Postgres/SQL with timings, reasons, mode, and data_label."""
    now = datetime.now(UTC)
    dec = make_test_decision(
        req_id="dec-persist-01",
        verdict=Verdict.DENY,
        wallet="0x1111111111111111111111111111111111111111",
        chain="arbitrum",
        risk_score=100,
        created_at=now,
    )

    saved = decision_store.save_decision(dec)
    assert saved.request_id == "dec-persist-01"

    # Query back from storage
    retrieved = decision_store.get_decision("dec-persist-01")
    assert retrieved is not None
    assert retrieved.request_id == "dec-persist-01"
    assert retrieved.verdict == Verdict.DENY
    assert retrieved.wallet == "0x1111111111111111111111111111111111111111"
    assert retrieved.chain == "arbitrum"
    assert retrieved.mode == OperationMode.ENFORCE
    assert retrieved.policy_version == "v1.0.0"
    assert retrieved.data_label == DataLabel.REAL
    assert retrieved.timings.get("total") == 4.2
    assert len(retrieved.reasons) == 1
    assert retrieved.reasons[0].code == "TEST_REASON"


def test_get_decisions_with_multi_field_filters():
    """Verify GET /v1/decisions filters by time range, verdict, wallet, and chain."""
    base_time = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)

    # Seed 4 decisions with different properties
    d1 = make_test_decision("d-1", Verdict.ALLOW, wallet="0xAAA", chain="ethereum", created_at=base_time)
    d2 = make_test_decision("d-2", Verdict.HOLD, wallet="0xAAA", chain="base", created_at=base_time + timedelta(hours=1))
    d3 = make_test_decision("d-3", Verdict.DENY, wallet="0xBBB", chain="ethereum", created_at=base_time + timedelta(hours=2))
    d4 = make_test_decision("d-4", Verdict.ALLOW, wallet="0xBBB", chain="optimism", created_at=base_time + timedelta(hours=3))

    for d in [d1, d2, d3, d4]:
        decision_store.save_decision(d)

    viewer_token = create_access_token(SEEDED_USERS[Role.VIEWER])
    headers = {"Authorization": f"Bearer {viewer_token}"}

    # 1. Filter by verdict=HOLD
    resp = client.get("/v1/decisions?verdict=HOLD", headers=headers)
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    assert items[0]["request_id"] == "d-2"

    # 2. Filter by wallet=0xAAA
    resp = client.get("/v1/decisions?wallet=0xAAA", headers=headers)
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 2
    assert {it["request_id"] for it in items} == {"d-1", "d-2"}

    # 3. Filter by chain=ethereum
    resp = client.get("/v1/decisions?chain=ethereum", headers=headers)
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 2
    assert {it["request_id"] for it in items} == {"d-1", "d-3"}

    # 4. Filter by time range: between hour 0.5 and hour 2.5
    t_start = (base_time + timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    t_end = (base_time + timedelta(hours=2, minutes=30)).isoformat().replace("+00:00", "Z")
    resp = client.get(f"/v1/decisions?start_time={t_start}&end_time={t_end}", headers=headers)
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 2
    assert {it["request_id"] for it in items} == {"d-2", "d-3"}


def test_cursor_pagination():
    """Verify cursor pagination navigates forward correctly without duplicate records."""
    base_time = datetime(2026, 11, 1, 10, 0, 0, tzinfo=UTC)

    # Seed 5 decisions ordered chronologically
    for i in range(5):
        d = make_test_decision(f"page-dec-{i}", created_at=base_time + timedelta(minutes=i * 10))
        decision_store.save_decision(d)

    # Query first page of limit=2
    decisions_p1, cursor_1 = decision_store.list_decisions(limit=2)
    assert len(decisions_p1) == 2
    assert decisions_p1[0].request_id == "page-dec-4"  # Most recent first
    assert decisions_p1[1].request_id == "page-dec-3"
    assert cursor_1 == "page-dec-3"

    # Query second page using cursor_1
    decisions_p2, cursor_2 = decision_store.list_decisions(limit=2, cursor=cursor_1)
    assert len(decisions_p2) == 2
    assert decisions_p2[0].request_id == "page-dec-2"
    assert decisions_p2[1].request_id == "page-dec-1"
    assert cursor_2 == "page-dec-1"

    # Query final page using cursor_2
    decisions_p3, cursor_3 = decision_store.list_decisions(limit=2, cursor=cursor_2)
    assert len(decisions_p3) == 1
    assert decisions_p3[0].request_id == "page-dec-0"
    assert cursor_3 is None  # No further pages


def test_websocket_stream_unauthenticated_client_rejected():
    """Verify WebSocket /v1/stream rejects unauthenticated clients or invalid JWTs."""
    # 1. No token provided
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/v1/stream"):
            pass
    assert exc_info.value.code == 1008

    # 2. Invalid JWT token
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/v1/stream?token=invalid.jwt.token"):
            pass
    assert exc_info.value.code == 1008


def test_websocket_stream_receives_events_in_order():
    """Verify WebSocket client receives initial last 50 decisions and subsequent typed events in order."""
    # 1. Seed existing decisions
    for i in range(3):
        decision_store.save_decision(make_test_decision(f"prior-dec-{i}"))

    viewer_token = create_access_token(SEEDED_USERS[Role.VIEWER])
    ws_url = f"/v1/stream?token={viewer_token}"

    with client.websocket_connect(ws_url) as ws:
        # Event 1: Connected handshake with prior decisions snapshot
        init_event = ws.receive_json()
        assert init_event["type"] == "connected"
        assert init_event["service"] == "bitguard"
        assert len(init_event["payload"]["last_decisions"]) == 3

        # 2. Publish new Decision -> pushed live as typed event
        new_dec = make_test_decision("live-stream-dec-99", verdict=Verdict.HOLD, risk_score=65)
        decision_store.save_decision(new_dec)

        event_dec = ws.receive_json()
        assert event_dec["type"] == "decision"
        assert event_dec["payload"]["request_id"] == "live-stream-dec-99"
        assert event_dec["payload"]["verdict"] == "HOLD"
        assert event_dec["data_label"] == "REAL"

        # 3. Publish Breaker state change -> pushed live as typed event
        stream_broadcaster.publish_breaker_state("ELEVATED", reason="Spike detected")
        event_breaker = ws.receive_json()
        assert event_breaker["type"] == "breaker_state"
        assert event_breaker["payload"]["state"] == "ELEVATED"
        assert "Spike detected" in event_breaker["payload"]["reason"]

        # 4. Outflow aggregate event
        stream_broadcaster.publish_outflows()
        event_outflow = ws.receive_json()
        assert event_outflow["type"] == "chain_outflow_aggregate"
        assert "outflows" in event_outflow["payload"]


def test_backpressure_drops_slow_clients():
    """Verify backpressure drops slow clients when queue capacity is exceeded rather than blocking."""
    # Create broadcaster with tiny queue of 2 items
    tiny_broadcaster = stream_broadcaster
    tiny_broadcaster.max_queue_size = 2

    # Mock a mock slow WebSocket client that never reads from its queue
    class MockSlowWebSocket:
        def __init__(self):
            self.closed = False
            self.close_code = None

        async def close(self, code=1000, reason=""):
            self.closed = True
            self.close_code = code

    mock_ws = MockSlowWebSocket()
    slow_client = tiny_broadcaster.register_client(mock_ws, client_id="slow-client-01")

    # Publish 2 events (fits in queue)
    tiny_broadcaster.publish_event("test_1", {"msg": 1})
    tiny_broadcaster.publish_event("test_2", {"msg": 2})
    assert slow_client.queue.qsize() == 2
    assert "slow-client-01" in tiny_broadcaster._clients

    # Publish 3rd event: queue is full -> client dropped immediately
    tiny_broadcaster.publish_event("test_3", {"msg": 3})
    assert "slow-client-01" not in tiny_broadcaster._clients
    assert not slow_client.is_alive

    # Allow close task to complete
    asyncio.run(asyncio.sleep(0.01))

    # Restore default capacity
    tiny_broadcaster.max_queue_size = 100


def test_killing_stream_never_affects_decisions():
    """Verify abruptly closing or killing stream clients never blocks or fails decision engine evaluations."""
    viewer_token = create_access_token(SEEDED_USERS[Role.VIEWER])

    # Connect client then immediately close it
    with client.websocket_connect(f"/v1/stream?token={viewer_token}") as ws:
        _ = ws.receive_json()
        # Abruptly exit context, killing websocket

    # Decision evaluation should execute smoothly with 0 errors and nominal latency
    start = time.perf_counter()
    dec = make_test_decision("post-kill-dec-1")
    saved = decision_store.save_decision(dec)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    assert saved.request_id == "post-kill-dec-1"
    assert elapsed_ms < 50.0  # Decoupled non-blocking execution
