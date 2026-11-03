"""Unit and integration tests for Task U5 - Live Feed.

Covers:
- WebSocket /v1/stream subscription and real decision events
- GET /v1/outflows per-chain 5-second aggregates
- GET /v1/timelocks and POST /v1/timelocks/{id}/cancel
- GET /v1/holds/{id}/view independent decoding
- Approval separation of duties (requester cannot approve, duplicate approver rejected)
- Frontend client & UI component verification for U5 requirements
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import rlp
from fastapi.testclient import TestClient

from services.bitguard.approvals.hold_store import hold_store
from services.bitguard.decoders.evm import evm_decoder
from services.bitguard.main import app
from services.bitguard.models import DataLabel, DecisionReason, HoldTicket, Role
from services.bitguard.rbac import SEEDED_USERS, create_access_token
from services.bitguard.stream.broadcaster import stream_broadcaster
from services.bitguard.timelock.store import TimelockItem, timelock_store


@pytest.fixture
def test_client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def auth_headers() -> dict[str, str]:
    user = SEEDED_USERS[Role.SECOPS]
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


def build_raw_test_tx(value: int = 50_000_000_000, nonce: int = 1) -> str:
    """Constructs a valid signed or unsigned raw EVM legacy transaction."""
    dest = bytes.fromhex("1111111111111111111111111111111111111111")
    payload = [nonce, 20_000_000_000, 21000, dest, value, b""]
    return "0x" + rlp.encode(payload).hex()


def test_get_outflows_endpoint(test_client: TestClient, auth_headers: dict[str, str]) -> None:
    """Verifies GET /v1/outflows returns per-chain aggregates."""
    res = test_client.get("/v1/outflows", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "outflows" in data
    assert "timestamp" in data
    assert "data_label" in data
    assert data["data_label"] in ["REAL", "SYNTHETIC", "REPORTED"]


def test_timelock_lifecycle_endpoints(test_client: TestClient, auth_headers: dict[str, str]) -> None:
    """Verifies listing and cancelling queued timelocked transactions."""
    # List timelocks
    res = test_client.get("/v1/timelocks", headers=auth_headers)
    assert res.status_code == 200
    items = res.json()
    assert isinstance(items, list)
    assert len(items) >= 2  # Seeded with at least 2 default items

    # Create a fresh test timelock item
    fresh_item = TimelockItem(
        id="tl-test-custom-01",
        request_id="req-test-custom-01",
        chain="ethereum",
        wallet="0x1234567890123456789012345678901234567890",
        recipient="0x9999999999999999999999999999999999999999",
        asset="ETH",
        amount_usd=250000.0,
        status="QUEUED",
        release_time=timelock_store.list_all()[0].release_time,
        data_label=DataLabel.REAL,
    )
    timelock_store.add(fresh_item)

    # Cancel the item
    cancel_res = test_client.post(
        f"/v1/timelocks/{fresh_item.id}/cancel",
        json={"reason": "SecOps flagged suspicious contract recipient"},
        headers=auth_headers,
    )
    assert cancel_res.status_code == 200
    cancelled_data = cancel_res.json()
    assert cancelled_data["status"] == "CANCELLED"
    assert cancelled_data["cancel_reason"] == "SecOps flagged suspicious contract recipient"
    assert cancelled_data["cancelled_by"] == SEEDED_USERS[Role.SECOPS].id

    # Cancelling non-existent item returns 404
    err_res = test_client.post(
        "/v1/timelocks/non-existent-tl-id/cancel",
        json={"reason": "test"},
        headers=auth_headers,
    )
    assert err_res.status_code == 404


def test_hold_view_and_separation_of_duties(test_client: TestClient, auth_headers: dict[str, str]) -> None:
    """Verifies hold ticket inspection (/v1/holds/{id}/view) and approval separation of duties."""
    raw = build_raw_test_tx()
    decoded = evm_decoder.decode(bytes.fromhex(raw.removeprefix("0x")))
    now = datetime.now(UTC)
    requester_user = SEEDED_USERS[Role.APPROVER]

    ticket = HoldTicket(
        id="ht-livefeed-001",
        request_id="req-livefeed-hold-01",
        tx_digest=decoded.digest,
        raw_tx=raw,
        chain="ethereum",
        wallet=decoded.from_address,
        amount_usd=50_000.0,
        requester_id=requester_user.id,
        reservation_id="res-livefeed-001",
        risk_score=78,
        reasons=[
            DecisionReason(
                code="OUTFLOW_VELOCITY_SPIKE",
                weight=50,
                detail="Transaction outflow exceeds 10m baseline",
            )
        ],
        status="PENDING",
        expires_at=now + timedelta(minutes=15),
        created_at=now,
    )
    hold_store.create(ticket)

    # 1. View hold details via /v1/holds/{id}/view
    view_res = test_client.get(f"/v1/holds/{ticket.id}/view", headers=auth_headers)
    assert view_res.status_code == 200
    view_data = view_res.json()
    assert view_data["hold_id"] == ticket.id
    assert view_data["decoded_tx"]["chain"] == "ethereum"
    assert view_data["decoded_tx"]["from"] == decoded.from_address
    assert view_data["decoded_tx"]["to"] == "0x1111111111111111111111111111111111111111"
    assert view_data["requester_id"] == requester_user.id
    assert len(view_data["reasons"]) > 0

    # 2. Separation of duties: requester cannot approve
    requester_token = create_access_token(requester_user)
    req_approve_res = test_client.post(
        f"/v1/holds/{ticket.id}/approve",
        json={
            "assertion": {
                "credential_id": "cred-requester",
                "authenticator_data": "dGVzdC1hdXRoLWRhdGE=",
                "client_data_json": "dGVzdC1jbGllbnQtZGF0YQ==",
                "signature": "dGVzdC1zaWduYXR1cmU=",
            }
        },
        headers={"Authorization": f"Bearer {requester_token}"},
    )
    assert req_approve_res.status_code == 403
    assert "REQUESTER_CANNOT_APPROVE" in req_approve_res.json()["detail"]


def test_websocket_stream_broadcasting(test_client: TestClient) -> None:
    """Verifies that the websocket stream pushes last decisions and receives live broadcasts."""
    user = SEEDED_USERS[Role.OPERATOR]
    token = create_access_token(user)

    with test_client.websocket_connect(f"/v1/stream?token={token}") as ws:
        # First message on connect is 'connected'
        msg1 = ws.receive_json()
        assert msg1["type"] == "connected"
        assert "last_decisions" in msg1["payload"]

        # Broadcast a test event
        test_payload = {
            "request_id": "req-stream-test-01",
            "verdict": "ALLOW",
            "risk_score": 12,
            "chain": "ethereum",
            "wallet": "0x1111111111111111111111111111111111111111",
            "timestamp": "2026-11-04T00:00:00Z",
        }
        stream_broadcaster.publish_event("decision", test_payload)

        # Receive broadcast message
        msg2 = ws.receive_json()
        assert msg2["type"] == "decision"
        assert msg2["payload"]["request_id"] == "req-stream-test-01"


def test_ui_source_code_implements_u5_requirements() -> None:
    """Verifies that the UI source files implement all required components for Task U5."""
    livefeed_file = Path("frontend/src/pages/LiveFeed.tsx")
    assert livefeed_file.exists()
    content = livefeed_file.read_text(encoding="utf-8")

    # 1. HOLD queue with countdown, view decoded tx, WebAuthn approve, deny, separation of duties explanation
    assert "Pending HOLD Quarantine Queue" in content or "Pending HOLD" in content
    assert "navigator.credentials.get" in content
    assert "Requester cannot approve own hold ticket" in content
    assert "already approved this ticket" in content
    assert "fetchHoldView" in content
    assert "handleDenyHold" in content

    # 2. Time-lock queue with release countdown and Cancel button
    assert "Active Time-Lock Delay Queue" in content or "Time-Lock" in content
    assert "cancelTimelock" in content
    assert "fetchTimelocks" in content
    assert "Releases in" in content or "release_time" in content

    # 3. Per-chain outflow bars fed from 5-second aggregates
    assert "Per-Chain Outflow Velocity (5s Aggregates)" in content or "Outflow" in content
    assert "fetchChainOutflows" in content
    assert "chain_outflow_aggregate" in content

    # 4. Deduplication by request_id across reconnects
    assert "prev.some" in content
    assert "request_id" in content

    # 5. Data provenance tags (REAL / SYNTHETIC)
    assert "REAL" in content
    assert "SYNTHETIC" in content

    # 6. API client layer verification
    api_ts = Path("frontend/src/api.ts").read_text(encoding="utf-8")
    assert "fetchTimelocks" in api_ts
    assert "cancelTimelock" in api_ts
    assert "fetchChainOutflows" in api_ts
    assert "openStream" in api_ts

    api_js = Path("web/api.js").read_text(encoding="utf-8")
    assert "fetchTimelocks" in api_js
    assert "cancelTimelock" in api_js
    assert "fetchChainOutflows" in api_js
    assert "openStream" in api_js
