"""API contract and OpenAPI drift tests for BitGuard Firewall."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from services.bitguard.main import app
from services.bitguard.models import (
    Approval,
    AuditEntry,
    AuthorizationItem,
    BreakerState,
    BreakerStateEnum,
    CallItem,
    DataLabel,
    Decision,
    DecisionReason,
    DecodedTx,
    FeeDetail,
    HoldTicket,
    OperationMode,
    PolicyVersion,
    SigningRequest,
    Verdict,
    WatchedAddress,
)

client = TestClient(app)


def test_openapi_schema_drift():
    """Verify live app.openapi() strictly matches docs/openapi.json.

    Fails if routes, models, or descriptions are modified without updating the contract export.
    """
    contract_path = Path(__file__).resolve().parent.parent / "docs" / "openapi.json"
    assert contract_path.exists(), "docs/openapi.json must exist"

    disk_schema = json.loads(contract_path.read_text(encoding="utf-8"))
    live_schema = json.loads(json.dumps(app.openapi()))

    assert live_schema == disk_schema, (
        "OpenAPI schema has drifted from docs/openapi.json! "
        "Run 'python services/bitguard/export_openapi.py' to synchronize."
    )


def test_signing_request_model_validation():
    """Verify SigningRequest model attributes, parsing, and constraints."""
    req_data = {
        "id": "req-contract-001",
        "raw_tx": "0x02f8708101...",
        "chain": "ethereum",
        "wallet": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "intent_id": "intent-1234",
        "mode": "SIMULATION",
        "metadata": {"origin": "trading-desk"},
    }
    req = SigningRequest.model_validate(req_data)
    assert req.id == "req-contract-001"
    assert req.raw_tx.startswith("0x02")
    assert req.chain == "ethereum"
    assert req.mode == OperationMode.SIMULATION
    assert req.metadata["origin"] == "trading-desk"
    assert isinstance(req.created_at, datetime)

    # Missing mandatory field raw_tx must raise ValidationError
    with pytest.raises(ValidationError):
        SigningRequest.model_validate({"id": "req-missing-tx", "chain": "eth", "wallet": "0x123"})


def test_decoded_tx_canonical_model():
    """Verify DecodedTx parsing, alias handling for from/to, and serialization."""
    raw_dict = {
        "chain": "ethereum",
        "from": "0x1111111111111111111111111111111111111111",
        "to": "0x2222222222222222222222222222222222222222",
        "asset": "ETH",
        "amount": "1000000000000000000",
        "calls": [
            {"to": "0x3333333333333333333333333333333333333333", "value": "100", "data": "0x"}
        ],
        "authorizations": [{"chain_id": 1, "address": "0x4444", "nonce": 0}],
        "fee": {
            "gas_limit": 21000,
            "max_fee_per_gas": "30000000000",
            "max_priority_fee_per_gas": "1000000000",
        },
        "digest": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    }
    decoded = DecodedTx.model_validate(raw_dict)
    assert decoded.chain == "ethereum"
    assert decoded.from_address == "0x1111111111111111111111111111111111111111"
    assert decoded.to_address == "0x2222222222222222222222222222222222222222"
    assert len(decoded.calls) == 1
    assert isinstance(decoded.calls[0], CallItem)
    assert len(decoded.authorizations) == 1
    assert isinstance(decoded.authorizations[0], AuthorizationItem)
    assert isinstance(decoded.fee, FeeDetail)

    dumped = decoded.model_dump(by_alias=True)
    assert dumped["from"] == "0x1111111111111111111111111111111111111111"
    assert dumped["to"] == "0x2222222222222222222222222222222222222222"


def test_decision_model_and_invariants():
    """Verify Decision model enforces risk score range, verdict enum, and data provenance."""
    dec = Decision(
        request_id="req-999",
        verdict=Verdict.DENY,
        risk_score=95,
        reasons=[DecisionReason(code="SUSPICIOUS_DELEGATION", weight=95, detail="Unauthorized delegate")],
        mode=OperationMode.ENFORCE,
        policy_version="v1.0.0",
        data_label=DataLabel.REAL,
    )
    assert dec.verdict == Verdict.DENY
    assert dec.risk_score == 95
    assert dec.data_label == DataLabel.REAL

    # Risk score > 100 must fail validation
    with pytest.raises(ValidationError):
        Decision(
            request_id="req-bad",
            verdict=Verdict.DENY,
            risk_score=101,
            reasons=[],
            mode=OperationMode.ENFORCE,
            policy_version="v1.0.0",
            data_label=DataLabel.REAL,
        )


def test_supporting_canonical_models():
    """Verify HoldTicket, Approval, PolicyVersion, AuditEntry, WatchedAddress, and BreakerState."""
    now = datetime.now(UTC)

    # HoldTicket
    ht = HoldTicket(
        id="ht-01",
        request_id="req-01",
        tx_digest="0xdigest",
        reasons=[DecisionReason(code="HOLD_VELOCITY", weight=50, detail="Velocity exceeded")],
        status="PENDING",
        expires_at=now,
    )
    assert ht.status == "PENDING"

    # Approval
    appr = Approval(
        id="appr-01",
        hold_ticket_id="ht-01",
        approver_id="sec-admin-1",
        tx_digest="0xdigest",
        webauthn_signature="webauthn-sig-bytes",
    )
    assert appr.approver_id == "sec-admin-1"

    # PolicyVersion
    pv = PolicyVersion(
        id="pv-01",
        version="v1.0.0",
        author="sec-team",
        rules={"max_value_usd": 100000},
        signature="policy-sig",
        is_active=True,
    )
    assert pv.is_active is True

    # AuditEntry
    ae = AuditEntry(
        index=1,
        timestamp=1730000000.0,
        event_type="DECISION",
        request_id="req-01",
        verdict="DENY",
        prev_hash="0" * 64,
        entry_hash="a" * 64,
        data_label=DataLabel.REPORTED,
    )
    assert ae.prev_hash == "0" * 64

    # WatchedAddress
    wa = WatchedAddress(
        id="wa-01",
        address="0x123",
        chain="ethereum",
        label="Deposit Hot Wallet",
        expected_code_hash="0xcode",
        allowed_delegates=["0xdelegate1"],
    )
    assert len(wa.allowed_delegates) == 1

    # BreakerState
    bs = BreakerState(
        state=BreakerStateEnum.LOCKDOWN,
        reason="Manual operator intervention",
        data_label=DataLabel.REAL,
    )
    assert bs.state == BreakerStateEnum.LOCKDOWN


def test_post_evaluate_endpoint_fails_closed():
    """POST /v1/evaluate returns 200 with fail-closed DENY on decode error or suspicious rule."""
    payload = {
        "id": "eval-req-101",
        "raw_tx": "0x02f87001",
        "chain": "ethereum",
        "wallet": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "mode": "SIMULATION",
        "metadata": {"simulate_decode_error": True},
    }
    response = client.post("/v1/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Verify against Decision model
    decision = Decision.model_validate(data)
    assert decision.request_id == "eval-req-101"
    assert decision.verdict == Verdict.DENY
    assert decision.risk_score == 100
    assert len(decision.reasons) >= 1
    assert decision.reasons[0].code == "DECODE_ERROR"
    assert decision.data_label in [DataLabel.REAL, DataLabel.SYNTHETIC, DataLabel.REPORTED]


def test_post_sign_requests_endpoint_fails_closed():
    """POST /v1/sign-requests returns 200 with binding DENY when rule violated in ENFORCE mode."""
    payload = {
        "id": "sign-req-202",
        "raw_tx": "0x02f87001",
        "chain": "ethereum",
        "wallet": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "mode": "ENFORCE",
        "metadata": {"simulate_deny": True},
    }
    response = client.post("/v1/sign-requests", json=payload)
    assert response.status_code == 200
    data = response.json()

    decision = Decision.model_validate(data)
    assert decision.request_id == "sign-req-202"
    assert decision.verdict == Verdict.DENY
    assert decision.reasons[0].code == "SUSPICIOUS_DELEGATION"


def test_post_evaluate_validation_error():
    """POST /v1/evaluate with missing required field raw_tx returns 422."""
    response = client.post("/v1/evaluate", json={"id": "bad-payload", "chain": "eth"})
    assert response.status_code == 422


def test_get_decisions_endpoint():
    """GET /v1/decisions returns a list of decisions adhering to contract."""
    response = client.get("/v1/decisions?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_get_breaker_endpoint():
    """GET /v1/breaker returns active BreakerState."""
    response = client.get("/v1/breaker")
    assert response.status_code == 200
    data = response.json()

    state = BreakerState.model_validate(data)
    assert state.state in [
        BreakerStateEnum.NORMAL,
        BreakerStateEnum.ELEVATED,
        BreakerStateEnum.HOLD,
        BreakerStateEnum.LOCKDOWN,
    ]
    assert state.data_label == DataLabel.REAL


def test_websocket_stream_contract():
    """WebSocket /v1/stream establishes handshake and responds to ping."""
    with client.websocket_connect("/v1/stream") as ws:
        init_data = ws.receive_json()
        assert init_data["type"] == "connected"
        assert init_data["service"] == "bitguard"
        assert init_data["channel"] == "events"

        ws.send_text("ping")
        pong = ws.receive_text()
        assert pong == "pong"
