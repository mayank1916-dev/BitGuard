"""Comprehensive unit and integration tests for withdrawal intent reconciliation (Milestone S08 / F2)."""

import pytest
import rlp
from fastapi.testclient import TestClient

from services.bitguard.decoders.evm import evm_decoder
from services.bitguard.ledger.intent_check import check_intent
from services.bitguard.ledger.metrics import intent_metrics
from services.bitguard.ledger.mock import mock_ledger_connector
from services.bitguard.ledger.models import IntentStatus, WithdrawalIntent
from services.bitguard.main import app
from services.bitguard.models import SigningRequest
from services.ledger_mock.main import app as ledger_mock_app

client = TestClient(app)
ledger_client = TestClient(ledger_mock_app)


def build_raw_legacy_tx(
    to: str,
    value: int,
    nonce: int = 0,
    gas_price: int = 20_000_000_000,
    gas_limit: int = 21000,
    data: bytes = b"",
    chain_id: int = 1,
) -> str:
    """Helper to build a valid signed/unsigned legacy EVM raw transaction hex."""
    to_bytes = bytes.fromhex(to[2:]) if to.startswith("0x") else bytes.fromhex(to)
    payload = [nonce, gas_price, gas_limit, to_bytes, value, data]
    return "0x" + rlp.encode(payload).hex()


@pytest.fixture(autouse=True)
def clean_ledger_state():
    """Resets mock ledger connectors and metric counters before each test."""
    mock_ledger_connector.reset()
    intent_metrics.reset()
    yield
    mock_ledger_connector.reset()
    intent_metrics.reset()


def test_intent_missing_when_no_id_supplied():
    """Reason code INTENT_MISSING: signing request has no intent_id."""
    raw_tx = build_raw_legacy_tx(to="0x1111111111111111111111111111111111111111", value=1000)
    decoded = evm_decoder.decode(raw_tx)

    req = SigningRequest(
        id="req-no-intent",
        raw_tx=raw_tx,
        chain="ethereum",
        wallet="0x1111111111111111111111111111111111111111",
        intent_id=None,
    )

    result = check_intent(req, decoded, mock_ledger_connector)
    assert not result.passed
    assert result.code == "INTENT_MISSING"


def test_intent_missing_when_invented_id():
    """Reason code INTENT_MISSING: request invents a non-existent intent ID."""
    raw_tx = build_raw_legacy_tx(to="0x1111111111111111111111111111111111111111", value=1000)
    decoded = evm_decoder.decode(raw_tx)

    req = SigningRequest(
        id="req-fake-intent",
        raw_tx=raw_tx,
        chain="ethereum",
        wallet="0x1111111111111111111111111111111111111111",
        intent_id="intent-invented-nonexistent-999",
    )

    result = check_intent(req, decoded, mock_ledger_connector)
    assert not result.passed
    assert result.code == "INTENT_MISSING"
    assert "does not exist in custody ledger" in (result.detail or "")


def test_intent_not_approved_pending_or_cancelled():
    """Reason code INTENT_NOT_APPROVED: intent exists but is PENDING or CANCELLED."""
    raw_tx = build_raw_legacy_tx(to="0x2222222222222222222222222222222222222222", value=5000)
    decoded = evm_decoder.decode(raw_tx)

    # 1. PENDING status
    pending_intent = WithdrawalIntent(
        id="intent-pending-01",
        status=IntentStatus.PENDING.value,
        chain="ethereum",
        asset="ETH",
        amount="5000",
        destination="0x2222222222222222222222222222222222222222",
    )
    mock_ledger_connector.register_intent(pending_intent)

    req_pending = SigningRequest(
        id="req-pending",
        raw_tx=raw_tx,
        chain="ethereum",
        wallet="0x2222222222222222222222222222222222222222",
        intent_id="intent-pending-01",
    )
    res_pending = check_intent(req_pending, decoded, mock_ledger_connector)
    assert not res_pending.passed
    assert res_pending.code == "INTENT_NOT_APPROVED"

    # 2. CANCELLED status
    cancelled_intent = WithdrawalIntent(
        id="intent-cancelled-02",
        status=IntentStatus.CANCELLED.value,
        chain="ethereum",
        asset="ETH",
        amount="5000",
        destination="0x2222222222222222222222222222222222222222",
    )
    mock_ledger_connector.register_intent(cancelled_intent)

    req_cancelled = SigningRequest(
        id="req-cancelled",
        raw_tx=raw_tx,
        chain="ethereum",
        wallet="0x2222222222222222222222222222222222222222",
        intent_id="intent-cancelled-02",
    )
    res_cancelled = check_intent(req_cancelled, decoded, mock_ledger_connector)
    assert not res_cancelled.passed
    assert res_cancelled.code == "INTENT_NOT_APPROVED"


def test_intent_already_paid():
    """Reason code INTENT_ALREADY_PAID: intent status is PAID."""
    raw_tx = build_raw_legacy_tx(to="0x3333333333333333333333333333333333333333", value=1000)
    decoded = evm_decoder.decode(raw_tx)

    paid_intent = WithdrawalIntent(
        id="intent-paid-03",
        status=IntentStatus.PAID.value,
        chain="ethereum",
        asset="ETH",
        amount="1000",
        destination="0x3333333333333333333333333333333333333333",
    )
    mock_ledger_connector.register_intent(paid_intent)

    req = SigningRequest(
        id="req-paid",
        raw_tx=raw_tx,
        chain="ethereum",
        wallet="0x3333333333333333333333333333333333333333",
        intent_id="intent-paid-03",
    )
    result = check_intent(req, decoded, mock_ledger_connector)
    assert not result.passed
    assert result.code == "INTENT_ALREADY_PAID"


def test_intent_mismatch_destination():
    """Reason code INTENT_MISMATCH_DESTINATION: raw bytes decode to different destination than intent."""
    raw_tx = build_raw_legacy_tx(to="0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", value=1000)
    decoded = evm_decoder.decode(raw_tx)
    assert decoded.to_address is not None
    assert decoded.to_address.lower() == "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    # Intent specifies destination 0xBBBB...
    intent = WithdrawalIntent(
        id="intent-dest-mismatch",
        status=IntentStatus.APPROVED.value,
        chain="ethereum",
        asset="ETH",
        amount="1000",
        destination="0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    )
    mock_ledger_connector.register_intent(intent)

    req = SigningRequest(
        id="req-dest-mismatch",
        raw_tx=raw_tx,
        chain="ethereum",
        wallet="0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        intent_id="intent-dest-mismatch",
    )

    result = check_intent(req, decoded, mock_ledger_connector)
    assert not result.passed
    assert result.code == "INTENT_MISMATCH_DESTINATION"
    assert "0xaaaaaaaa" in (result.detail or "").lower()
    assert "0xbbbbbbbb" in (result.detail or "").lower()


def test_intent_mismatch_amount():
    """Reason code INTENT_MISMATCH_AMOUNT: raw bytes decode to different amount than intent."""
    raw_tx = build_raw_legacy_tx(to="0x4444444444444444444444444444444444444444", value=9999)
    decoded = evm_decoder.decode(raw_tx)
    assert decoded.amount == "9999"

    # Intent specifies amount 5000
    intent = WithdrawalIntent(
        id="intent-amt-mismatch",
        status=IntentStatus.APPROVED.value,
        chain="ethereum",
        asset="ETH",
        amount="5000",
        destination="0x4444444444444444444444444444444444444444",
    )
    mock_ledger_connector.register_intent(intent)

    req = SigningRequest(
        id="req-amt-mismatch",
        raw_tx=raw_tx,
        chain="ethereum",
        wallet="0x4444444444444444444444444444444444444444",
        intent_id="intent-amt-mismatch",
    )

    result = check_intent(req, decoded, mock_ledger_connector)
    assert not result.passed
    assert result.code == "INTENT_MISMATCH_AMOUNT"
    assert "9999" in (result.detail or "")
    assert "5000" in (result.detail or "")


def test_idempotency_second_request_is_intent_replay():
    """Reason code INTENT_REPLAY: an intent can be consumed once; second request is DENY."""
    target_dest = "0x5555555555555555555555555555555555555555"
    raw_tx = build_raw_legacy_tx(to=target_dest, value=1000)
    decoded = evm_decoder.decode(raw_tx)

    intent = WithdrawalIntent(
        id="intent-idempotent-01",
        status=IntentStatus.APPROVED.value,
        chain="ethereum",
        asset="ETH",
        amount="1000",
        destination=target_dest,
    )
    mock_ledger_connector.register_intent(intent)

    req = SigningRequest(
        id="req-first-attempt",
        raw_tx=raw_tx,
        chain="ethereum",
        wallet=target_dest,
        intent_id="intent-idempotent-01",
    )

    # First attempt: succeeds
    res1 = check_intent(req, decoded, mock_ledger_connector)
    assert res1.passed

    # Simulate consumption (as happens when transaction is broadcast/signed)
    consumed = mock_ledger_connector.mark_consumed("intent-idempotent-01")
    assert consumed

    # Second consumption attempt returns False
    assert not mock_ledger_connector.mark_consumed("intent-idempotent-01")

    # Second request with the same intent ID: MUST FAIL with INTENT_REPLAY
    req2 = SigningRequest(
        id="req-replay-attack",
        raw_tx=raw_tx,
        chain="ethereum",
        wallet=target_dest,
        intent_id="intent-idempotent-01",
    )
    res2 = check_intent(req2, decoded, mock_ledger_connector)
    assert not res2.passed
    assert res2.code == "INTENT_REPLAY"


def test_legitimate_intent_reconciliation_passes_pipeline():
    """Legitimate request matching approved intent passes pipeline and consumes intent."""
    target_dest = "0x7777777777777777777777777777777777777777"
    raw_tx = build_raw_legacy_tx(to=target_dest, value=2500)

    intent = WithdrawalIntent(
        id="intent-legit-pipeline",
        status=IntentStatus.APPROVED.value,
        chain="ethereum",
        asset="ETH",
        amount="2500",
        destination=target_dest,
    )
    mock_ledger_connector.register_intent(intent)

    payload = {
        "id": "req-legit-01",
        "raw_tx": raw_tx,
        "chain": "ethereum",
        "wallet": target_dest,
        "intent_id": "intent-legit-pipeline",
    }

    # Evaluate dry-run
    res_dry = client.post("/v1/evaluate", json=payload)
    assert res_dry.status_code == 200
    data_dry = res_dry.json()
    assert data_dry["verdict"] == "ALLOW"
    # Dry run must NOT consume intent
    assert not mock_ledger_connector.is_consumed("intent-legit-pipeline")

    # Production sign-request
    res_prod = client.post("/v1/sign-requests", json=payload)
    assert res_prod.status_code == 200
    data_prod = res_prod.json()
    assert data_prod["verdict"] == "ALLOW"
    # Production sign-request consumed the intent
    assert mock_ledger_connector.is_consumed("intent-legit-pipeline")

    # Immediate second sign-request with same intent -> DENIED with INTENT_REPLAY
    res_replay = client.post("/v1/sign-requests", json=payload)
    assert res_replay.status_code == 200
    data_replay = res_replay.json()
    assert data_replay["verdict"] == "DENY"
    assert data_replay["reasons"][0]["code"] == "INTENT_REPLAY"


def test_unmatched_request_rate_metric():
    """Metric unmatched_request_rate accurately calculates ratio and exposes breakdown."""
    target_dest = "0x8888888888888888888888888888888888888888"
    raw_tx = build_raw_legacy_tx(to=target_dest, value=1000)
    decoded = evm_decoder.decode(raw_tx)

    # 1. Successful match
    intent = WithdrawalIntent(
        id="intent-metrics-ok",
        status=IntentStatus.APPROVED.value,
        chain="ethereum",
        asset="ETH",
        amount="1000",
        destination=target_dest,
    )
    mock_ledger_connector.register_intent(intent)
    req_ok = SigningRequest(
        id="req-m1",
        raw_tx=raw_tx,
        chain="ethereum",
        wallet=target_dest,
        intent_id="intent-metrics-ok",
    )
    check_intent(req_ok, decoded, mock_ledger_connector)

    # 2. Unmatched: INTENT_MISSING
    req_bad1 = SigningRequest(
        id="req-m2",
        raw_tx=raw_tx,
        chain="ethereum",
        wallet=target_dest,
        intent_id="intent-ghost",
    )
    check_intent(req_bad1, decoded, mock_ledger_connector)

    # 3. Unmatched: INTENT_NOT_APPROVED
    intent_pending = WithdrawalIntent(
        id="intent-metrics-pending",
        status=IntentStatus.PENDING.value,
        chain="ethereum",
        asset="ETH",
        amount="1000",
        destination=target_dest,
    )
    mock_ledger_connector.register_intent(intent_pending)
    req_bad2 = SigningRequest(
        id="req-m3",
        raw_tx=raw_tx,
        chain="ethereum",
        wallet=target_dest,
        intent_id="intent-metrics-pending",
    )
    check_intent(req_bad2, decoded, mock_ledger_connector)

    # Query metrics via API
    metrics_res = client.get("/v1/metrics/intent")
    assert metrics_res.status_code == 200
    data = metrics_res.json()

    assert data["total_intent_checks"] == 3
    assert data["unmatched_intent_checks"] == 2
    assert data["matched_intent_checks"] == 1
    # 2 / 3 = 0.6667
    assert data["unmatched_request_rate"] == 0.6667
    assert data["reasons_breakdown"]["INTENT_MISSING"] == 1
    assert data["reasons_breakdown"]["INTENT_NOT_APPROVED"] == 1


def test_ledger_mock_fastapi_endpoints():
    """Verify services/ledger_mock endpoints for creating, approving, consuming, and listing intents."""
    # 1. Create intent
    create_payload = {
        "id": "intent-test-mock-01",
        "chain": "ethereum",
        "asset": "USDC",
        "amount": "50000000",
        "destination": "0x9999999999999999999999999999999999999999",
        "status": "PENDING",
    }
    res_create = ledger_client.post("/intents", json=create_payload)
    assert res_create.status_code == 201
    created = res_create.json()
    assert created["id"] == "intent-test-mock-01"
    assert created["status"] == "PENDING"

    # 2. Get intent (read-only)
    res_get = ledger_client.get("/intents/intent-test-mock-01")
    assert res_get.status_code == 200
    assert res_get.json()["asset"] == "USDC"

    # 3. Approve intent
    res_approve = ledger_client.post("/intents/intent-test-mock-01/approve")
    assert res_approve.status_code == 200
    assert res_approve.json()["status"] == "APPROVED"

    # 4. Consume intent
    res_consume = ledger_client.post("/intents/intent-test-mock-01/consume")
    assert res_consume.status_code == 200
    assert res_consume.json()["status"] == "PAID"
    assert res_consume.json()["consumed_at"] is not None

    # 5. Second consume returns 409 Conflict
    res_consume_repeat = ledger_client.post("/intents/intent-test-mock-01/consume")
    assert res_consume_repeat.status_code == 409

    # 6. List intents
    res_list = ledger_client.get("/intents")
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 1
