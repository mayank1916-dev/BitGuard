"""Integration and contract tests for JSON-RPC 2.0 Signing Gateway (Milestone S12).

Tests:
1. Normal withdrawal signed (valid mTLS + intent + limits -> signature)
2. Over-limit withdrawal is HOLD (-32004 with hold_id)
3. No-intent withdrawal is DENY (-32003 with INTENT_MISSING)
4. Missing client certificate is DENY (-32003 with INVALID_CALLER_IDENTITY)
5. Direct call to shim without BitGuard is refused
6. Demo custody client execution
7. Internal engine error fail-closed handling (never leaks signature)
8. JSON-RPC 2.0 protocol error handling (-32700, -32600, -32601, -32602)
9. mTLS CA cryptographic verification and rogue cert rejection
"""

from pathlib import Path
from unittest.mock import patch

import fakeredis
import httpx
import pytest
import rlp
from fastapi.testclient import TestClient

from lab.demo_custody.client import CustodyClientRpcError, DemoCustodyClient
from lab.scripts.make_dev_ca import generate_dev_pki
from services.bitguard.config import settings
from services.bitguard.gateway.client_shim import signer_shim_client
from services.bitguard.gateway.handler import quarantine_store
from services.bitguard.ledger.mock import mock_ledger_connector
from services.bitguard.ledger.models import IntentStatus, WithdrawalIntent
from services.bitguard.limits.store import limit_store
from services.bitguard.main import app
from services.bitguard.mode_service import mode_service
from services.bitguard.models import OperationMode
from services.signer_shim.main import app as shim_app
from services.signer_shim.main import init_public_key_set
from services.signer_shim.nonce_store import nonce_store

client = TestClient(app)

BENIGN_DEST = "0x1111111111111111111111111111111111111111"
BENIGN_DEST_RAW = "1111111111111111111111111111111111111111"
VALID_SAN_HEADERS = {"X-Client-Cert-SAN": "spiffe://exchange.internal/workload/custody"}


def build_raw_legacy_tx(to_hex: str = BENIGN_DEST_RAW, value: int = 1000) -> str:
    """Helper constructing a canonical raw unsigned legacy EVM transaction hex."""
    clean_hex = to_hex[2:] if to_hex.startswith("0x") else to_hex
    payload = [0, 20_000_000_000, 21000, bytes.fromhex(clean_hex), value, b""]
    return "0x" + rlp.encode(payload).hex()


@pytest.fixture(autouse=True)
def setup_gateway_test_env(tmp_path: Path):
    """Sets up an isolated test environment with fake Redis and in-memory shim transport."""
    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    limit_store.set_redis_client(fake_redis)
    nonce_store.set_redis_client(fake_redis)
    init_public_key_set()

    # Wire in-memory transport to the signer shim FastAPI app
    signer_shim_client.transport = httpx.ASGITransport(app=shim_app)

    # Set default wallet group to ENFORCE mode for deterministic binding tests
    default_group = mode_service.get_wallet_group("default")
    default_group.mode = OperationMode.ENFORCE

    # Reset ledger and quarantine stores
    mock_ledger_connector.reset()
    quarantine_store.clear()

    yield

    mock_ledger_connector.reset()
    quarantine_store.clear()


def test_normal_withdrawal_signed():
    """Test 1: Normal authorized withdrawal within limits is signed successfully."""
    raw_tx = build_raw_legacy_tx(value=1000)
    intent_id = "intent-normal-01"

    # Register pre-approved withdrawal intent
    intent = WithdrawalIntent(
        id=intent_id,
        status=IntentStatus.APPROVED.value,
        chain="ethereum",
        asset="ETH",
        amount="1000",
        destination=BENIGN_DEST,
    )
    mock_ledger_connector.register_intent(intent)

    rpc_payload = {
        "jsonrpc": "2.0",
        "method": "bitguard_signTransaction",
        "params": {
            "chain": "ethereum",
            "raw_tx": raw_tx,
            "intent_id": intent_id,
            "amount_usd": 1500.0,
        },
        "id": 101,
    }

    resp = client.post("/rpc", json=rpc_payload, headers=VALID_SAN_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["jsonrpc"] == "2.0"
    assert data["id"] == 101
    assert data["error"] is None

    result = data["result"]
    assert result is not None
    assert result["status"] == "SIGNED"
    assert result["signature"].startswith("0x")
    assert len(result["signature"]) >= 130
    assert result["decision_id"].startswith("req-")
    assert result["tx_hash"].startswith("0x")

    # Verify intent was consumed idempotently
    assert mock_ledger_connector.is_consumed(intent_id)


def test_over_limit_withdrawal_is_hold():
    """Test 2: Withdrawal exceeding the single tx threshold is quarantined on HOLD."""
    raw_tx = build_raw_legacy_tx(value=5000)
    intent_id = "intent-overlimit-01"

    intent = WithdrawalIntent(
        id=intent_id,
        status=IntentStatus.APPROVED.value,
        chain="ethereum",
        asset="ETH",
        amount="5000",
        destination=BENIGN_DEST,
    )
    mock_ledger_connector.register_intent(intent)

    # USD amount ($75,000) exceeds default single tx threshold ($50,000)
    rpc_payload = {
        "jsonrpc": "2.0",
        "method": "bitguard_signTransaction",
        "params": {
            "chain": "ethereum",
            "raw_tx": raw_tx,
            "intent_id": intent_id,
            "amount_usd": 75_000.0,
        },
        "id": 102,
    }

    resp = client.post("/rpc", json=rpc_payload, headers=VALID_SAN_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["result"] is None
    assert data["error"] is not None

    err = data["error"]
    assert err["code"] == -32004  # Quarantine HOLD error code
    assert "HOLD" in err["message"]

    err_data = err["data"]
    assert err_data["hold_id"].startswith("ht-req-")
    assert err_data["hold_id"] in quarantine_store
    assert any(r["code"] == "SINGLE_TX_LIMIT_EXCEEDED" for r in err_data["reasons"])
    assert err_data["risk_score"] >= 50

    # Ensure intent was NOT consumed
    assert not mock_ledger_connector.is_consumed(intent_id)


def test_no_intent_is_deny():
    """Test 3: Withdrawal without a valid intent is fail-closed DENIED."""
    raw_tx = build_raw_legacy_tx(value=1000)

    # Provide an invented / nonexistent intent ID
    rpc_payload = {
        "jsonrpc": "2.0",
        "method": "bitguard_signTransaction",
        "params": {
            "chain": "ethereum",
            "raw_tx": raw_tx,
            "intent_id": "nonexistent-intent-999",
            "amount_usd": 150.0,
        },
        "id": 103,
    }

    resp = client.post("/rpc", json=rpc_payload, headers=VALID_SAN_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["result"] is None
    assert data["error"] is not None

    err = data["error"]
    assert err["code"] == -32003  # DENIED error code
    assert any(r["code"] == "INTENT_MISSING" for r in err["data"]["reasons"])
    assert err["data"]["risk_score"] == 100


def test_missing_client_cert_is_deny():
    """Test 4: Request without mTLS client certificate / SAN is DENIED immediately."""
    raw_tx = build_raw_legacy_tx(value=1000)

    rpc_payload = {
        "jsonrpc": "2.0",
        "method": "bitguard_signTransaction",
        "params": {
            "chain": "ethereum",
            "raw_tx": raw_tx,
            "intent_id": "intent-101",
        },
        "id": 104,
    }

    # No mTLS headers passed
    resp = client.post("/rpc", json=rpc_payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["result"] is None
    assert data["error"] is not None
    assert data["error"]["code"] == -32003
    assert any(r["code"] == "INVALID_CALLER_IDENTITY" for r in data["error"]["data"]["reasons"])


def test_direct_call_to_shim_without_bitguard_is_refused():
    """Test 5: Signer shim refuses direct calls without valid BitGuard approval token or internal ACL."""
    shim_test_client = TestClient(shim_app)
    raw_tx = build_raw_legacy_tx(value=1000)

    # Direct call without ACL header
    resp = shim_test_client.post(
        "/sign",
        json={"raw_tx_bytes": raw_tx, "token": "dummy-token"},
    )
    assert resp.status_code == 403

    # Direct call with ACL header but missing token
    resp_with_acl = shim_test_client.post(
        "/sign",
        headers={"X-BitGuard-Internal-Auth": settings.signer_shim_internal_auth_token},
        json={"raw_tx_bytes": raw_tx, "token": ""},
    )
    assert resp_with_acl.status_code == 400
    assert resp_with_acl.json()["reason_code"] == "MISSING_APPROVAL_TOKEN"


def test_demo_custody_client_execution():
    """Test 6: lab/demo_custody client executes requests and handles result / errors."""
    raw_tx = build_raw_legacy_tx(value=2000)
    intent_id = "intent-custody-demo"

    intent = WithdrawalIntent(
        id=intent_id,
        status=IntentStatus.APPROVED.value,
        chain="ethereum",
        asset="ETH",
        amount="2000",
        destination=BENIGN_DEST,
    )
    mock_ledger_connector.register_intent(intent)

    # Create demo client routing to in-memory FastAPI app
    custody_client = DemoCustodyClient(
        base_url="http://testserver",
        transport=httpx.ASGITransport(app=app),
        san="spiffe://exchange.internal/workload/custody",
    )

    # Case A: Normal signing succeeds
    res = custody_client.sign_transaction(
        chain="ethereum",
        raw_tx=raw_tx,
        intent_id=intent_id,
        amount_usd=1000.0,
    )
    assert res["status"] == "SIGNED"
    assert "signature" in res

    # Case B: Over-limit raises CustodyClientRpcError (-32004)
    intent_hold = WithdrawalIntent(
        id="intent-hold-demo",
        status=IntentStatus.APPROVED.value,
        chain="ethereum",
        asset="ETH",
        amount="2000",
        destination=BENIGN_DEST,
    )
    mock_ledger_connector.register_intent(intent_hold)

    with pytest.raises(CustodyClientRpcError) as exc_info:
        custody_client.sign_transaction(
            chain="ethereum",
            raw_tx=raw_tx,
            intent_id="intent-hold-demo",
            amount_usd=90_000.0,
        )
    assert exc_info.value.code == -32004
    assert exc_info.value.data["hold_id"].startswith("ht-req-")


def test_engine_internal_error_fails_closed():
    """Test 7: Unhandled engine exceptions fail closed with ENGINE_ERROR and never leak signatures."""
    raw_tx = build_raw_legacy_tx(value=1000)
    intent_id = "intent-crash-01"

    intent = WithdrawalIntent(
        id=intent_id,
        status=IntentStatus.APPROVED.value,
        chain="ethereum",
        asset="ETH",
        amount="1000",
        destination=BENIGN_DEST,
    )
    mock_ledger_connector.register_intent(intent)

    rpc_payload = {
        "jsonrpc": "2.0",
        "method": "bitguard_signTransaction",
        "params": {
            "chain": "ethereum",
            "raw_tx": raw_tx,
            "intent_id": intent_id,
        },
        "id": 107,
    }

    # Simulate unexpected runtime exception inside decision_engine.evaluate
    with patch("services.bitguard.gateway.handler.decision_engine.evaluate", side_effect=RuntimeError("Simulated pipeline crash")):
        resp = client.post("/rpc", json=rpc_payload, headers=VALID_SAN_HEADERS)

    assert resp.status_code == 200
    data = resp.json()

    assert data["result"] is None
    assert data["error"] is not None
    assert data["error"]["code"] == -32003
    assert any(r["code"] == "ENGINE_ERROR" for r in data["error"]["data"]["reasons"])


def test_json_rpc_protocol_errors():
    """Test 8: Validates JSON-RPC 2.0 protocol error codes (-32700, -32600, -32601, -32602)."""
    # 1. Parse error / empty payload (-32700)
    resp = client.post("/rpc", content=b"", headers={"Content-Type": "application/json"})
    assert resp.status_code == 200
    assert resp.json()["error"]["code"] == -32700

    # 2. Invalid Request: not an object (-32600)
    resp = client.post("/rpc", json=["not", "an", "object"])
    assert resp.status_code == 200
    assert resp.json()["error"]["code"] == -32600

    # 3. Method not found (-32601)
    resp = client.post("/rpc", json={"jsonrpc": "2.0", "method": "unknown_method", "id": 1})
    assert resp.status_code == 200
    assert resp.json()["error"]["code"] == -32601

    # 4. Invalid params (-32602)
    resp = client.post(
        "/rpc",
        json={"jsonrpc": "2.0", "method": "bitguard_signTransaction", "params": "not-a-dict", "id": 2},
    )
    assert resp.status_code == 200
    assert resp.json()["error"]["code"] == -32602


def test_mtls_ca_cryptographic_verification(tmp_path: Path):
    """Test 9: Verifies client certificates against Dev Root CA and rejects untrusted rogue certificates."""
    pki = generate_dev_pki(tmp_path)

    # Configure CA path for gateway verification
    with patch.object(settings, "mtls_ca_cert_path", pki["ca_cert"]):
        raw_tx = build_raw_legacy_tx(value=1000)
        intent = WithdrawalIntent(
            id="intent-mtls-pki",
            status=IntentStatus.APPROVED.value,
            chain="ethereum",
            asset="ETH",
            amount="1000",
            destination=BENIGN_DEST,
        )
        mock_ledger_connector.register_intent(intent)

        # Case A: Legitimate client cert signed by CA succeeds
        legit_cert_pem = Path(pki["client_cert"]).read_text(encoding="utf-8")
        resp_legit = client.post(
            "/rpc",
            json={
                "jsonrpc": "2.0",
                "method": "bitguard_signTransaction",
                "params": {"chain": "ethereum", "raw_tx": raw_tx, "intent_id": "intent-mtls-pki"},
                "id": 201,
            },
            headers={"X-Client-Cert-Pem": legit_cert_pem},
        )
        assert resp_legit.status_code == 200
        assert resp_legit.json()["result"]["status"] == "SIGNED"

        # Case B: Rogue client cert signed by untrusted rogue CA is rejected
        rogue_cert_pem = Path(pki["rogue_cert"]).read_text(encoding="utf-8")
        resp_rogue = client.post(
            "/rpc",
            json={
                "jsonrpc": "2.0",
                "method": "bitguard_signTransaction",
                "params": {"chain": "ethereum", "raw_tx": raw_tx, "intent_id": "intent-mtls-pki"},
                "id": 202,
            },
            headers={"X-Client-Cert-Pem": rogue_cert_pem},
        )
        assert resp_rogue.status_code == 200
        assert resp_rogue.json()["result"] is None
        assert resp_rogue.json()["error"]["code"] == -32003
        assert any(r["code"] == "INVALID_CALLER_IDENTITY" for r in resp_rogue.json()["error"]["data"]["reasons"])
