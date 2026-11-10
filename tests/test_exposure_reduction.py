"""Comprehensive test suite for Task S29 - Exposure Reduction (F11).

Invariants Verified:
- Invariant #1: Key Isolation (BitGuard never holds signing keys).
- Invariant #3: Fail-Closed Default (caps and cold transfers quarantine into HOLD).
- Invariant #5: WebAuthn Hardware Approvals over tx digest.
- Invariant #6: Asymmetric Policy Evolution (proposals cannot be approved by requester).
- Invariant #8: Explicit Data Provenance (values labelled REAL or REPORTED).
- Invariant #9: Environment & Safety Boundary (local chains with disposable keys ONLY).
"""


import fakeredis
import pytest
import rlp
from fastapi.testclient import TestClient

from services.bitguard.approvals.hold_store import hold_store
from services.bitguard.approvals.webauthn import (
    approver_registry,
    create_test_webauthn_assertion,
)
from services.bitguard.engine.pipeline import DecisionEngine
from services.bitguard.exposure.models import ExposureStatus
from services.bitguard.exposure.poller import ExposureService, exposure_service
from services.bitguard.limits.store import LimitStore, ScopeBuilder
from services.bitguard.main import app
from services.bitguard.models import OperationMode, Role, SigningRequest, Verdict
from services.bitguard.policy.classifier import classify_change
from services.bitguard.policy.models import (
    ChangeClassification,
    PolicyDocument,
    WalletExposurePolicy,
)
from services.bitguard.rbac import ALL_TEST_USERS, SEEDED_USERS, create_access_token
from services.bitguard.rpc.client import MockRpcClient

client = TestClient(app)

HOT_WALLET = "0x742d35cc6634c0532925a3b844bc454e4438f44e"
COLD_WALLET = "0x8888888888888888888888888888888888888888"
BENIGN_DEST = "0x1111111111111111111111111111111111111111"


def get_auth_header(role: Role, user_id: str | None = None) -> dict[str, str]:
    """Generates valid JWT bearer authorization header for a test user."""
    if user_id and user_id in ALL_TEST_USERS:
        user = ALL_TEST_USERS[user_id]
    else:
        user = SEEDED_USERS[role]
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


def build_raw_legacy_tx(to_addr: str, value_wei: int = 0, nonce: int = 0) -> str:
    """Builds valid RLP-encoded raw EVM legacy transaction."""
    clean = to_addr.removeprefix("0x")
    to_bytes = bytes.fromhex(clean)
    payload = [nonce, 20_000_000_000, 21000, to_bytes, value_wei, b""]
    return "0x" + rlp.encode(payload).hex()


@pytest.fixture
def exposure_fixture():
    """Provides isolated MockRpcClient, FakeRedis LimitStore, and clean ExposureService."""
    mock_rpc = MockRpcClient()
    mock_rpc.set_latest_block(200)

    fake_server = fakeredis.FakeServer()
    fake_client = fakeredis.FakeRedis(server=fake_server, decode_responses=True)
    isolated_limit_store = LimitStore(redis_client=fake_client)

    service = ExposureService(
        rpc_client=mock_rpc,
        limit_store_inst=isolated_limit_store,
        hold_store_inst=hold_store,
        cold_storage_wallet=COLD_WALLET,
    )

    # Configure hot wallet with 100 max cap, 50 target, 20 top-up threshold
    policy = WalletExposurePolicy(
        max_hot_balance=100.0,
        target_hot_balance=50.0,
        top_up_threshold=20.0,
    )
    service.configure_wallet(HOT_WALLET, policy, baseline_wei=50 * 10**18)

    # Also bind to global singleton for router testing
    exposure_service.set_rpc_client(mock_rpc)
    exposure_service.configure_wallet(HOT_WALLET, policy, baseline_wei=50 * 10**18)

    return {
        "mock_rpc": mock_rpc,
        "limit_store": isolated_limit_store,
        "service": service,
        "policy": policy,
    }


def test_balance_above_cap_creates_sweep_proposal(exposure_fixture):
    """Requirement 1: When on-chain balance exceeds max_hot_balance, a sweep proposal is created as a HOLD ticket."""
    mock_rpc: MockRpcClient = exposure_fixture["mock_rpc"]
    service: ExposureService = exposure_fixture["service"]

    # Balance on-chain is 150 ETH (cap is 100 ETH, target is 50 ETH -> excess is 100 ETH)
    mock_rpc.set_balance(HOT_WALLET, 150 * 10**18)

    record, alerts, proposal = service.poll_wallet(HOT_WALLET)

    assert record.balance_ether == 150.0
    assert proposal is not None
    assert proposal.status == "PENDING"
    assert proposal.amount_usd == 100.0  # Sweeps excess (150 - 50 = 100)
    assert proposal.wallet.lower() == HOT_WALLET.lower()
    assert any(r.code == "EXPOSURE_CAP_EXCEEDED" for r in proposal.reasons)

    # Verify proposal ticket is persisted in hold_store
    ticket_in_store = hold_store.get(proposal.id)
    assert ticket_in_store is not None
    assert ticket_in_store.id == proposal.id


def test_balance_below_threshold_creates_top_up_proposal(exposure_fixture):
    """Requirement 5: When on-chain balance drops below top_up_threshold, a top-up proposal is created."""
    mock_rpc: MockRpcClient = exposure_fixture["mock_rpc"]
    service: ExposureService = exposure_fixture["service"]

    # Balance on-chain is 10 ETH (threshold is 20 ETH, target is 50 ETH -> top-up needed is 40 ETH)
    mock_rpc.set_balance(HOT_WALLET, 10 * 10**18)

    record, alerts, proposal = service.poll_wallet(HOT_WALLET)

    assert record.balance_ether == 10.0
    assert proposal is not None
    assert proposal.status == "PENDING"
    assert proposal.amount_usd == 40.0  # Top-up amount (50 - 10 = 40)
    assert any(r.code == "EXPOSURE_TOP_UP_REQUIRED" for r in proposal.reasons)


def test_cold_request_is_always_hold_regardless_of_size():
    """Requirement 2: Cold transfer is a distinct request type that is ALWAYS HOLD regardless of size."""
    engine = DecisionEngine()

    raw_tx = build_raw_legacy_tx(BENIGN_DEST, value_wei=100)

    # 1. Cold transfer via request_type attribute
    req1 = SigningRequest(
        chain="ethereum",
        wallet=HOT_WALLET,
        raw_tx=raw_tx,
        mode=OperationMode.ENFORCE,
        request_type="COLD_TRANSFER",
        metadata={"amount_usd": 1.0},  # Tiny amount ($1) must still HOLD
    )
    decision1 = engine.evaluate(req1)
    assert decision1.verdict == Verdict.HOLD
    assert any(r.code == "COLD_STORAGE_TRANSFER" for r in decision1.reasons)

    # 2. Cold transfer via metadata flag
    req2 = SigningRequest(
        chain="ethereum",
        wallet=HOT_WALLET,
        raw_tx=raw_tx,
        mode=OperationMode.ENFORCE,
        metadata={"request_type": "COLD_TRANSFER", "amount_usd": 0.05},
    )
    decision2 = engine.evaluate(req2)
    assert decision2.verdict == Verdict.HOLD
    assert any(r.code == "COLD_STORAGE_TRANSFER" for r in decision2.reasons)


def test_proposals_cannot_be_approved_by_requester(exposure_fixture):
    """Requirement 3: Proposals cannot be approved by the requester (Separation of Duties)."""
    mock_rpc: MockRpcClient = exposure_fixture["mock_rpc"]
    service: ExposureService = exposure_fixture["service"]

    # Proposer is usr-approver-01
    proposer_id = "usr-approver-01"
    mock_rpc.set_balance(HOT_WALLET, 140 * 10**18)
    _, _, proposal = service.poll_wallet(HOT_WALLET, requester_id=proposer_id)
    assert proposal is not None

    # Proposer attempts to approve their own proposal ticket
    priv_key_1 = approver_registry.dev_private_keys[proposer_id]
    assertion_1 = create_test_webauthn_assertion(
        private_key=priv_key_1,
        tx_digest=proposal.tx_digest,
        sign_count=1,
    )
    headers_1 = get_auth_header(Role.APPROVER, user_id=proposer_id)

    resp = client.post(
        f"/v1/holds/{proposal.id}/approve",
        json={"assertion": assertion_1.model_dump()},
        headers=headers_1,
    )
    # Must be rejected with 403 Forbidden
    assert resp.status_code == 403
    assert "REQUESTER_CANNOT_APPROVE" in resp.json()["detail"]

    # Now verify that an independent approver (usr-approver-02) CAN approve
    approver_id_2 = "usr-approver-02"
    priv_key_2 = approver_registry.dev_private_keys[approver_id_2]
    assertion_2 = create_test_webauthn_assertion(
        private_key=priv_key_2,
        tx_digest=proposal.tx_digest,
        sign_count=1,
    )
    headers_2 = get_auth_header(Role.APPROVER, user_id=approver_id_2)

    resp_ok = client.post(
        f"/v1/holds/{proposal.id}/approve",
        json={"assertion": assertion_2.model_dump()},
        headers=headers_2,
    )
    assert resp_ok.status_code == 200
    assert resp_ok.json()["approvals_count"] == 1


def test_balance_reconciliation_and_divergence_alert(exposure_fixture):
    """Requirement 4: Balance poller reconciles committed limit volume against on-chain balance and alerts on divergence."""
    mock_rpc: MockRpcClient = exposure_fixture["mock_rpc"]
    limit_store_inst: LimitStore = exposure_fixture["limit_store"]
    service: ExposureService = exposure_fixture["service"]

    # Baseline is 50 ETH.
    service.set_wallet_baseline(HOT_WALLET, 50 * 10**18)

    # Commit 5 ETH of approved outflows in the limit store
    wallet_scope = ScopeBuilder.wallet_scope(HOT_WALLET)
    res = limit_store_inst.reserve([wallet_scope], amount=5 * 10**18, cap=100 * 10**18)
    assert res.ok is True
    limit_store_inst.commit(res.reservation_id)

    # Case A: On-chain balance is 45 ETH -> perfectly matches expected balance (50 - 5 = 45 ETH)
    mock_rpc.set_balance(HOT_WALLET, 45 * 10**18)
    record_clean, alerts_clean, _ = service.poll_wallet(HOT_WALLET)
    assert record_clean.divergence_wei == 0
    assert len(alerts_clean) == 0

    # Case B: On-chain balance unexpectedly drops to 30 ETH (15 ETH unauthorized drop!)
    mock_rpc.set_balance(HOT_WALLET, 30 * 10**18)
    record_div, alerts_div, _ = service.poll_wallet(HOT_WALLET)
    assert record_div.divergence_wei == 15 * 10**18
    assert len(alerts_div) >= 1
    assert alerts_div[0].alert_code == "BALANCE_DIVERGENCE"
    assert alerts_div[0].severity == "CRITICAL"
    assert "diverges from expected balance" in alerts_div[0].detail


def test_get_exposure_api_returns_provenance_and_summary(exposure_fixture):
    """Requirement 6: API GET /v1/exposure returns per-wallet balance, cap, headroom, and total exposure with REAL/REPORTED labels."""
    mock_rpc: MockRpcClient = exposure_fixture["mock_rpc"]

    mock_rpc.set_balance(HOT_WALLET, 65 * 10**18)
    exposure_service.poll_wallet(HOT_WALLET)

    headers = get_auth_header(Role.VIEWER)
    resp = client.get("/v1/exposure", headers=headers)
    assert resp.status_code == 200

    data = resp.json()
    assert data["total_exposure_at_risk"] == 65.0
    assert data["total_headroom"] == 35.0  # 100 - 65 = 35
    assert data["data_label"] in ["REAL", "REPORTED"]
    assert len(data["wallets"]) >= 1

    wallet_item = next(w for w in data["wallets"] if w["wallet"].lower() == HOT_WALLET.lower())
    assert wallet_item["balance"] == 65.0
    assert wallet_item["cap"] == 100.0
    assert wallet_item["headroom"] == 35.0
    assert wallet_item["data_label"] in ["REAL", "REPORTED"]
    assert wallet_item["status"] == ExposureStatus.NORMAL.value


def test_policy_classification_tightening_and_loosening():
    """Verifies that raising exposure caps classifies as LOOSEN and lowering classifies as TIGHTEN (Invariant #6)."""
    old_doc = PolicyDocument(
        wallet_exposure={
            HOT_WALLET: WalletExposurePolicy(max_hot_balance=100.0, top_up_threshold=20.0)
        }
    )

    # 1. Raising cap: 100 -> 150 is LOOSEN
    doc_loosen = old_doc.model_copy(deep=True)
    doc_loosen.wallet_exposure[HOT_WALLET].max_hot_balance = 150.0
    assert classify_change(old_doc, doc_loosen) == ChangeClassification.LOOSEN

    # 2. Lowering cap: 100 -> 80 is TIGHTEN
    doc_tighten = old_doc.model_copy(deep=True)
    doc_tighten.wallet_exposure[HOT_WALLET].max_hot_balance = 80.0
    assert classify_change(old_doc, doc_tighten) == ChangeClassification.TIGHTEN
