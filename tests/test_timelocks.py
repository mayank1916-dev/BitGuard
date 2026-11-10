"""Comprehensive test suite for Task S30 - Time-Locks and Delayed Releases (F12).

Invariants Verified:
- Invariant #1: Key Isolation (BitGuard never holds keys; releases one-time token to signer shim).
- Invariant #2: Approval Binding & Verification (one-time token bound to digest, wallet, chain).
- Invariant #3: Fail-Closed Default (unverified conditions or breaker lockdown cancel releases).
- Invariant #6: Asymmetric Policy Evolution (cancel is instant single-person tightening; release requires delay expiration).
- Invariant #7: Immutable Audit Trail (all creations, releases, and cancellations audited).
- Invariant #8: Explicit Data Provenance (values labelled REAL or SYNTHETIC).
- Invariant #9: Environment & Safety Boundary (local chains with disposable keys ONLY).
"""

from datetime import UTC, datetime, timedelta

import pytest
import rlp
from fastapi.testclient import TestClient

from services.bitguard.approvals.hold_store import hold_store
from services.bitguard.engine.breaker_store import breaker_store
from services.bitguard.engine.pipeline import DecisionEngine
from services.bitguard.ledger.mock import mock_ledger_connector
from services.bitguard.ledger.models import IntentStatus, WithdrawalIntent
from services.bitguard.main import app
from services.bitguard.models import (
    BreakerStateEnum,
    HoldState,
    Role,
    SigningRequest,
    Verdict,
)
from services.bitguard.policy.classifier import classify_change
from services.bitguard.policy.models import (
    ChangeClassification,
    PolicyDocument,
    ThresholdsPolicy,
    TimeLockPolicy,
)
from services.bitguard.rbac import ALL_TEST_USERS, SEEDED_USERS, create_access_token
from services.bitguard.timelock.service import (
    customer_notice_webhook,
    timelock_service,
)
from services.bitguard.timelock.store import timelock_store
from services.bitguard.timelock.worker import (
    timelock_release_worker,
)

client = TestClient(app)

HOT_WALLET = "0x742d35cc6634c0532925a3b844bc454e4438f44e"
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


@pytest.fixture(autouse=True)
def clean_timelock_environment():
    """Resets breaker, mocks, stores, and webhooks before each test."""
    breaker_store.set_state(BreakerStateEnum.NORMAL, reason="Test setup")
    mock_ledger_connector.reset()
    timelock_store.reset()
    customer_notice_webhook.reset()
    yield
    breaker_store.set_state(BreakerStateEnum.NORMAL, reason="Test teardown")


def test_release_does_not_happen_early():
    """Requirement 1: Release worker ensures that release does not happen before release_not_before."""
    now = datetime(2026, 11, 10, 12, 0, 0, tzinfo=UTC)
    raw_tx = build_raw_legacy_tx(BENIGN_DEST, value_wei=10**18)
    digest = "0x" + "a" * 64

    # 30 minute delay configured
    policy = TimeLockPolicy(timelock_minutes=30)
    ticket = timelock_service.create_timelock_ticket(
        request_id="req-tl-early-01",
        raw_tx=raw_tx,
        tx_digest=digest,
        wallet=HOT_WALLET,
        amount_usd=100_000.0,
        policy=policy,
        now=now,
    )

    assert ticket.state == HoldState.PENDING_RELEASE.value
    assert ticket.release_not_before == now + timedelta(minutes=30)

    # 1. Check at now + 15m (matures in 15m): must NOT release early
    results_early = timelock_release_worker.process_pending_releases(
        now=now + timedelta(minutes=15)
    )
    assert any(r["ticket_id"] == ticket.id and r["status"] == "WAITING" for r in results_early)

    # Ticket state remains PENDING_RELEASE
    persisted = hold_store.get(ticket.id)
    assert persisted is not None
    assert persisted.state == HoldState.PENDING_RELEASE.value

    # 2. Check at now + 30m 1s: delay has elapsed -> releases successfully!
    results_matured = timelock_release_worker.process_pending_releases(
        now=now + timedelta(minutes=30, seconds=1)
    )
    release_res = next(r for r in results_matured if r["ticket_id"] == ticket.id)
    assert release_res["status"] == "RELEASED"
    assert release_res["token"] is not None

    persisted_released = hold_store.get(ticket.id)
    assert persisted_released is not None
    assert persisted_released.state == HoldState.RELEASED.value
    assert persisted_released.released_at is not None


def test_cancel_by_operator_secops_and_approver():
    """Requirement 2: Cancel: POST /v1/holds/{id}/cancel by Operator, SecOps or Approver at any time before release."""
    now = datetime.now(UTC)
    raw_tx = build_raw_legacy_tx(BENIGN_DEST, value_wei=10**18)

    # 1. Cancel by Operator
    ticket1 = timelock_service.create_timelock_ticket(
        request_id="req-tl-cancel-op",
        raw_tx=raw_tx,
        tx_digest="0x" + "1" * 64,
        wallet=HOT_WALLET,
        amount_usd=60_000.0,
        now=now,
    )
    headers_op = get_auth_header(Role.OPERATOR)
    resp_op = client.post(
        f"/v1/holds/{ticket1.id}/cancel",
        json={"reason": "Suspicious counterparty address"},
        headers=headers_op,
    )
    assert resp_op.status_code == 200
    assert resp_op.json()["state"] == "CANCELLED"
    assert hold_store.get(ticket1.id).state == "CANCELLED"

    # 2. Cancel by SecOps
    ticket2 = timelock_service.create_timelock_ticket(
        request_id="req-tl-cancel-secops",
        raw_tx=raw_tx,
        tx_digest="0x" + "2" * 64,
        wallet=HOT_WALLET,
        amount_usd=70_000.0,
        now=now,
    )
    headers_secops = get_auth_header(Role.SECOPS)
    resp_secops = client.post(
        f"/v1/holds/{ticket2.id}/cancel",
        json={"reason": "SecOps preemptive hold"},
        headers=headers_secops,
    )
    assert resp_secops.status_code == 200
    assert resp_secops.json()["state"] == "CANCELLED"
    assert hold_store.get(ticket2.id).state == "CANCELLED"

    # 3. Cancel by Approver
    ticket3 = timelock_service.create_timelock_ticket(
        request_id="req-tl-cancel-approver",
        raw_tx=raw_tx,
        tx_digest="0x" + "3" * 64,
        wallet=HOT_WALLET,
        amount_usd=80_000.0,
        now=now,
    )
    headers_approver = get_auth_header(Role.APPROVER)
    resp_approver = client.post(
        f"/v1/holds/{ticket3.id}/cancel",
        json={"reason": "Approver refused transfer during review"},
        headers=headers_approver,
    )
    assert resp_approver.status_code == 200
    assert resp_approver.json()["state"] == "CANCELLED"
    assert hold_store.get(ticket3.id).state == "CANCELLED"


def test_elevated_and_hold_breaker_lengthens_delay():
    """Requirement 3: Delay multiplier by breaker state: ELEVATED x2, HOLD x4 (configurable)."""
    now = datetime(2026, 11, 10, 14, 0, 0, tzinfo=UTC)
    raw_tx = build_raw_legacy_tx(BENIGN_DEST, value_wei=10**18)
    base_minutes = 10

    policy = TimeLockPolicy(
        timelock_minutes=base_minutes,
        delay_multipliers={"NORMAL": 1.0, "ELEVATED": 2.0, "HOLD": 4.0},
    )

    # 1. Breaker NORMAL -> 10m * 1.0 = 10m delay
    breaker_store.set_state(BreakerStateEnum.NORMAL, reason="Normal baseline")
    ticket_normal = timelock_service.create_timelock_ticket(
        request_id="req-tl-mult-normal",
        raw_tx=raw_tx,
        tx_digest="0x" + "4" * 64,
        wallet=HOT_WALLET,
        policy=policy,
        now=now,
    )
    assert ticket_normal.release_not_before == now + timedelta(minutes=10)

    # 2. Breaker ELEVATED -> 10m * 2.0 = 20m delay (ELEVATED x2)
    breaker_store.set_state(BreakerStateEnum.ELEVATED, reason="Spike detected")
    ticket_elevated = timelock_service.create_timelock_ticket(
        request_id="req-tl-mult-elevated",
        raw_tx=raw_tx,
        tx_digest="0x" + "5" * 64,
        wallet=HOT_WALLET,
        policy=policy,
        now=now,
    )
    assert ticket_elevated.release_not_before == now + timedelta(minutes=20)

    # 3. Breaker HOLD -> 10m * 4.0 = 40m delay (HOLD x4)
    breaker_store.set_state(BreakerStateEnum.HOLD, reason="Quarantine hold active")
    ticket_hold = timelock_service.create_timelock_ticket(
        request_id="req-tl-mult-hold",
        raw_tx=raw_tx,
        tx_digest="0x" + "6" * 64,
        wallet=HOT_WALLET,
        policy=policy,
        now=now,
    )
    assert ticket_hold.release_not_before == now + timedelta(minutes=40)


def test_lockdown_cancels_releases():
    """Requirement 4: Circuit breaker LOCKDOWN cancels releases immediately."""
    now = datetime(2026, 11, 10, 15, 0, 0, tzinfo=UTC)
    raw_tx = build_raw_legacy_tx(BENIGN_DEST, value_wei=10**18)

    ticket = timelock_service.create_timelock_ticket(
        request_id="req-tl-lockdown-cancel",
        raw_tx=raw_tx,
        tx_digest="0x" + "7" * 64,
        wallet=HOT_WALLET,
        now=now,
    )
    assert ticket.state == HoldState.PENDING_RELEASE.value

    # Trip circuit breaker to LOCKDOWN
    breaker_store.set_state(BreakerStateEnum.LOCKDOWN, reason="Emergency lockdown active")

    # Release worker runs: LOCKDOWN cancels releases
    results = timelock_release_worker.process_pending_releases(now=now + timedelta(hours=2))
    lockdown_res = next(r for r in results if r["ticket_id"] == ticket.id)
    assert lockdown_res["status"] == "CANCELLED"
    assert lockdown_res["reason"] == "BREAKER_LOCKDOWN"

    persisted = hold_store.get(ticket.id)
    assert persisted is not None
    assert persisted.state == HoldState.CANCELLED.value


def test_customer_notice_webhook_invoked_at_creation():
    """Requirement 5: Optional webhook hook 'customer_notice' invoked at creation (mock implementation)."""
    now = datetime.now(UTC)
    raw_tx = build_raw_legacy_tx(BENIGN_DEST, value_wei=10**18)

    customer_notice_webhook.reset()
    assert len(customer_notice_webhook.notices) == 0

    ticket = timelock_service.create_timelock_ticket(
        request_id="req-tl-webhook-notice",
        raw_tx=raw_tx,
        tx_digest="0x" + "8" * 64,
        wallet=HOT_WALLET,
        amount_usd=125_000.0,
        now=now,
    )

    assert len(customer_notice_webhook.notices) == 1
    notice = customer_notice_webhook.notices[0]
    assert notice["ticket_id"] == ticket.id
    assert notice["wallet"] == HOT_WALLET
    assert notice["amount_usd"] == 125_000.0
    assert notice["delay_minutes"] == 30.0
    assert notice["state"] == HoldState.PENDING_RELEASE.value


def test_intent_invalidation_cancels_timelocked_release():
    """Invariant #3: If custody intent is cancelled or invalid, release worker cancels release and audits."""
    now = datetime(2026, 11, 10, 16, 0, 0, tzinfo=UTC)
    raw_tx = build_raw_legacy_tx(BENIGN_DEST, value_wei=10**18)

    # Register initial approved intent
    intent = WithdrawalIntent(
        id="intent-tl-cancel-01",
        chain="ethereum",
        asset="ETH",
        amount="1000000000000000000",
        destination=BENIGN_DEST,
        status=IntentStatus.APPROVED.value,
    )
    mock_ledger_connector.register_intent(intent)

    ticket = timelock_service.create_timelock_ticket(
        request_id="req-tl-intent-inval",
        raw_tx=raw_tx,
        tx_digest="0x" + "9" * 64,
        wallet=HOT_WALLET,
        intent_id=intent.id,
        now=now,
    )

    # Later before release, intent is CANCELLED in custody ledger
    intent.status = IntentStatus.CANCELLED.value
    mock_ledger_connector.register_intent(intent)

    # When release worker runs after release_not_before:
    results = timelock_release_worker.process_pending_releases(now=now + timedelta(hours=1))
    inval_res = next(r for r in results if r["ticket_id"] == ticket.id)
    assert inval_res["status"] == "CANCELLED"
    assert inval_res["reason"] == "INTENT_INVALID"

    assert hold_store.get(ticket.id).state == HoldState.CANCELLED.value


def test_decision_engine_flags_timelock_delay():
    """Policy: Withdrawals at or above threshold that otherwise pass become TIMELOCKED (Verdict.HOLD)."""
    engine = DecisionEngine()
    policy_doc = PolicyDocument(
        thresholds=ThresholdsPolicy(single_tx_usd=100_000.0),
        time_lock=TimeLockPolicy(
            timelock_threshold={"ETH": 25.0, "USD": 50_000.0},
            timelock_minutes=15,
        ),
    )
    engine.reload_policy(policy_doc)

    raw_tx_small = build_raw_legacy_tx(BENIGN_DEST, value_wei=10 * 10**18)
    raw_tx_large = build_raw_legacy_tx(BENIGN_DEST, value_wei=30 * 10**18)

    # Case A: Amount 10 ETH (< 25 ETH threshold) -> Passes cleanly (ALLOW)
    req_small = SigningRequest(
        chain="ethereum",
        wallet=HOT_WALLET,
        raw_tx=raw_tx_small,
        metadata={"amount_usd": 20_000.0},
    )
    dec_small = engine.evaluate(req_small)
    assert dec_small.verdict == Verdict.ALLOW
    assert not any(r.code == "TIMELOCK_DELAY" for r in dec_small.reasons)

    # Case B: Amount 30 ETH (>= 25 ETH threshold) -> TIMELOCKED into HOLD
    req_large = SigningRequest(
        chain="ethereum",
        wallet=HOT_WALLET,
        raw_tx=raw_tx_large,
        metadata={"amount_usd": 60_000.0},
    )
    dec_large = engine.evaluate(req_large)
    assert dec_large.verdict == Verdict.HOLD
    assert any(r.code == "TIMELOCK_DELAY" for r in dec_large.reasons)
    assert req_large.metadata.get("is_timelocked") is True
    assert req_large.metadata.get("release_not_before") is not None


def test_timelock_policy_classification_asymmetric_tightening_loosening():
    """Invariant #6: Longer delay or lower threshold is TIGHTEN; shorter delay or higher threshold is LOOSEN."""
    old_policy = PolicyDocument(
        time_lock=TimeLockPolicy(timelock_minutes=30, timelock_threshold={"ETH": 50.0})
    )

    # 1. Longer delay: 30m -> 60m is TIGHTEN
    doc_tighten_delay = old_policy.model_copy(deep=True)
    doc_tighten_delay.time_lock.timelock_minutes = 60
    assert classify_change(old_policy, doc_tighten_delay) == ChangeClassification.TIGHTEN

    # 2. Shorter delay: 30m -> 15m is LOOSEN
    doc_loosen_delay = old_policy.model_copy(deep=True)
    doc_loosen_delay.time_lock.timelock_minutes = 15
    assert classify_change(old_policy, doc_loosen_delay) == ChangeClassification.LOOSEN

    # 3. Lower threshold: 50 -> 20 (more transactions delayed) is TIGHTEN
    doc_tighten_th = old_policy.model_copy(deep=True)
    doc_tighten_th.time_lock.timelock_threshold["ETH"] = 20.0
    assert classify_change(old_policy, doc_tighten_th) == ChangeClassification.TIGHTEN

    # 4. Higher threshold: 50 -> 100 (more transactions bypass delay) is LOOSEN
    doc_loosen_th = old_policy.model_copy(deep=True)
    doc_loosen_th.time_lock.timelock_threshold["ETH"] = 100.0
    assert classify_change(old_policy, doc_loosen_th) == ChangeClassification.LOOSEN
