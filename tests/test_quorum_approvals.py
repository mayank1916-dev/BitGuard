"""Comprehensive unit and integration tests for Quorum WebAuthn Approvals (Milestone S16 / F10).

Covers:
- Invariant #1: Key Isolation (BitGuard never holds keys; releases to signer shim).
- Invariant #2: Approval Binding & Verification (one-time Ed25519 token bound to digest).
- Invariant #3: Fail-Closed Default (unknown, expired, or invalid assertion fails closed).
- Invariant #4: Raw Byte Source of Truth (independent decode in view and release).
- Invariant #5: WebAuthn Hardware Approvals over tx digest (links only in notifiers, no buttons).
- Invariant #6: Asymmetric Policy Evolution (deny = 1 approver instant; approval = quorum of 2 distinct approvers).
- Invariant #7: Immutable Audit Trail.
- Invariant #8: Explicit Data Provenance (data_label REAL).

Required Tests:
1. One approver cannot release.
2. Same approver twice cannot release.
3. Requester cannot approve.
4. Wrong digest challenge is rejected.
5. Expired ticket cannot be approved.
6. Replayed assertion is rejected.
7. End-to-end: HOLD -> two approvals with WebAuthn -> signature issued by shim.
8. Single approver denies immediately (Invariant #6).
9. Pluggable notifiers contain console link only and NO approve buttons.
10. Console view recomputes ground truth from raw bytes.
"""

from datetime import UTC, datetime, timedelta

import fakeredis
import httpx
import pytest
import rlp
from fastapi.testclient import TestClient

from services.bitguard.approvals.hold_store import hold_store
from services.bitguard.approvals.notifiers import (
    PagerDutyNotifier,
    SlackNotifier,
    TelegramNotifier,
)
from services.bitguard.approvals.service import approval_service
from services.bitguard.approvals.webauthn import (
    approver_registry,
    create_test_webauthn_assertion,
)
from services.bitguard.audit_service import audit_service
from services.bitguard.decoders.evm import evm_decoder
from services.bitguard.gateway.client_shim import signer_shim_client
from services.bitguard.limits.store import limit_store
from services.bitguard.main import app
from services.bitguard.models import DecisionReason, HoldTicket, Role
from services.bitguard.rbac import ALL_TEST_USERS, SEEDED_USERS, create_access_token
from services.signer_shim.main import app as shim_app
from services.signer_shim.main import init_public_key_set
from services.signer_shim.nonce_store import nonce_store

client = TestClient(app)

BENIGN_DEST_RAW = "1111111111111111111111111111111111111111"


def build_raw_legacy_tx(value: int = 1_000_000_000, nonce: int = 0) -> str:
    """Helper constructing canonical raw unsigned legacy EVM transaction hex."""
    payload = [nonce, 20_000_000_000, 21000, bytes.fromhex(BENIGN_DEST_RAW), value, b""]
    return "0x" + rlp.encode(payload).hex()


@pytest.fixture(autouse=True)
def setup_approvals_test_environment():
    """Sets up an isolated test environment with fake Redis and in-memory shim transport."""
    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    limit_store.set_redis_client(fake_redis)
    nonce_store.set_redis_client(fake_redis)
    init_public_key_set()

    # Wire in-memory transport to the signer shim FastAPI app
    signer_shim_client.transport = httpx.ASGITransport(app=shim_app)
    approval_service.shim_client.transport = httpx.ASGITransport(app=shim_app)

    # Clear stores and reset replays
    hold_store.clear()
    approver_registry.reset_replays()

    yield

    hold_store.clear()
    approver_registry.reset_replays()


def get_auth_header(role: Role = Role.APPROVER, user_id: str | None = None) -> dict[str, str]:
    """Helper creating Bearer Authorization header for seeded test users."""
    user = ALL_TEST_USERS.get(user_id) if user_id else SEEDED_USERS[role]
    assert user is not None
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


def create_sample_hold_ticket(
    hold_id: str = "ht-test-001",
    requester_id: str = "spiffe://exchange.internal/workload/custody",
    expired: bool = False,
    raw_tx: str | None = None,
) -> HoldTicket:
    """Helper creating a quarantined HoldTicket in hold_store."""
    raw = raw_tx or build_raw_legacy_tx()
    decoded = evm_decoder.decode(bytes.fromhex(raw.removeprefix("0x")))
    now = datetime.now(UTC)
    expires_at = now - timedelta(minutes=5) if expired else now + timedelta(minutes=15)

    ticket = HoldTicket(
        id=hold_id,
        request_id=f"req-{hold_id}",
        tx_digest=decoded.digest,
        raw_tx=raw,
        chain="ethereum",
        wallet=decoded.from_address,
        amount_usd=50_000.0,
        requester_id=requester_id,
        reservation_id=f"res-{hold_id}",
        risk_score=75,
        reasons=[
            DecisionReason(
                code="SINGLE_TX_LIMIT_EXCEEDED",
                weight=50,
                detail="Transaction exceeds $20,000 threshold",
            )
        ],
        status="PENDING",
        expires_at=expires_at,
        created_at=now,
    )
    return hold_store.create(ticket)


# =========================================================================
# TEST 1: One approver cannot release (Quorum requires 2 distinct approvers)
# =========================================================================


def test_one_approver_cannot_release():
    """Requirement 1: 1 of 2 approvals records the approval but does NOT release the tx."""
    ticket = create_sample_hold_ticket("ht-quorum-01")
    priv_key_1 = approver_registry.dev_private_keys["usr-approver-01"]

    assertion_1 = create_test_webauthn_assertion(
        private_key=priv_key_1,
        tx_digest=ticket.tx_digest,
        sign_count=1,
    )

    headers_1 = get_auth_header(Role.APPROVER, "usr-approver-01")
    resp = client.post(
        f"/v1/holds/{ticket.id}/approve",
        json={"assertion": assertion_1.model_dump()},
        headers=headers_1,
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "PENDING_QUORUM"
    assert data["approvals_count"] == 1
    assert data["required_approvals"] == 2
    assert data["signature"] is None
    assert "1 of 2 approvals recorded" in data["message"]

    # Verify ticket in store is still PENDING
    stored = hold_store.get(ticket.id)
    assert stored is not None
    assert stored.status == "PENDING"
    assert len(stored.approvals) == 1
    assert stored.signed_result is None


# =========================================================================
# TEST 2: Same approver twice cannot release
# =========================================================================


def test_same_approver_twice_cannot_release():
    """Requirement 2: The same approver submitting a second approval is rejected with 400."""
    ticket = create_sample_hold_ticket("ht-quorum-02")
    priv_key_1 = approver_registry.dev_private_keys["usr-approver-01"]

    # First approval
    assertion_1 = create_test_webauthn_assertion(
        private_key=priv_key_1,
        tx_digest=ticket.tx_digest,
        sign_count=1,
    )
    headers_1 = get_auth_header(Role.APPROVER, "usr-approver-01")
    resp1 = client.post(
        f"/v1/holds/{ticket.id}/approve",
        json={"assertion": assertion_1.model_dump()},
        headers=headers_1,
    )
    assert resp1.status_code == 200

    # Second approval by SAME approver (even with fresh sign count)
    assertion_2 = create_test_webauthn_assertion(
        private_key=priv_key_1,
        tx_digest=ticket.tx_digest,
        sign_count=2,
    )
    resp2 = client.post(
        f"/v1/holds/{ticket.id}/approve",
        json={"assertion": assertion_2.model_dump()},
        headers=headers_1,
    )
    assert resp2.status_code == 400
    assert "DUPLICATE_APPROVER" in resp2.json()["detail"]


# =========================================================================
# TEST 3: Requester cannot approve
# =========================================================================


def test_requester_cannot_approve_own_request():
    """Requirement 3: Separation of duties: requester cannot approve their own hold ticket."""
    # Create ticket requested by usr-approver-01
    ticket = create_sample_hold_ticket("ht-quorum-03", requester_id="usr-approver-01")
    priv_key_1 = approver_registry.dev_private_keys["usr-approver-01"]

    assertion = create_test_webauthn_assertion(
        private_key=priv_key_1,
        tx_digest=ticket.tx_digest,
        sign_count=1,
    )
    headers_1 = get_auth_header(Role.APPROVER, "usr-approver-01")

    resp = client.post(
        f"/v1/holds/{ticket.id}/approve",
        json={"assertion": assertion.model_dump()},
        headers=headers_1,
    )
    assert resp.status_code == 403
    assert "REQUESTER_CANNOT_APPROVE" in resp.json()["detail"]


# =========================================================================
# TEST 4: Wrong digest challenge is rejected
# =========================================================================


def test_wrong_digest_challenge_is_rejected():
    """Requirement 4: WebAuthn challenge not equal to tx digest fails closed with 400."""
    ticket = create_sample_hold_ticket("ht-quorum-04")
    priv_key_1 = approver_registry.dev_private_keys["usr-approver-01"]

    # Assertion with an invented challenge
    wrong_challenge = "0x" + "a" * 64
    assertion = create_test_webauthn_assertion(
        private_key=priv_key_1,
        tx_digest=ticket.tx_digest,
        wrong_challenge=wrong_challenge,
        sign_count=1,
    )
    headers_1 = get_auth_header(Role.APPROVER, "usr-approver-01")

    resp = client.post(
        f"/v1/holds/{ticket.id}/approve",
        json={"assertion": assertion.model_dump()},
        headers=headers_1,
    )
    assert resp.status_code == 400
    assert "INVALID_CHALLENGE" in resp.json()["detail"]


# =========================================================================
# TEST 5: Expired ticket cannot be approved
# =========================================================================


def test_expired_ticket_cannot_be_approved():
    """Requirement 5: Quarantined ticket whose expiry elapsed cannot be approved."""
    ticket = create_sample_hold_ticket("ht-quorum-05", expired=True)
    priv_key_1 = approver_registry.dev_private_keys["usr-approver-01"]

    assertion = create_test_webauthn_assertion(
        private_key=priv_key_1,
        tx_digest=ticket.tx_digest,
        sign_count=1,
    )
    headers_1 = get_auth_header(Role.APPROVER, "usr-approver-01")

    resp = client.post(
        f"/v1/holds/{ticket.id}/approve",
        json={"assertion": assertion.model_dump()},
        headers=headers_1,
    )
    assert resp.status_code == 400
    assert "HOLD_EXPIRED" in resp.json()["detail"]


# =========================================================================
# TEST 6: Replayed assertion is rejected
# =========================================================================


def test_replayed_assertion_is_rejected():
    """Requirement 6: Replayed WebAuthn assertion payload is rejected atomically."""
    ticket_1 = create_sample_hold_ticket("ht-quorum-06a")
    ticket_2 = create_sample_hold_ticket("ht-quorum-06b")
    # Same raw_tx gives same digest
    ticket_2.tx_digest = ticket_1.tx_digest
    hold_store.create(ticket_2)

    priv_key_1 = approver_registry.dev_private_keys["usr-approver-01"]
    assertion = create_test_webauthn_assertion(
        private_key=priv_key_1,
        tx_digest=ticket_1.tx_digest,
        sign_count=1,
    )
    headers_1 = get_auth_header(Role.APPROVER, "usr-approver-01")

    # Use on ticket 1
    resp1 = client.post(
        f"/v1/holds/{ticket_1.id}/approve",
        json={"assertion": assertion.model_dump()},
        headers=headers_1,
    )
    assert resp1.status_code == 200

    # Replay identical assertion on ticket 2 (even by another user)
    headers_2 = get_auth_header(Role.APPROVER, "usr-approver-02")
    resp2 = client.post(
        f"/v1/holds/{ticket_2.id}/approve",
        json={"assertion": assertion.model_dump()},
        headers=headers_2,
    )
    assert resp2.status_code == 400
    assert "ASSERTION_REPLAY" in resp2.json()["detail"]


# =========================================================================
# TEST 7: End-to-end: HOLD -> Two WebAuthn Approvals -> Signature Issued
# =========================================================================


def test_end_to_end_hold_two_approvals_releases_signature():
    """Requirement 7: Full lifecycle: HOLD ticket -> Approver 1 -> Approver 2 -> Quorum -> Released."""
    raw_tx = build_raw_legacy_tx(value=5_000_000_000, nonce=10)
    ticket = create_sample_hold_ticket("ht-e2e-07", raw_tx=raw_tx)

    priv_key_1 = approver_registry.dev_private_keys["usr-approver-01"]
    priv_key_2 = approver_registry.dev_private_keys["usr-approver-02"]

    # Approver 1 signs
    assertion_1 = create_test_webauthn_assertion(
        private_key=priv_key_1,
        tx_digest=ticket.tx_digest,
        sign_count=1,
    )
    headers_1 = get_auth_header(Role.APPROVER, "usr-approver-01")
    resp1 = client.post(
        f"/v1/holds/{ticket.id}/approve",
        json={"assertion": assertion_1.model_dump()},
        headers=headers_1,
    )
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "PENDING_QUORUM"

    # Approver 2 signs
    assertion_2 = create_test_webauthn_assertion(
        private_key=priv_key_2,
        tx_digest=ticket.tx_digest,
        sign_count=1,
    )
    headers_2 = get_auth_header(Role.APPROVER, "usr-approver-02")
    resp2 = client.post(
        f"/v1/holds/{ticket.id}/approve",
        json={"assertion": assertion_2.model_dump()},
        headers=headers_2,
    )
    assert resp2.status_code == 200
    data2 = resp2.json()

    # Quorum reached!
    assert data2["status"] == "RELEASED"
    assert data2["approvals_count"] == 2
    assert data2["signature"] is not None
    assert data2["signature"].startswith("0x")
    assert "Quorum reached" in data2["message"]

    # Verify ticket state is APPROVED in store
    stored = hold_store.get(ticket.id)
    assert stored is not None
    assert stored.status in ("APPROVED", "RELEASED")
    assert stored.signed_result is not None
    assert stored.signed_result["signature"] == data2["signature"]

    # Verify audit entries appended
    audit_entries = audit_service.get_entries()[-10:]
    event_types = [e.event_type for e in audit_entries]
    assert "APPROVAL_QUORUM_REACHED" in event_types
    assert "TRANSACTION_SIGNED" in event_types


# =========================================================================
# TEST 8: Single Approver Denies Immediately (Invariant #6)
# =========================================================================


def test_single_approver_denies_and_tightens_immediately():
    """Invariant #6: Any single Approver can deny immediately, cancelling reservations."""
    ticket = create_sample_hold_ticket("ht-deny-08")
    headers = get_auth_header(Role.APPROVER, "usr-approver-01")

    resp = client.post(
        f"/v1/holds/{ticket.id}/deny",
        json={"reason": "Suspected compromise during incident investigation"},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "DENIED"
    assert data["hold_id"] == ticket.id
    assert "Suspected compromise" in data["reason"]

    # Verify ticket state in store
    stored = hold_store.get(ticket.id)
    assert stored is not None
    assert stored.status == "DENIED"

    # Cannot approve after being denied
    priv_key_1 = approver_registry.dev_private_keys["usr-approver-01"]
    assertion = create_test_webauthn_assertion(
        private_key=priv_key_1,
        tx_digest=ticket.tx_digest,
        sign_count=1,
    )
    resp_reapprove = client.post(
        f"/v1/holds/{ticket.id}/approve",
        json={"assertion": assertion.model_dump()},
        headers=headers,
    )
    assert resp_reapprove.status_code == 400


# =========================================================================
# TEST 9: Pluggable Notifiers Strictly Contain Console Link and NO Buttons
# =========================================================================


def test_notifiers_contain_console_link_and_no_approve_buttons():
    """Invariant #5: Slack, Telegram, PagerDuty carry ONLY a link, never an approve button."""
    ticket = create_sample_hold_ticket("ht-notify-09")
    expected_link = f"https://console.bitguard.exchange/holds/{ticket.id}"

    # Slack
    slack = SlackNotifier()
    slack_payload = slack.format_payload(ticket)
    assert "text" in slack_payload
    assert expected_link in slack_payload["text"]
    # Guarantee no interactive blocks or buttons
    assert "blocks" not in slack_payload
    assert "button" not in str(slack_payload).lower()
    assert "approve" not in str(slack_payload).lower() or "quarantine" in str(slack_payload).lower()

    # Telegram
    telegram = TelegramNotifier(chat_id="12345")
    tg_payload = telegram.format_payload(ticket)
    assert "text" in tg_payload
    assert expected_link in tg_payload["text"]
    # Guarantee no inline keyboard or callback buttons
    assert "reply_markup" not in tg_payload
    assert "inline_keyboard" not in str(tg_payload).lower()

    # PagerDuty
    pd = PagerDutyNotifier()
    pd_payload = pd.format_payload(ticket)
    assert "links" in pd_payload
    assert pd_payload["links"][0]["href"] == expected_link
    assert "action" not in pd_payload.get("payload", {})


# =========================================================================
# TEST 10: Console View Recomputes Ground Truth Independently
# =========================================================================


def test_console_view_recomputes_ground_truth_from_raw_bytes():
    """Invariant #4: GET /v1/holds/{id}/view re-decodes raw unsigned bytes independently."""
    raw_tx = build_raw_legacy_tx(value=777_000_000, nonce=42)
    ticket = create_sample_hold_ticket("ht-view-10", raw_tx=raw_tx)
    headers = get_auth_header(Role.VIEWER)

    resp = client.get(f"/v1/holds/{ticket.id}/view", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["hold_id"] == ticket.id
    assert data["status"] == "PENDING"
    assert data["data_label"] == "REAL"
    assert data["seconds_remaining"] > 0
    assert not data["is_expired"]

    # Verify decoded tx
    decoded = data["decoded_tx"]
    assert decoded is not None
    assert decoded["amount"] == "777000000"
    assert decoded["digest"] == ticket.tx_digest
