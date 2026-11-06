"""Comprehensive unit and integration test suite for Quarantine Hold Tickets (TASK S14).

Invariants & Requirements:
- hold_tickets table and service: id, digest, decoded_tx (JSON), reasons, requester_identity,
  state [PENDING|APPROVED|DENIED|EXPIRED|CANCELLED|RELEASED], created_at, expires_at,
  release_not_before, released_at.
- Enforce valid state transitions in code and with a database constraint/trigger. Terminal states cannot change.
- A single-use guarantee: a ticket can produce at most one token (SELECT ... FOR UPDATE).
- Expiry worker: PENDING tickets past expires_at become EXPIRED, original request counts as DENY,
  reservations released.
- Every transition writes an AuditEntry.
- API: GET /v1/holds (filter by state), GET /v1/holds/{id}, POST /v1/holds/{id}/cancel (Operator or SecOps; cancelling only tightens).
- Tests: all valid and invalid transitions, double-release attempt, expiry, restart of service does not lose tickets.
"""

import threading
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any

import fakeredis
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from services.bitguard.approvals.exceptions import (
    InvalidHoldStateTransitionError,
    TicketAlreadyReleasedError,
)
from services.bitguard.approvals.hold_store import hold_store
from services.bitguard.approvals.state_machine import TERMINAL_STATES, validate_transition
from services.bitguard.approvals.worker import hold_expiry_worker
from services.bitguard.audit_service import audit_service
from services.bitguard.db_models import Base, HoldTicketRecord
from services.bitguard.limits.store import ScopeBuilder, limit_store
from services.bitguard.main import app
from services.bitguard.models import DecisionReason, HoldTicket, Role
from services.bitguard.rbac import ALL_TEST_USERS, SEEDED_USERS, create_access_token

client = TestClient(app)


def get_auth_header(role: Role = Role.OPERATOR, user_id: str | None = None) -> dict[str, str]:
    """Helper creating Bearer Authorization header."""
    user = ALL_TEST_USERS.get(user_id) if user_id else SEEDED_USERS[role]
    assert user is not None
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def clean_environment() -> Generator[None, None, None]:
    """Cleans up hold store and audit service between tests."""
    hold_store.clear()
    audit_service.clear()
    server = fakeredis.FakeServer()
    fake_client = fakeredis.FakeRedis(server=server, decode_responses=True)
    limit_store.set_redis_client(fake_client)
    yield
    hold_store.clear()
    audit_service.clear()


def make_sample_ticket(
    ticket_id: str = "ht-test-01",
    state: str = "PENDING",
    expired: bool = False,
    reservation_id: str | None = None,
    amount_usd: float = 25000.0,
) -> HoldTicket:
    """Helper constructing a canonical S14 HoldTicket."""
    now = datetime.now(UTC)
    expires_at = now - timedelta(seconds=10) if expired else now + timedelta(minutes=15)
    return HoldTicket(
        id=ticket_id,
        request_id=f"req-{ticket_id}",
        digest="0x" + "a" * 64,
        tx_digest="0x" + "a" * 64,
        decoded_tx={
            "chain": "ethereum",
            "from_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            "to_address": "0x1111111111111111111111111111111111111111",
            "value": 1000000000000000000,
            "nonce": 42,
        },
        raw_tx="0x02f8...sample_raw_hex",
        chain="ethereum",
        wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        amount_usd=amount_usd,
        requester_id="spiffe://exchange.internal/workload/custody",
        requester_identity="spiffe://exchange.internal/workload/custody",
        reservation_id=reservation_id,
        risk_score=80,
        reasons=[DecisionReason(code="VELOCITY_SPIKE", weight=80, detail="Velocity spike above baseline")],
        state=state,
        status=state,
        expires_at=expires_at,
        created_at=now,
        release_not_before=None,
        released_at=None,
    )


# =========================================================================
# 1. State Machine & Transitions Tests (Valid and Invalid)
# =========================================================================

def test_all_valid_state_transitions() -> None:
    """Verifies that all allowed state transitions succeed cleanly."""
    valid_paths = [
        ("PENDING", "APPROVED"),
        ("PENDING", "DENIED"),
        ("PENDING", "EXPIRED"),
        ("PENDING", "CANCELLED"),
        ("PENDING", "RELEASED"),
        ("APPROVED", "RELEASED"),
        ("APPROVED", "CANCELLED"),
    ]
    for idx, (source, target) in enumerate(valid_paths):
        tid = f"ht-valid-{idx}"
        ticket = make_sample_ticket(ticket_id=tid, state=source)
        hold_store.create(ticket)

        updated = hold_store.transition_state(tid, target, actor="usr-test")
        assert updated.state == target
        assert updated.status == target


def test_invalid_state_transitions_rejected_in_code() -> None:
    """Verifies invalid transitions raise InvalidHoldStateTransitionError."""
    # APPROVED cannot transition to DENIED or EXPIRED
    invalid_transitions = [
        ("APPROVED", "DENIED"),
        ("APPROVED", "EXPIRED"),
        ("APPROVED", "PENDING"),
    ]
    for idx, (source, target) in enumerate(invalid_transitions):
        tid = f"ht-invalid-{idx}"
        ticket = make_sample_ticket(ticket_id=tid, state=source)
        hold_store.create(ticket)

        with pytest.raises(InvalidHoldStateTransitionError) as exc_info:
            hold_store.transition_state(tid, target, actor="usr-test")
        assert "Invalid transition" in str(exc_info.value)


def test_terminal_states_cannot_change() -> None:
    """Terminal states (DENIED, EXPIRED, CANCELLED, RELEASED) cannot transition to any other state."""
    all_states = ["PENDING", "APPROVED", "DENIED", "EXPIRED", "CANCELLED", "RELEASED"]
    for term in TERMINAL_STATES:
        for target in all_states:
            if target == term:
                continue  # noop
            with pytest.raises(InvalidHoldStateTransitionError) as exc_info:
                validate_transition(term, target, ticket_id="test-ticket")
            assert "Terminal state" in str(exc_info.value)

            tid = f"ht-term-{term}-{target}"
            ticket = make_sample_ticket(ticket_id=tid, state=term)
            hold_store.create(ticket)

            with pytest.raises(InvalidHoldStateTransitionError):
                hold_store.transition_state(tid, target, actor="usr-test")


def test_terminal_state_constraint_at_database_level() -> None:
    """Verifies database trigger / listener rejects updating terminal records."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)

    with session_factory() as session:
        # Create a record directly in terminal state DENIED
        rec = HoldTicketRecord(
            id="ht-db-terminal-test",
            request_id="req-db-001",
            tx_digest="0xdigest1",
            state="DENIED",
            status="DENIED",
            reasons=[],
            expires_at=datetime.now(UTC),
            created_at=datetime.now(UTC),
        )
        session.add(rec)
        session.commit()

        # Attempt to modify state from DENIED to APPROVED
        rec.state = "APPROVED"
        with pytest.raises(InvalidHoldStateTransitionError):
            session.commit()


# =========================================================================
# 2. Single-Use Guarantee & Double-Release Attempt Tests
# =========================================================================

def test_single_use_guarantee_prevents_double_release() -> None:
    """A ticket can produce at most one approval token; second release attempt raises TicketAlreadyReleasedError."""
    tid = "ht-single-use-01"
    ticket = make_sample_ticket(ticket_id=tid, state="PENDING")
    hold_store.create(ticket)

    # First release succeeds
    res1 = hold_store.atomic_release(
        ticket_id=tid,
        actor="system",
        signed_result={"signature": "0xsig1", "tx_hash": "0xhash1"},
    )
    assert res1.state == "RELEASED"
    assert res1.released_at is not None
    assert res1.signed_result == {"signature": "0xsig1", "tx_hash": "0xhash1"}

    # Second release attempt fails immediately
    with pytest.raises(TicketAlreadyReleasedError) as exc_info:
        hold_store.atomic_release(
            ticket_id=tid,
            actor="system",
            signed_result={"signature": "0xsig2", "tx_hash": "0xhash2"},
        )
    assert "SINGLE_USE_VIOLATION" in str(exc_info.value)


def test_concurrent_double_release_attempt_under_threads() -> None:
    """Concurrent release attempts from multiple threads result in exactly one success."""
    tid = "ht-concurrent-release-01"
    ticket = make_sample_ticket(ticket_id=tid, state="PENDING")
    hold_store.create(ticket)

    results: list[Any] = []
    errors: list[Exception] = []

    def attempt_release(idx: int) -> None:
        try:
            res = hold_store.atomic_release(
                ticket_id=tid,
                actor=f"worker-{idx}",
                signed_result={"signature": f"0xsig-{idx}", "tx_hash": f"0xhash-{idx}"},
            )
            results.append(res)
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=attempt_release, args=(1,))
    t2 = threading.Thread(target=attempt_release, args=(2,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Exactly one successful release, exactly one rejected with TicketAlreadyReleasedError
    assert len(results) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], TicketAlreadyReleasedError)


# =========================================================================
# 3. Expiry Worker Tests
# =========================================================================

def test_expiry_worker_sweeps_past_due_tickets_and_releases_limits() -> None:
    """Pending tickets past expires_at become EXPIRED, reservation released, and DENY logged."""
    # 1. Setup a reservation in limit_store
    scope_key = ScopeBuilder.wallet_scope("0x742d35Cc6634C0532925a3b844Bc454e4438f44e", window_seconds=3600)
    res = limit_store.reserve(
        scope_keys=[scope_key],
        amount=10_000,
        window_seconds=3600,
        cap=100_000,
    )
    assert res.ok
    res_id = res.reservation_id

    # 2. Create ticket that is expired past TTL
    tid = "ht-expired-01"
    ticket = make_sample_ticket(
        ticket_id=tid,
        state="PENDING",
        expired=True,
        reservation_id=res_id,
        amount_usd=10_000.0,
    )
    hold_store.create(ticket)

    # 3. Run sweep
    expired_ids = hold_expiry_worker.sweep_expired()
    assert tid in expired_ids

    # 4. Verify ticket state updated to EXPIRED
    updated_ticket = hold_store.get(tid)
    assert updated_ticket is not None
    assert updated_ticket.state == "EXPIRED"
    assert updated_ticket.status == "EXPIRED"

    # 5. Verify limit reservation was released (cannot be committed now)
    assert not limit_store.commit(res_id)

    # 6. Verify AuditEntry with verdict DENY was logged
    audit_entries = audit_service.get_entries()
    assert any(
        e.action == "HOLD_EXPIRED" and e.payload.get("hold_id") == tid and e.verdict == "DENY"
        for e in audit_entries
    )


def test_expiry_worker_ignores_active_and_terminal_tickets() -> None:
    """Tickets that have not reached expires_at or are already terminal are not expired."""
    t_active = make_sample_ticket(ticket_id="ht-active", state="PENDING", expired=False)
    t_approved = make_sample_ticket(ticket_id="ht-appr", state="APPROVED", expired=True)
    t_released = make_sample_ticket(ticket_id="ht-rel", state="RELEASED", expired=True)

    hold_store.create(t_active)
    hold_store.create(t_approved)
    hold_store.create(t_released)

    expired_ids = hold_expiry_worker.sweep_expired()
    assert "ht-active" not in expired_ids
    assert "ht-appr" not in expired_ids
    assert "ht-rel" not in expired_ids

    assert hold_store.get("ht-active").state == "PENDING"  # type: ignore[union-attr]
    assert hold_store.get("ht-appr").state == "APPROVED"  # type: ignore[union-attr]
    assert hold_store.get("ht-rel").state == "RELEASED"  # type: ignore[union-attr]


# =========================================================================
# 4. Service Restart / Persistence Tests
# =========================================================================

def test_service_restart_does_not_lose_tickets() -> None:
    """Clearing in-memory cache simulates service restart; tickets reload from database with all fields."""
    tid = "ht-persist-01"
    ticket = make_sample_ticket(ticket_id=tid, state="PENDING")
    hold_store.create(ticket)

    # Simulate restart by clearing in-memory cache
    hold_store.clear()

    # Retrieve by ID from persistent store
    reloaded = hold_store.get(tid)
    assert reloaded is not None
    assert reloaded.id == tid
    assert reloaded.digest == ticket.digest
    assert reloaded.decoded_tx == ticket.decoded_tx
    assert reloaded.requester_identity == ticket.requester_identity
    assert reloaded.state == "PENDING"
    assert len(reloaded.reasons) == 1
    assert reloaded.reasons[0].code == "VELOCITY_SPIKE"

    # Also list_active returns persistent tickets after restart
    hold_store.clear()
    active_list = hold_store.list_active(limit=10, state="PENDING")
    assert any(t.id == tid for t in active_list)


# =========================================================================
# 5. API Endpoints Tests
# =========================================================================

def test_get_holds_and_filter_by_state() -> None:
    """GET /v1/holds returns list and supports state filtering."""
    t1 = make_sample_ticket(ticket_id="ht-api-p1", state="PENDING")
    t2 = make_sample_ticket(ticket_id="ht-api-p2", state="PENDING")
    t3 = make_sample_ticket(ticket_id="ht-api-c1", state="CANCELLED")

    hold_store.create(t1)
    hold_store.create(t2)
    hold_store.create(t3)

    headers = get_auth_header(Role.OPERATOR)

    # 1. Unfiltered list
    res = client.get("/v1/holds", headers=headers)
    assert res.status_code == 200
    all_tickets = res.json()
    assert len(all_tickets) >= 3

    # 2. Filter by state=PENDING
    res_pending = client.get("/v1/holds?state=PENDING", headers=headers)
    assert res_pending.status_code == 200
    pending_tickets = res_pending.json()
    assert all(t["state"] == "PENDING" for t in pending_tickets)
    assert any(t["id"] == "ht-api-p1" for t in pending_tickets)

    # 3. Filter by state=CANCELLED
    res_cancelled = client.get("/v1/holds?state=CANCELLED", headers=headers)
    assert res_cancelled.status_code == 200
    cancelled_tickets = res_cancelled.json()
    assert all(t["state"] == "CANCELLED" for t in cancelled_tickets)
    assert any(t["id"] == "ht-api-c1" for t in cancelled_tickets)


def test_get_single_hold_by_id() -> None:
    """GET /v1/holds/{id} retrieves specific ticket details."""
    tid = "ht-get-single-01"
    ticket = make_sample_ticket(ticket_id=tid, state="PENDING")
    hold_store.create(ticket)

    headers = get_auth_header(Role.OPERATOR)
    res = client.get(f"/v1/holds/{tid}", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == tid
    assert data["digest"] == ticket.digest
    assert data["decoded_tx"] is not None
    assert data["decoded_tx"]["from_address"] == "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    assert data["state"] == "PENDING"

    # Non-existent ticket returns 404
    res_404 = client.get("/v1/holds/ht-non-existent", headers=headers)
    assert res_404.status_code == 404


def test_post_cancel_hold_operator_and_secops() -> None:
    """POST /v1/holds/{id}/cancel cancels hold ticket immediately (Operator/SecOps tightening)."""
    # 1. Operator cancels
    tid1 = "ht-cancel-op-01"
    ticket1 = make_sample_ticket(ticket_id=tid1, state="PENDING")
    hold_store.create(ticket1)

    op_headers = get_auth_header(Role.OPERATOR)
    res1 = client.post(
        f"/v1/holds/{tid1}/cancel",
        json={"reason": "Operator observed suspicious pattern off-chain"},
        headers=op_headers,
    )
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["status"] == "CANCELLED"
    assert data1["state"] == "CANCELLED"
    assert data1["hold_id"] == tid1
    assert data1["cancelled_by"] == "usr-operator-01"

    # Verify state in store
    assert hold_store.get(tid1).state == "CANCELLED"  # type: ignore[union-attr]

    # 2. SecOps cancels
    tid2 = "ht-cancel-sec-02"
    ticket2 = make_sample_ticket(ticket_id=tid2, state="PENDING")
    hold_store.create(ticket2)

    sec_headers = get_auth_header(Role.SECOPS)
    res2 = client.post(
        f"/v1/holds/{tid2}/cancel",
        json={"reason": "SecOps initiated proactive quarantine tightening"},
        headers=sec_headers,
    )
    assert res2.status_code == 200
    assert res2.json()["status"] == "CANCELLED"
    assert hold_store.get(tid2).state == "CANCELLED"  # type: ignore[union-attr]


def test_cancel_already_terminal_ticket_rejected() -> None:
    """Attempting to cancel an already terminal ticket returns 400 Bad Request."""
    tid = "ht-cancel-terminal"
    ticket = make_sample_ticket(ticket_id=tid, state="DENIED")
    hold_store.create(ticket)

    headers = get_auth_header(Role.OPERATOR)
    res = client.post(
        f"/v1/holds/{tid}/cancel",
        json={"reason": "Redundant cancel attempt"},
        headers=headers,
    )
    assert res.status_code == 400
    assert "terminal state" in res.json()["detail"]


def test_audit_entries_written_for_every_transition() -> None:
    """Verifies that an AuditEntry is appended to the audit ledger for every lifecycle event."""
    tid = "ht-audit-trail-01"
    ticket = make_sample_ticket(ticket_id=tid, state="PENDING")
    hold_store.create(ticket)

    # 1. HOLD_TICKET_CREATED
    entries = [e for e in audit_service.get_entries() if e.payload.get("hold_id") == tid]
    assert any(e.action == "HOLD_TICKET_CREATED" for e in entries)

    # 2. Transition to APPROVED
    hold_store.transition_state(tid, "APPROVED", actor="usr-approver-01")
    entries = [e for e in audit_service.get_entries() if e.payload.get("hold_id") == tid]
    assert any(e.action == "HOLD_APPROVED" for e in entries)

    # 3. Transition to RELEASED
    hold_store.atomic_release(tid, actor="system", signed_result={"sig": "0x123"})
    entries = [e for e in audit_service.get_entries() if e.payload.get("hold_id") == tid]
    assert any(e.action == "HOLD_RELEASED" and e.verdict == "ALLOW" for e in entries)
