"""Comprehensive tests for cryptographic audit chain, object-lock anchoring, and SIEM export (Milestone S21 / F18).

Invariants Verified:
- Invariant #3: Fail-Closed Default (tampering, deletion, or anchor mismatch fails closed).
- Invariant #7: Immutable Audit Trail (SHA-256 hash chaining: entry_hash = sha256(prev_hash || canonical_json(entry))).
- Invariant #8: Explicit Data Provenance (data_label REAL).

Required Scenarios:
1. Deterministic genesis block and monotonic hash chaining.
2. Modify one row directly in the database => verify reports the exact first bad sequence.
3. Delete a row directly in the database => verify fails and reports the missing sequence.
4. Anchor mismatch between WORM object-lock anchor and ledger head is detected and reported.
5. Tail truncation / deletion after anchoring is detected.
6. SIEM export (RFC 5424 Syslog and OpenTelemetry LogRecord).
7. RBAC permissions on /v1/audit/verify and /v1/audit/anchor.
"""


import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from services.bitguard.audit import (
    GENESIS_PREV_HASH,
    anchor_service,
    audit_service,
    compute_entry_hash,
    siem_exporter,
)
from services.bitguard.database import set_engine
from services.bitguard.db_models import AuditEntryRecord, Base
from services.bitguard.main import app
from services.bitguard.models import Role
from services.bitguard.rbac import SEEDED_USERS, create_access_token

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_audit_test_env():
    """Initializes clean in-memory SQLite database and isolated audit state for each test."""
    engine = sa.create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=sa.pool.StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    set_engine(engine)
    audit_service.set_session_factory(session_factory)
    audit_service.clear()
    anchor_service.clear()

    yield {"engine": engine, "session_factory": session_factory}

    audit_service.clear()
    anchor_service.clear()
    audit_service.set_session_factory(None)


def _get_auth_header(role: Role) -> dict[str, str]:
    user = SEEDED_USERS[role]
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


# =====================================================================
# Test 1: Genesis block & monotonic hash chaining
# =====================================================================
def test_genesis_block_and_monotonic_hash_chain():
    """Verifies sequence numbers, parent hash pointers, and canonical RFC 8785 JSON hashing."""
    e1 = audit_service.append_entry(
        action="DECISION",
        actor="workload:custody-01",
        payload={"request_id": "req-001", "verdict": "ALLOW", "risk_score": 10},
        ts=1730000001.0,
    )
    assert e1.seq == 1
    assert e1.prev_hash == GENESIS_PREV_HASH
    assert len(e1.entry_hash) == 64

    # Verify deterministic hash recomputation
    expected_e1_hash = compute_entry_hash(
        prev_hash=GENESIS_PREV_HASH,
        entry={
            "action": "DECISION",
            "actor": "workload:custody-01",
            "data_label": "REAL",
            "payload": {"request_id": "req-001", "verdict": "ALLOW", "risk_score": 10},
            "seq": 1,
            "ts": 1730000001.0,
        },
    )
    assert e1.entry_hash == expected_e1_hash

    # Append second entry
    e2 = audit_service.append_entry(
        action="HOLD_CREATED",
        actor="system",
        payload={"hold_id": "ht-001", "reasons": ["SINGLE_TX_LIMIT_EXCEEDED"]},
        ts=1730000002.0,
    )
    assert e2.seq == 2
    assert e2.prev_hash == e1.entry_hash
    assert e2.entry_hash != e1.entry_hash

    # Verify integrity reports ok=True
    res = audit_service.verify_chain()
    assert res.ok is True
    assert res.checked_entries == 2
    assert res.first_bad_seq is None


# =====================================================================
# Test 2: Modify one row directly in DB => exact first bad sequence reported
# =====================================================================
def test_modify_row_directly_in_db_reports_exact_first_bad_seq(setup_audit_test_env):
    """An attacker with direct database access alters a payload in row 3; verify reports first_bad_seq=3."""
    session_factory = setup_audit_test_env["session_factory"]

    # Append 5 valid entries
    for i in range(1, 6):
        audit_service.append_entry(
            action=f"ACTION_{i}",
            actor=f"actor_{i}",
            payload={"request_id": f"req-{i}", "val": i * 100},
            ts=1730000000.0 + i,
        )

    # Initial verification succeeds
    res_initial = audit_service.verify_chain()
    assert res_initial.ok is True
    assert res_initial.checked_entries == 5
    assert res_initial.first_bad_seq is None

    # ATTACK: Direct raw SQL UPDATE tampering with row sequence 3
    with session_factory() as session:
        tampered_row = session.query(AuditEntryRecord).filter_by(seq=3).first()
        assert tampered_row is not None
        # Alter the payload content without updating entry_hash
        tampered_row.payload = {"request_id": "req-3", "val": 999999, "malicious_injection": True}
        session.commit()

    # Re-verify audit chain
    res_tampered = audit_service.verify_chain()
    assert res_tampered.ok is False
    assert res_tampered.checked_entries == 2  # Entries 1 and 2 were checked successfully
    assert res_tampered.first_bad_seq == 3
    assert "Tampered content at sequence 3" in (res_tampered.details or "")

    # Also test via HTTP GET /v1/audit/verify with Compliance role
    compliance_headers = _get_auth_header(Role.COMPLIANCE)
    http_resp = client.get("/v1/audit/verify", headers=compliance_headers)
    assert http_resp.status_code == 200
    data = http_resp.json()
    assert data["ok"] is False
    assert data["checked_entries"] == 2
    assert data["first_bad_seq"] == 3

    # Viewer role lacks READ_AUDIT permission -> 403 Forbidden
    viewer_headers = _get_auth_header(Role.VIEWER)
    resp_unauth = client.get("/v1/audit/verify", headers=viewer_headers)
    assert resp_unauth.status_code == 403


# =====================================================================
# Test 3: Delete a row directly in DB => verify fails closed
# =====================================================================
def test_delete_row_directly_in_db_fails_closed(setup_audit_test_env):
    """An attacker deletes row sequence 3; verify detects sequence gap and fails closed."""
    session_factory = setup_audit_test_env["session_factory"]

    # Append 5 valid entries
    for i in range(1, 6):
        audit_service.append_entry(
            action=f"ACTION_{i}",
            actor=f"actor_{i}",
            payload={"id": i},
            ts=1730000000.0 + i,
        )

    # ATTACK: Direct raw SQL DELETE removing row 3
    with session_factory() as session:
        row3 = session.query(AuditEntryRecord).filter_by(seq=3).first()
        assert row3 is not None
        session.delete(row3)
        session.commit()

    # Verify audit chain
    res = audit_service.verify_chain()
    assert res.ok is False
    assert res.first_bad_seq == 3
    assert res.checked_entries == 2  # Rows 1 and 2 passed before gap at 3
    assert "Sequence gap detected" in (res.details or "")


# =====================================================================
# Test 4: External Object-Lock Anchor Mismatch
# =====================================================================
def test_anchor_mismatch_is_detected_and_reported():
    """If an external object-lock anchor disagrees with the database head, verify fails."""
    # Append 4 entries
    for i in range(1, 5):
        audit_service.append_entry(
            action=f"ACTION_{i}",
            payload={"event": i},
            ts=1730000000.0 + i,
        )

    # Legitimate anchor checkpoint taken at seq 4
    receipt = audit_service.anchor_head()
    assert receipt["seq"] == 4
    assert receipt["head_hash"] == audit_service._last_head_hash

    # Verification with legitimate anchor succeeds
    res_ok = audit_service.verify_chain()
    assert res_ok.ok is True
    assert res_ok.checked_entries == 4
    assert res_ok.last_anchor is not None
    assert res_ok.last_anchor["seq"] == 4

    # ATTACK: External anchor contains divergent hash (or DB history was forked/rewritten)
    anchor_service.clear()
    anchor_service.record_anchor(
        head_hash="deadbeef" * 8,  # Corrupted / tampered head hash
        seq=4,
        ts=1730000010.0,
    )

    res_fail = audit_service.verify_chain()
    assert res_fail.ok is False
    assert res_fail.first_bad_seq == 4
    assert "Anchor mismatch at sequence 4" in (res_fail.details or "")


# =====================================================================
# Test 5: Tail Row Deletion after Anchoring Detected
# =====================================================================
def test_tail_deletion_after_anchor_detected(setup_audit_test_env):
    """If rows at the end of the chain are deleted after anchoring, verify flags the truncation."""
    session_factory = setup_audit_test_env["session_factory"]

    for i in range(1, 6):
        audit_service.append_entry(action=f"ACTION_{i}", payload={"i": i})

    # Anchor at seq 5
    audit_service.anchor_head()

    # ATTACK: Delete tail rows 4 and 5 from database
    with session_factory() as session:
        session.query(AuditEntryRecord).filter(AuditEntryRecord.seq >= 4).delete()
        session.commit()

    res = audit_service.verify_chain()
    assert res.ok is False
    assert res.first_bad_seq == 4  # Tail missing
    assert "Anchor references sequence 5 beyond available ledger length 3" in (res.details or "")


# =====================================================================
# Test 6: SIEM export formatting (RFC 5424 Syslog and OpenTelemetry)
# =====================================================================
def test_siem_export_formatting():
    """Validates RFC 5424 Syslog structured data and OpenTelemetry LogRecord payloads."""
    entry = {
        "seq": 10,
        "ts": 1730100000.5,
        "actor": "secops-operator-01",
        "action": "BREAKER_ESCALATE",
        "payload": {"target_state": "LOCKDOWN", "reason": "Anomaly detected"},
        "prev_hash": "a" * 64,
        "entry_hash": "b" * 64,
    }

    # 1. RFC 5424 Syslog
    syslog_msg = siem_exporter.format_rfc5424(entry)
    assert syslog_msg.startswith("<133>1")
    assert '[bitguard@52834 seq="10" action="BREAKER_ESCALATE" actor="secops-operator-01"' in syslog_msg
    assert 'entry_hash="' + ("b" * 64) + '"' in syslog_msg
    assert '"target_state":"LOCKDOWN"' in syslog_msg

    # 2. OpenTelemetry OTLP
    otel_payload = siem_exporter.format_otel_log_record(entry)
    resource_logs = otel_payload["resourceLogs"][0]
    service_attr = resource_logs["resource"]["attributes"][0]
    assert service_attr["key"] == "service.name"
    assert service_attr["value"]["stringValue"] == "bitguard"

    log_record = resource_logs["scopeLogs"][0]["logRecords"][0]
    assert log_record["severityText"] == "INFO"
    attrs = {a["key"]: a["value"] for a in log_record["attributes"]}
    assert attrs["audit.seq"]["intValue"] == 10
    assert attrs["audit.action"]["stringValue"] == "BREAKER_ESCALATE"


# =====================================================================
# Test 7: API endpoints & RBAC protections
# =====================================================================
def test_audit_api_endpoints_and_rbac():
    """Tests GET /v1/audit/entries and POST /v1/audit/anchor role enforcement."""
    # Append entries
    audit_service.append_entry(action="DECISION", actor="usr-viewer", payload={"val": 1})
    audit_service.append_entry(action="BREAKER_ESCALATE", actor="usr-secops", payload={"val": 2})

    viewer_headers = _get_auth_header(Role.VIEWER)
    compliance_headers = _get_auth_header(Role.COMPLIANCE)
    secops_headers = _get_auth_header(Role.SECOPS)
    operator_headers = _get_auth_header(Role.OPERATOR)

    # 1. GET /v1/audit/entries with Viewer role -> 403 Forbidden (Separation of duties)
    resp_viewer = client.get("/v1/audit/entries", headers=viewer_headers)
    assert resp_viewer.status_code == 403

    # Compliance role has READ_AUDIT permission -> 200 OK
    resp_entries = client.get("/v1/audit/entries", headers=compliance_headers)
    assert resp_entries.status_code == 200
    entries = resp_entries.json()
    assert len(entries) >= 2
    assert entries[0]["seq"] == 1
    assert entries[1]["seq"] == 2
    assert entries[0]["data_label"] == "REAL"

    # Filter by action
    resp_filter = client.get("/v1/audit/entries?action=BREAKER_ESCALATE", headers=compliance_headers)
    assert resp_filter.status_code == 200
    filtered = resp_filter.json()
    assert len(filtered) == 1
    assert filtered[0]["action"] == "BREAKER_ESCALATE"

    # 2. POST /v1/audit/anchor with Operator role -> 403 Forbidden (requires SecOps/Admin/Compliance)
    resp_unauth = client.post("/v1/audit/anchor", headers=operator_headers)
    assert resp_unauth.status_code == 403

    # 3. POST /v1/audit/anchor with SecOps role -> 200 OK
    resp_anchor = client.post("/v1/audit/anchor", headers=secops_headers)
    assert resp_anchor.status_code == 200
    anchor_data = resp_anchor.json()
    assert anchor_data["status"] == "ANCHORED"
    assert anchor_data["anchor"]["seq"] == 2
    assert anchor_data["data_label"] == "REAL"
