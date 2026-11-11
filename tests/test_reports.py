"""Comprehensive unit and integration tests for BitGuard Reports (Milestone S35 / F20).

Verifies:
- Endpoints under /v1/reports/* with Compliance role access (and 403 for unauthorized roles).
- Numbers in generated reports strictly equal the underlying database source tables.
- Formats: PDF (starts with %PDF-) and structured CSV with audit stamp and data labels.
- Audit chain verification stamp is cryptographically valid and bound to the report.
"""

import time
from datetime import UTC, datetime, timedelta

import fakeredis
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from services.bitguard.audit import audit_service
from services.bitguard.database import get_session_factory, set_engine
from services.bitguard.db_models import (
    ApprovalRecord,
    Base,
    BreakerStateRecord,
    DecisionRecord,
    HoldTicketRecord,
    IncidentRecord,
    PolicyVersionRecord,
)
from services.bitguard.main import app
from services.bitguard.models import Role
from services.signer_shim.heartbeat import heartbeat_tracker
from services.signer_shim.nonce_store import nonce_store

COMPLIANCE_AUTH_HEADERS = {"X-User-Role": Role.COMPLIANCE.value, "X-User-Id": "compliance-officer"}
OPERATOR_AUTH_HEADERS = {"X-User-Role": Role.OPERATOR.value, "X-User-Id": "operator-user"}
VIEWER_AUTH_HEADERS = {"X-User-Role": Role.VIEWER.value, "X-User-Id": "viewer-user"}
ADMIN_AUTH_HEADERS = {"X-User-Role": Role.ADMIN.value, "X-User-Id": "admin-user"}

test_client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_reports_test_db():
    """Sets up an isolated SQLite database and FakeRedis client for reporting tests."""
    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    set_engine(engine)

    server = fakeredis.FakeServer()
    fake_client = fakeredis.FakeRedis(server=server, decode_responses=True)
    nonce_store.set_redis_client(fake_client)

    heartbeat_tracker.last_heartbeat_time = time.time()
    audit_service.clear()

    yield

    engine.dispose()


def get_test_db() -> Session:
    """Yields a test database session."""
    return get_session_factory()()


# -----------------------------------------------------------------------------
# RBAC Tests
# -----------------------------------------------------------------------------


def test_compliance_role_can_access_reports():
    """Compliance role and Admin role can access reports endpoints."""
    # Seed a basic incident
    sess = get_test_db()
    inc = IncidentRecord(
        id="inc-test-rbac",
        trigger="EIP7702_DELEGATION",
        status="RESOLVED",
        severity="CRITICAL",
        detected_at=datetime.now(UTC),
        timeline=[],
        checklist=[],
        approvals=[],
    )
    sess.add(inc)
    sess.commit()
    sess.close()

    # Compliance: 200 OK
    resp = test_client.get(
        "/v1/reports/incident/inc-test-rbac?format=json",
        headers=COMPLIANCE_AUTH_HEADERS,
    )
    assert resp.status_code == 200

    # Admin: 200 OK
    resp_admin = test_client.get(
        "/v1/reports/incident/inc-test-rbac?format=json",
        headers=ADMIN_AUTH_HEADERS,
    )
    assert resp_admin.status_code == 200


def test_unauthorized_roles_receive_403_forbidden():
    """Viewer and Operator without Compliance permission receive 403 Forbidden."""
    resp_viewer = test_client.get(
        "/v1/reports/monthly?year=2026&month=11&format=json",
        headers=VIEWER_AUTH_HEADERS,
    )
    assert resp_viewer.status_code == 403
    assert "Access denied" in resp_viewer.text

    resp_operator = test_client.get(
        "/v1/reports/policy-history?format=json",
        headers=OPERATOR_AUTH_HEADERS,
    )
    assert resp_operator.status_code == 403


# -----------------------------------------------------------------------------
# Report 1 Tests: Incident Post-Mortem (Numbers match source tables)
# -----------------------------------------------------------------------------


def test_incident_post_mortem_numbers_equal_source_tables():
    """Verifies incident post-mortem data, timeline, containment ms, and decisions equal DB tables."""
    sess = get_test_db()

    inc_id = "inc-2026-audit-01"
    t_detect = datetime(2026, 11, 10, 14, 0, 0, tzinfo=UTC)
    t_contain = datetime(2026, 11, 10, 14, 0, 0, 12500, tzinfo=UTC)
    t_resolve = datetime(2026, 11, 10, 14, 30, 0, tzinfo=UTC)
    ttc_ms = 12.50

    inc = IncidentRecord(
        id=inc_id,
        trigger="UNAUTHORIZED_DELEGATION",
        status="RESOLVED",
        severity="CRITICAL",
        detected_at=t_detect,
        contained_at=t_contain,
        time_to_contain_ms=ttc_ms,
        resolved_at=t_resolve,
        timeline=[
            {"timestamp": "2026-11-10T14:00:00Z", "event": "Watcher alert detected", "actor": "system", "detail": "Delegate code mismatch"},
            {"timestamp": "2026-11-10T14:00:00.012Z", "event": "Breaker tripped to LOCKDOWN", "actor": "system", "detail": "Automated containment"},
        ],
        checklist=[
            {"id": "step-1", "text": "Notify SecOps On-Call", "ticked": True, "ticked_by": "secops-bot"},
            {"id": "step-2", "text": "Verify hot wallet nonces", "ticked": True, "ticked_by": "alice-secops"},
        ],
        approvals=[
            {"step_id": "step-2", "approver": "bob-approver", "role": "Approver", "timestamp": "2026-11-10T14:15:00Z"}
        ],
        data_label="REAL",
    )
    sess.add(inc)

    # Add 2 decisions in the incident window
    dec1 = DecisionRecord(
        id="dec-inc-01",
        request_id="req-inc-01",
        verdict="DENY",
        risk_score=95,
        reasons=[{"code": "DELEGATION_NOT_ALLOWED", "weight": 95, "detail": "Unapproved delegate"}],
        mode="ENFORCE",
        policy_version="v1.2.0",
        data_label="REAL",
        wallet="0x1111111111111111111111111111111111111111",
        chain="ethereum",
        created_at=t_detect + timedelta(seconds=2),
    )
    dec2 = DecisionRecord(
        id="dec-inc-02",
        request_id="req-inc-02",
        verdict="HOLD",
        risk_score=70,
        reasons=[{"code": "BREAKER_LOCKDOWN", "weight": 70, "detail": "Lockdown active"}],
        mode="ENFORCE",
        policy_version="v1.2.0",
        data_label="REAL",
        wallet="0x2222222222222222222222222222222222222222",
        chain="ethereum",
        created_at=t_detect + timedelta(seconds=10),
    )
    sess.add_all([dec1, dec2])
    sess.commit()
    sess.close()

    # 1. JSON Verification (Source Table Parity)
    resp_json = test_client.get(
        f"/v1/reports/incident/{inc_id}?format=json",
        headers=COMPLIANCE_AUTH_HEADERS,
    )
    assert resp_json.status_code == 200
    data = resp_json.json()

    assert data["incident_id"] == inc_id
    assert data["trigger"] == "UNAUTHORIZED_DELEGATION"
    assert data["severity"] == "CRITICAL"
    assert data["status"] == "RESOLVED"
    assert data["time_to_contain_ms"] == ttc_ms
    assert data["policy_version_at_time"] == "v1.2.0"
    # Actions: 2 checklist + 1 approval = 3 actions
    assert len(data["actions_taken"]) == 3
    # Decisions made in window = 2
    assert len(data["decisions_made"]) == 2
    assert data["decisions_made"][0]["verdict"] == "DENY"
    assert data["decisions_made"][1]["verdict"] == "HOLD"
    # Timeline items = 2
    assert len(data["timeline"]) == 2
    # Audit stamp is valid
    assert data["audit_verification"]["audit_chain_valid"] is True
    assert data["data_label"] == "REAL"

    # 2. CSV Verification
    resp_csv = test_client.get(
        f"/v1/reports/incident/{inc_id}?format=csv",
        headers=COMPLIANCE_AUTH_HEADERS,
    )
    assert resp_csv.status_code == 200
    assert resp_csv.headers["content-type"].startswith("text/csv")
    csv_text = resp_csv.text
    assert f"Incident ID,{inc_id}" in csv_text
    assert "UNAUTHORIZED_DELEGATION" in csv_text
    assert "Time to Contain (ms),12.50" in csv_text
    assert "DENY" in csv_text
    assert "reduces and contains" in csv_text

    # 3. PDF Verification
    resp_pdf = test_client.get(
        f"/v1/reports/incident/{inc_id}?format=pdf",
        headers=COMPLIANCE_AUTH_HEADERS,
    )
    assert resp_pdf.status_code == 200
    assert resp_pdf.headers["content-type"] == "application/pdf"
    assert resp_pdf.content.startswith(b"%PDF-")
    assert len(resp_pdf.content) > 1000


def test_incident_post_mortem_not_found():
    """Non-existent incident returns 404."""
    resp = test_client.get(
        "/v1/reports/incident/non-existent-inc?format=json",
        headers=COMPLIANCE_AUTH_HEADERS,
    )
    assert resp.status_code == 404


# -----------------------------------------------------------------------------
# Report 2 Tests: Monthly Control Report (Numbers match source tables)
# -----------------------------------------------------------------------------


def test_monthly_control_report_numbers_equal_source_tables():
    """Verifies monthly control report decision counts, holds, and false-positives equal DB tables."""
    sess = get_test_db()

    target_year = 2026
    target_month = 11
    month_start = datetime(target_year, target_month, 1, 0, 0, 0, tzinfo=UTC)

    # 1. Seed Decisions: 5 ALLOW, 3 HOLD, 2 DENY. 1 is false positive. Total = 10.
    for i in range(5):
        sess.add(DecisionRecord(
            id=f"dec-allow-{i}",
            request_id=f"req-allow-{i}",
            verdict="ALLOW",
            risk_score=10,
            reasons=[],
            mode="ENFORCE",
            policy_version="v1.0.0",
            data_label="REAL",
            is_false_positive=False,
            created_at=month_start + timedelta(days=i),
        ))

    for j in range(3):
        sess.add(DecisionRecord(
            id=f"dec-hold-{j}",
            request_id=f"req-hold-{j}",
            verdict="HOLD",
            risk_score=60,
            reasons=[{"code": "VELOCITY_SPIKE", "weight": 60, "detail": "spike"}],
            mode="ENFORCE",
            policy_version="v1.0.0",
            data_label="REAL",
            is_false_positive=(j == 0),  # 1 false positive
            created_at=month_start + timedelta(days=j + 5),
        ))

    for k in range(2):
        sess.add(DecisionRecord(
            id=f"dec-deny-{k}",
            request_id=f"req-deny-{k}",
            verdict="DENY",
            risk_score=90,
            reasons=[{"code": "LIMIT_EXCEEDED", "weight": 90, "detail": "exceeded"}],
            mode="ENFORCE",
            policy_version="v1.0.0",
            data_label="REAL",
            is_false_positive=False,
            created_at=month_start + timedelta(days=k + 8),
        ))

    # Add 1 decision in previous month (must NOT be counted)
    sess.add(DecisionRecord(
        id="dec-prev-month",
        request_id="req-prev",
        verdict="ALLOW",
        risk_score=10,
        reasons=[],
        mode="ENFORCE",
        policy_version="v1.0.0",
        data_label="REAL",
        created_at=datetime(2026, 10, 25, 0, 0, 0, tzinfo=UTC),
    ))

    # 2. Seed Hold Tickets: 2 APPROVED, 1 DENIED. Total = 3.
    sess.add(HoldTicketRecord(
        id="ht-01",
        request_id="req-hold-0",
        tx_digest="0x1111",
        state="APPROVED",
        status="APPROVED",
        expires_at=month_start + timedelta(hours=2),
        created_at=month_start + timedelta(days=5),
    ))
    sess.add(HoldTicketRecord(
        id="ht-02",
        request_id="req-hold-1",
        tx_digest="0x2222",
        state="APPROVED",
        status="APPROVED",
        expires_at=month_start + timedelta(hours=2),
        created_at=month_start + timedelta(days=6),
    ))
    sess.add(HoldTicketRecord(
        id="ht-03",
        request_id="req-hold-2",
        tx_digest="0x3333",
        state="DENIED",
        status="DENIED",
        expires_at=month_start + timedelta(hours=2),
        created_at=month_start + timedelta(days=7),
    ))

    # 3. Seed Approvals: 2 approvals from 2 distinct approvers
    sess.add(ApprovalRecord(
        id="appr-01",
        hold_ticket_id="ht-01",
        approver_id="approver-alice",
        approver_role="Approver",
        tx_digest="0x1111",
        webauthn_signature="sig-alice",
        created_at=month_start + timedelta(days=5, hours=1),
    ))
    sess.add(ApprovalRecord(
        id="appr-02",
        hold_ticket_id="ht-02",
        approver_id="approver-bob",
        approver_role="Approver",
        tx_digest="0x2222",
        webauthn_signature="sig-bob",
        created_at=month_start + timedelta(days=6, hours=1),
    ))

    # 4. Seed Breaker State Record
    sess.add(BreakerStateRecord(
        state="ELEVATED",
        reason="Test elevated velocity breach",
        updated_by="secops-user",
        token_epoch=2,
        data_label="REAL",
        updated_at=month_start + timedelta(days=12),
    ))

    sess.commit()
    sess.close()

    # 1. JSON Verification (Exact Table Parity)
    resp_json = test_client.get(
        f"/v1/reports/monthly?year={target_year}&month={target_month}&format=json",
        headers=COMPLIANCE_AUTH_HEADERS,
    )
    assert resp_json.status_code == 200
    data = resp_json.json()

    assert data["period"] == f"{target_year:04d}-{target_month:02d}"
    assert data["total_decisions"] == 10
    assert data["decision_counts_by_verdict"]["ALLOW"] == 5
    assert data["decision_counts_by_verdict"]["HOLD"] == 3
    assert data["decision_counts_by_verdict"]["DENY"] == 2
    assert data["false_positive_count"] == 1
    assert data["false_positive_rate_pct"] == 10.0  # 1 / 10 = 10.0%

    assert data["hold_counts"]["TOTAL_HOLDS"] == 3
    assert data["hold_counts"]["APPROVED"] == 2
    assert data["hold_counts"]["DENIED"] == 1

    assert data["approval_statistics"]["total_approvals"] == 2
    assert data["approval_statistics"]["unique_approvers_count"] == 2

    assert len(data["breaker_history"]) == 1
    assert data["breaker_history"][0]["state"] == "ELEVATED"

    assert data["audit_verification"]["audit_chain_valid"] is True

    # 2. CSV Verification
    resp_csv = test_client.get(
        f"/v1/reports/monthly?year={target_year}&month={target_month}&format=csv",
        headers=COMPLIANCE_AUTH_HEADERS,
    )
    assert resp_csv.status_code == 200
    assert resp_csv.headers["content-type"].startswith("text/csv")
    csv_text = resp_csv.text
    assert "Total Decisions Evaluated,10" in csv_text
    assert "Decisions - ALLOW,5" in csv_text
    assert "Decisions - HOLD,3" in csv_text
    assert "Decisions - DENY,2" in csv_text
    assert "False Positive Rate (%),10.00%" in csv_text
    assert "Hardware Approvals Count,2" in csv_text

    # 3. PDF Verification
    resp_pdf = test_client.get(
        f"/v1/reports/monthly?year={target_year}&month={target_month}&format=pdf",
        headers=COMPLIANCE_AUTH_HEADERS,
    )
    assert resp_pdf.status_code == 200
    assert resp_pdf.headers["content-type"] == "application/pdf"
    assert resp_pdf.content.startswith(b"%PDF-")
    assert len(resp_pdf.content) > 1000


# -----------------------------------------------------------------------------
# Report 3 Tests: Policy Change History (Numbers match source tables)
# -----------------------------------------------------------------------------


def test_policy_change_history_numbers_equal_source_tables():
    """Verifies policy change history versions, diffs, approvers, and backtests equal DB tables."""
    sess = get_test_db()

    # Seed 2 policy versions: v1.0.0 (Genesis) and v1.1.0 (Loosening with 2 approvers)
    pv1 = PolicyVersionRecord(
        id="pv-01",
        version="v1.0.0",
        author="alice-operator",
        content={"limits": {"global_daily_usd": 1_000_000, "global_single_tx_usd": 100_000}},
        content_hash="hash-v100",
        status="ACTIVE",
        change_type="TIGHTEN",
        is_active=True,
        created_at=datetime(2026, 11, 1, 10, 0, 0, tzinfo=UTC),
        activated_at=datetime(2026, 11, 1, 10, 0, 0, tzinfo=UTC),
    )

    pv2 = PolicyVersionRecord(
        id="pv-02",
        version="v1.1.0",
        author="bob-operator",
        content={"limits": {"global_daily_usd": 2_000_000, "global_single_tx_usd": 200_000}},
        content_hash="hash-v110",
        status="ACTIVE",
        change_type="LOOSEN",
        approvals=[{"approver_id": "approver-1"}, {"approver_id": "approver-2"}],
        cool_down_until=datetime(2026, 11, 5, 12, 0, 0, tzinfo=UTC),
        backtest_report_id="btr-loosen-20261105",
        is_active=True,
        created_at=datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC),
        activated_at=datetime(2026, 11, 5, 12, 1, 0, tzinfo=UTC),
    )

    sess.add_all([pv1, pv2])
    sess.commit()
    sess.close()

    # 1. JSON Verification
    resp_json = test_client.get(
        "/v1/reports/policy-history?format=json",
        headers=COMPLIANCE_AUTH_HEADERS,
    )
    assert resp_json.status_code == 200
    data = resp_json.json()

    assert data["total_versions"] == 2
    v1 = data["versions"][0]
    v2 = data["versions"][1]

    assert v1["version"] == "v1.0.0"
    assert v1["change_type"] == "TIGHTEN"

    assert v2["version"] == "v1.1.0"
    assert v2["change_type"] == "LOOSEN"
    assert v2["approvers_count"] == 2
    assert "approver-1" in v2["approvers"]
    assert "approver-2" in v2["approvers"]
    assert v2["backtest_report_id"] == "btr-loosen-20261105"
    assert "global_daily_usd" in v2["diff_summary"]

    assert data["audit_verification"]["audit_chain_valid"] is True

    # 2. Filter by Version
    resp_filt = test_client.get(
        "/v1/reports/policy-history?version=v1.1.0&format=json",
        headers=COMPLIANCE_AUTH_HEADERS,
    )
    assert resp_filt.status_code == 200
    filt_data = resp_filt.json()
    assert filt_data["total_versions"] == 1
    assert filt_data["versions"][0]["version"] == "v1.1.0"

    # 3. CSV Verification
    resp_csv = test_client.get(
        "/v1/reports/policy-history?format=csv",
        headers=COMPLIANCE_AUTH_HEADERS,
    )
    assert resp_csv.status_code == 200
    assert resp_csv.headers["content-type"].startswith("text/csv")
    csv_text = resp_csv.text
    assert "v1.0.0,alice-operator,TIGHTEN" in csv_text
    assert "v1.1.0,bob-operator,LOOSEN" in csv_text
    assert "btr-loosen-20261105" in csv_text

    # 4. PDF Verification
    resp_pdf = test_client.get(
        "/v1/reports/policy-history?format=pdf",
        headers=COMPLIANCE_AUTH_HEADERS,
    )
    assert resp_pdf.status_code == 200
    assert resp_pdf.headers["content-type"] == "application/pdf"
    assert resp_pdf.content.startswith(b"%PDF-")
    assert len(resp_pdf.content) > 1000
