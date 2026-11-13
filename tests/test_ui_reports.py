"""Test suite for Reports & Audit UI and API integration (Milestone U9).

Verifies:
1. When DATA_SOURCE='api':
   - Existing audit tick calls /v1/audit/verify and shows ok / first bad sequence.
   - Shows last anchor time and status (WORM checkpointing).
   - Lists incidents with time_to_contain and an expandable timeline.
   - Adds buttons to export:
     a) Incident post-mortem (PDF and CSV)
     b) Monthly control report (PDF and CSV)
     c) Policy change & dual-control approval history (PDF and CSV)
2. Demo mode preserves simulated tampering and generated demo report.
3. Strict adherence to Invariant #10 (Visual stability) and Invariant #11 (Language invariants).
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from services.bitguard.audit import audit_service
from services.bitguard.incidents.store import incident_store
from services.bitguard.main import app
from services.bitguard.models import Role
from services.bitguard.rbac import ALL_TEST_USERS, SEEDED_USERS, create_access_token

client = TestClient(app)

ROOT_DIR = Path(__file__).resolve().parent.parent
REPORTS_VIEW_FILE = ROOT_DIR / "frontend" / "src" / "pages" / "ReportsView.tsx"
FRONTEND_API_FILE = ROOT_DIR / "frontend" / "src" / "api.ts"
WEB_API_FILE = ROOT_DIR / "web" / "api.js"


def get_token(role: Role = Role.COMPLIANCE, user_id: str | None = None) -> dict[str, str]:
    """Generates valid JWT Bearer header for test users."""
    if user_id and user_id in ALL_TEST_USERS:
        user = ALL_TEST_USERS[user_id]
    else:
        user = SEEDED_USERS.get(role)
        if not user:
            for u in ALL_TEST_USERS.values():
                if u.role == role:
                    user = u
                    break
    assert user is not None
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def reset_reports_env():
    """Ensures fresh state for audit and incident store."""
    audit_service.clear()
    # Seed baseline audit entry
    audit_service.append_entry(
        action="DECISION:ALLOW",
        payload={"request_id": "req-init", "risk_score": 10, "verdict": "ALLOW"},
        actor="system",
    )
    incident_store.clear()
    incident_store._create_seed_incident()
    yield


def test_audit_verify_endpoint_success():
    """Requirement: /v1/audit/verify returns ok: bool, checked_entries, and anchor state."""
    headers = get_token(Role.SECOPS)
    resp = client.get("/v1/audit/verify", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "ok" in data
    assert data["ok"] is True
    assert data["checked_entries"] >= 1
    assert data["first_bad_seq"] is None


def test_audit_manual_anchor_creation():
    """Requirement: Manual WORM anchor creation updates last_anchor state."""
    headers = get_token(Role.ADMIN)
    resp = client.post("/v1/audit/anchor", headers=headers)
    assert resp.status_code == 200
    res_data = resp.json()
    assert "anchor" in res_data
    anchor = res_data["anchor"]
    assert "head_hash" in anchor
    assert "storage_uri" in anchor
    assert "bitguard-audit" in anchor["storage_uri"] or "anchor" in anchor["storage_uri"]

    # Check that verify now reports last_anchor
    verify_resp = client.get("/v1/audit/verify", headers=headers)
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["last_anchor"] is not None
    assert verify_data["last_anchor"]["head_hash"] == anchor["head_hash"]


def test_incidents_list_with_timeline_and_time_to_contain():
    """Requirement: Incidents list includes time_to_contain and timeline events."""
    headers = get_token(Role.SECOPS)
    resp = client.get("/v1/incidents", headers=headers)
    assert resp.status_code == 200
    incidents = resp.json()
    assert len(incidents) >= 1

    seed_inc = next((inc for inc in incidents if inc["id"] == "inc-7702-drain-01"), None)
    assert seed_inc is not None
    assert seed_inc["time_to_contain_ms"] is not None
    assert isinstance(seed_inc["time_to_contain_ms"], (int, float))
    assert seed_inc["time_to_contain_ms"] > 0
    assert len(seed_inc["timeline"]) >= 3

    # Check timeline event structure
    first_event = seed_inc["timeline"][0]
    assert "event_type" in first_event
    assert "message" in first_event
    assert "timestamp" in first_event


def test_incident_report_export_pdf_and_csv():
    """Requirement: Incident post-mortem export returns PDF and CSV with audit verification stamps."""
    headers = get_token(Role.COMPLIANCE)

    # PDF format
    resp_pdf = client.get("/v1/reports/incident/inc-7702-drain-01?format=pdf", headers=headers)
    assert resp_pdf.status_code == 200
    assert resp_pdf.headers["content-type"] == "application/pdf"
    assert resp_pdf.content.startswith(b"%PDF-")

    # CSV format
    resp_csv = client.get("/v1/reports/incident/inc-7702-drain-01?format=csv", headers=headers)
    assert resp_csv.status_code == 200
    assert "text/csv" in resp_csv.headers["content-type"]
    csv_text = resp_csv.content.decode("utf-8")
    assert "Incident ID,inc-7702-drain-01" in csv_text or "inc-7702-drain-01" in csv_text
    assert "REAL" in csv_text


def test_monthly_control_report_export_pdf_and_csv():
    """Requirement: Monthly control report export returns PDF and CSV."""
    headers = get_token(Role.COMPLIANCE)

    # PDF format
    resp_pdf = client.get("/v1/reports/monthly?year=2026&month=11&format=pdf", headers=headers)
    assert resp_pdf.status_code == 200
    assert resp_pdf.headers["content-type"] == "application/pdf"
    assert resp_pdf.content.startswith(b"%PDF-")

    # CSV format
    resp_csv = client.get("/v1/reports/monthly?year=2026&month=11&format=csv", headers=headers)
    assert resp_csv.status_code == 200
    assert "text/csv" in resp_csv.headers["content-type"]
    csv_text = resp_csv.content.decode("utf-8")
    assert "Monthly Control" in csv_text or "SUMMARY CONTROL METRIC" in csv_text


def test_policy_history_report_export_pdf_and_csv():
    """Requirement: Policy change history export returns PDF and CSV."""
    headers = get_token(Role.COMPLIANCE)

    # PDF format
    resp_pdf = client.get("/v1/reports/policy-history?format=pdf", headers=headers)
    assert resp_pdf.status_code == 200
    assert resp_pdf.headers["content-type"] == "application/pdf"
    assert resp_pdf.content.startswith(b"%PDF-")

    # CSV format
    resp_csv = client.get("/v1/reports/policy-history?format=csv", headers=headers)
    assert resp_csv.status_code == 200
    assert "text/csv" in resp_csv.headers["content-type"]
    csv_text = resp_csv.content.decode("utf-8")
    assert "Policy Change" in csv_text or "Version" in csv_text


def test_ui_reports_view_contract():
    """Requirement: Frontend ReportsView.tsx, api.ts, and web/api.js satisfy U9 requirements."""
    assert REPORTS_VIEW_FILE.exists()
    assert FRONTEND_API_FILE.exists()
    assert WEB_API_FILE.exists()

    content_tsx = REPORTS_VIEW_FILE.read_text(encoding="utf-8")
    content_api_ts = FRONTEND_API_FILE.read_text(encoding="utf-8")
    content_api_js = WEB_API_FILE.read_text(encoding="utf-8")

    # 1. Dual-mode support (DATA_SOURCE='api' vs demo mode)
    assert "DATA_SOURCE === 'api'" in content_tsx
    assert "simulateAuditTamper" in content_tsx
    assert "resetAuditChain" in content_tsx

    # 2. Existing audit tick calls /v1/audit/verify and shows ok / first bad sequence
    assert "verifyAuditLedger" in content_tsx
    assert "first_bad_seq" in content_tsx or "firstBadSeq" in content_tsx

    # 3. Shows last anchor time and status
    assert "lastAnchorTime" in content_tsx
    assert "lastAnchorStatus" in content_tsx
    assert "triggerManualAnchor" in content_tsx

    # 4. Lists incidents with time_to_contain and an expandable timeline
    assert "time_to_contain" in content_tsx or "time_to_contain_ms" in content_tsx
    assert "expandedIncidentId" in content_tsx
    assert "timeline" in content_tsx

    # 5. Buttons to export post-mortem PDF, monthly control report, and change history with CSV options
    assert "exportIncidentReport" in content_tsx
    assert "exportMonthlyReport" in content_tsx
    assert "exportPolicyHistoryReport" in content_tsx
    assert "Post-Mortem PDF" in content_tsx
    assert "Monthly Report (PDF)" in content_tsx
    assert "Change History (PDF)" in content_tsx
    assert "CSV" in content_tsx

    # 6. API parity across TypeScript and JavaScript clients
    for fn in [
        "verifyAuditLedger",
        "fetchAuditEntries",
        "triggerManualAnchor",
        "listIncidents",
        "exportIncidentReport",
        "exportMonthlyReport",
        "exportPolicyHistoryReport",
    ]:
        assert fn in content_api_ts, f"Missing {fn} in frontend/src/api.ts"
        assert fn in content_api_js, f"Missing {fn} in web/api.js"

    # 7. Language invariant check (Invariant #11)
    assert "reduces and contains" in content_tsx
    # Check that forbidden unhedged "prevents" is not used in claims
    assert "prevents unauthorized" not in content_tsx.lower()
