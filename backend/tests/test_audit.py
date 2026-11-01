import pytest
from fastapi.testclient import TestClient

from backend.app.core.audit import AuditLog, compute_entry_hash
from backend.app.main import create_app
from backend.app.models import Decision


def test_genesis_block_and_hash_chain():
    """Verify genesis block has 64-zero prev_hash and hash chaining is deterministic."""
    audit = AuditLog()
    e0 = audit.append_entry(
        request_id="req-001",
        action="allow",
        risk=5,
        rule_hits=[],
        timestamp=1730300000.0,
    )

    assert e0.index == 0
    assert e0.prev_hash == "0" * 64
    assert len(e0.entry_hash) == 64

    # Verify deterministic hash calculation
    expected_hash0 = compute_entry_hash(
        prev_hash="0" * 64,
        timestamp=1730300000.0,
        request_id="req-001",
        action="allow",
        risk=5,
        rule_hits=[],
    )
    assert e0.entry_hash == expected_hash0

    # Append second entry
    e1 = audit.append_entry(
        request_id="req-002",
        action="deny",
        risk=95,
        rule_hits=["delegation_denied"],
        timestamp=1730300010.0,
    )

    assert e1.index == 1
    assert e1.prev_hash == e0.entry_hash
    assert e1.entry_hash != e0.entry_hash


def test_audit_integrity_verification_and_tamper_detection():
    """Verify verify_integrity() detects tampering and returns the exact corrupted index."""
    audit = AuditLog()
    for i in range(5):
        audit.append_entry(
            request_id=f"req-{i:03d}",
            action="deny" if i % 2 == 1 else "allow",
            risk=90 if i % 2 == 1 else 10,
            rule_hits=["spray_detected"] if i % 2 == 1 else [],
            timestamp=1730300000.0 + i * 10,
        )

    # Intact chain
    is_valid, corrupted_idx = audit.verify_integrity()
    assert is_valid is True
    assert corrupted_idx is None

    # Corrupt index 2
    corrupted = audit.tamper_test_corrupt_entry(2)
    assert corrupted is True

    # Re-verify should fail at index 2
    is_valid_after, detected_corrupt_idx = audit.verify_integrity()
    assert is_valid_after is False
    assert detected_corrupt_idx == 2

    # Reset restores integrity
    audit.reset()
    is_valid_restored, no_corrupt = audit.verify_integrity()
    assert is_valid_restored is True
    assert no_corrupt is None


def test_audit_api_endpoints_and_pdf_download():
    """Verify audit endpoints and PDF post-mortem download stream."""
    app = create_app()
    client = TestClient(app)

    # 1. Audit records
    res_records = client.get("/api/audit/records")
    assert res_records.status_code == 200
    records_body = res_records.json()
    assert "root_hash" in records_body
    assert records_body["total_records"] > 0
    assert len(records_body["records"]) > 0

    # 2. Audit verify
    res_verify = client.get("/api/audit/verify")
    assert res_verify.status_code == 200
    verify_body = res_verify.json()
    assert verify_body["valid"] is True
    assert verify_body["corrupted_index"] is None

    # 3. Simulate tamper
    res_tamper = client.post("/api/audit/simulate-tamper?index=1")
    assert res_tamper.status_code == 200
    tamper_body = res_tamper.json()
    assert tamper_body["is_chain_valid"] is False
    assert tamper_body["detected_corrupted_index"] == 1

    # 4. Verify detects tamper
    res_verify_tampered = client.get("/api/audit/verify")
    assert res_verify_tampered.json()["valid"] is False
    assert res_verify_tampered.json()["corrupted_index"] == 1

    # 5. Reset audit
    res_reset = client.post("/api/audit/reset")
    assert res_reset.status_code == 200
    assert res_reset.json()["valid"] is True

    # 6. Verify restored
    res_verify_clean = client.get("/api/audit/verify")
    assert res_verify_clean.json()["valid"] is True
    assert res_verify_clean.json()["corrupted_index"] is None

    # 7. Post-mortem PDF stream
    res_pdf = client.get("/api/report/download")
    assert res_pdf.status_code == 200
    assert res_pdf.headers["content-type"] == "application/pdf"
    assert "attachment; filename=\"bitguard_incident_report.pdf\"" in res_pdf.headers.get("content-disposition", "")
    assert res_pdf.content.startswith(b"%PDF-")
    assert len(res_pdf.content) > 1000
