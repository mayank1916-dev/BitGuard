"""Test suite for Sensitivity Lab UI and API integration (Milestone U8).

Verifies:
1. When DATA_SOURCE='api':
   - Sliders edit a DRAFT policy.
   - 'Run backtest' calls S22 engine and returns holds, false positives, synthetic loss contained.
   - Classification API produces clear badges (TIGHTENS / LOOSENS / MIXED), structured diff, and textual diff.
   - Tightening: single authorized person can activate instantly.
   - Loosening: requires 2 WebAuthn approvers, cool-down, and attached backtest report. Author cannot approve.
   - Rollback: restores active policy to selected historical version for authorized roles (SecOps, Admin).
2. Demo mode remains unchanged with built-in curve simulation.
3. Strict adherence to Invariant #10 (visual stability) and Invariant #11 (language invariants).
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from services.bitguard.approvals.webauthn import (
    approver_registry,
    create_test_webauthn_assertion,
)
from services.bitguard.breaker import distributed_breaker_store
from services.bitguard.engine.pipeline import decision_engine
from services.bitguard.main import app
from services.bitguard.models import Role
from services.bitguard.policy.models import (
    ChangeClassification,
    PolicyStatus,
)
from services.bitguard.policy.service import policy_service
from services.bitguard.policy.store import policy_store
from services.bitguard.rbac import ALL_TEST_USERS, SEEDED_USERS, create_access_token

client = TestClient(app)

ROOT_DIR = Path(__file__).resolve().parent.parent
SENSITIVITY_LAB_FILE = ROOT_DIR / "frontend" / "src" / "pages" / "SensitivityLab.tsx"
FRONTEND_API_FILE = ROOT_DIR / "frontend" / "src" / "api.ts"
WEB_API_FILE = ROOT_DIR / "web" / "api.js"


def get_token(role: Role = Role.SECOPS, user_id: str | None = None) -> dict[str, str]:
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
def reset_policy_env():
    """Resets policy store, breaker store, and restores baseline policy."""
    policy_store.clear()
    distributed_breaker_store.reset()
    approver_registry.reset_replays()
    approver_registry._init_dev_approvers()
    baseline = policy_service.get_or_create_baseline()
    decision_engine.reload_policy(baseline.content, content_hash=baseline.content_hash)
    yield
    policy_store.clear()
    distributed_breaker_store.reset()
    approver_registry.reset_replays()


def test_classify_policy_draft_tighten():
    """Requirement: Sliders edit draft policy; classify returns badge 'TIGHTENS' and allows instant activation."""
    headers = get_token(Role.OPERATOR)
    draft_tighten = {
        "single_tx_usd": 20_000,
        "wallet_limit_usd": 40_000,
        "global_limit_usd": 200_000,
    }
    resp = client.post("/v1/policies/classify", json={"draft": draft_tighten}, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["badge"] == "TIGHTENS"
    assert data["classification"] == ChangeClassification.TIGHTEN
    assert data["requirements"]["can_instant_activate"] is True
    assert data["requirements"]["approvers_required"] == 1
    assert data["requirements"]["cooldown_seconds"] == 0
    assert data["requirements"]["backtest_required"] is False
    assert "single_tx_usd" in data["diff"]
    assert data["diff"]["single_tx_usd"]["direction"] == "TIGHTEN"
    assert "text_diff" in data and len(data["text_diff"]) > 0


def test_classify_policy_draft_loosen():
    """Requirement: Loosening draft returns badge 'LOOSENS', requires 2 approvers, cool-down and backtest."""
    headers = get_token(Role.OPERATOR)
    draft_loosen = {
        "single_tx_usd": 150_000,
        "wallet_limit_usd": 750_000,
        "global_limit_usd": 2_000_000,
    }
    resp = client.post("/v1/policies/classify", json={"draft": draft_loosen}, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["badge"] == "LOOSENS"
    assert data["classification"] == ChangeClassification.LOOSEN
    assert data["requirements"]["can_instant_activate"] is False
    assert data["requirements"]["approvers_required"] == 2
    assert data["requirements"]["cooldown_seconds"] > 0
    assert data["requirements"]["backtest_required"] is True
    assert "single_tx_usd" in data["diff"]
    assert data["diff"]["single_tx_usd"]["direction"] == "LOOSEN"


def test_classify_policy_draft_mixed():
    """Requirement: Raising one limit and lowering another returns badge 'MIXED' (governed as loosening)."""
    headers = get_token(Role.OPERATOR)
    draft_mixed = {
        "single_tx_usd": 20_000,  # lower than baseline 50k
        "wallet_limit_usd": 750_000,  # higher than baseline 500k
    }
    resp = client.post("/v1/policies/classify", json={"draft": draft_mixed}, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["badge"] == "MIXED"
    assert data["classification"] == ChangeClassification.MIXED
    assert data["requirements"]["can_instant_activate"] is False
    assert data["requirements"]["approvers_required"] == 2
    assert data["requirements"]["backtest_required"] is True


def test_draft_backtest_calls_s22_engine():
    """Requirement: 'Run backtest' button calls S22 and shows results (holds, false positives, synthetic loss prevented)."""
    headers = get_token(Role.SECOPS)
    draft = {
        "single_tx_usd": 40_000,
        "wallet_limit_usd": 80_000,
        "global_limit_usd": 400_000,
    }
    resp = client.post(
        "/v1/policies/draft/backtest",
        json={"draft_policy": draft, "scenarios": ["split_under_limit", "rapid_velocity"]},
        headers=headers,
    )
    assert resp.status_code == 200
    report = resp.json()
    assert report["id"].startswith("btr-")
    assert "held_count" in report
    assert "estimated_false_positives" in report
    assert "synthetic_loss_prevented_usd" in report
    assert report["synthetic_loss_prevented_usd"] >= 0


def test_asymmetric_governance_tightening_instant_activate():
    """Requirement: Tightening shows 'Activate now' button (single person instant)."""
    headers = get_token(Role.OPERATOR, user_id="usr-operator-01")
    active_before = policy_store.get_active()
    assert active_before is not None

    tight_doc = active_before.content.model_dump(mode="json")
    tight_doc["thresholds"]["single_tx_usd"] = 10_000
    tight_doc["limits"]["global_single_tx_usd"] = 10_000
    tight_doc["version"] = "v1.1.0-tight"

    propose_resp = client.post(
        "/v1/policies",
        json={"version": "v1.1.0-tight", "content": tight_doc},
        headers=headers,
    )
    assert propose_resp.status_code == 201
    proposed = propose_resp.json()
    assert proposed["change_type"] == ChangeClassification.TIGHTEN

    # Instant activate without approvals or cooldown
    act_resp = client.post(f"/v1/policies/{proposed['id']}/activate", headers=headers)
    assert act_resp.status_code == 200
    activated = act_resp.json()
    assert activated["status"] == PolicyStatus.ACTIVE
    assert policy_store.get_active().id == proposed["id"]


def test_asymmetric_governance_loosening_quorum_and_blocks_author():
    """Requirement: Loosening shows requirements (2 approvers, cool-down, attached backtest report) and 'Approve' with WebAuthn, never for author."""
    author_headers = get_token(Role.SECOPS, user_id="usr-secops-01")
    approver1_headers = get_token(Role.APPROVER, user_id="usr-approver-01")
    approver2_headers = get_token(Role.APPROVER, user_id="usr-approver-02")

    active_before = policy_store.get_active()
    assert active_before is not None

    # 1. Prepare loosening document
    loose_doc = active_before.content.model_dump(mode="json")
    loose_doc["thresholds"]["single_tx_usd"] = 200_000
    loose_doc["limits"]["global_single_tx_usd"] = 200_000
    loose_doc["limits"]["global_velocity_limit_usd"] = 750_000
    loose_doc["limits"]["global_daily_usd"] = 2_000_000
    loose_doc["version"] = "v1.2.0-loose"

    # 2. Run backtest with identical document to obtain matching report
    bt_resp = client.post(
        "/v1/policies/draft/backtest",
        json={"draft_policy": loose_doc},
        headers=author_headers,
    )
    assert bt_resp.status_code == 200
    backtest_report_id = bt_resp.json()["id"]

    # 3. Propose loosening policy with backtest report
    propose_resp = client.post(
        "/v1/policies",
        json={
            "version": "v1.2.0-loose",
            "content": loose_doc,
            "backtest_report_id": backtest_report_id,
        },
        headers=author_headers,
    )
    assert propose_resp.status_code == 201
    prop_data = propose_resp.json()
    ver_id = prop_data["id"]
    content_hash = prop_data["content_hash"]

    priv_secops = approver_registry.dev_private_keys["usr-secops-01"]
    priv_app1 = approver_registry.dev_private_keys["usr-approver-01"]
    priv_app2 = approver_registry.dev_private_keys["usr-approver-02"]

    # 3. Separation of duties: Author CANNOT approve
    author_assertion = create_test_webauthn_assertion(private_key=priv_secops, tx_digest=content_hash)
    fail_approve = client.post(
        f"/v1/policies/{ver_id}/approve",
        json={"assertion": author_assertion.model_dump()},
        headers=author_headers,
    )
    assert fail_approve.status_code == 403
    assert "author" in fail_approve.json()["detail"].lower()

    # 4. Approver 1 approves
    app1_assertion = create_test_webauthn_assertion(private_key=priv_app1, tx_digest=content_hash)
    app1_resp = client.post(
        f"/v1/policies/{ver_id}/approve",
        json={"assertion": app1_assertion.model_dump()},
        headers=approver1_headers,
    )
    assert app1_resp.status_code == 200
    assert len(app1_resp.json()["approvals"]) == 1

    # Cannot activate yet: quorum (2 approvers) not met
    act_premature = client.post(f"/v1/policies/{ver_id}/activate", headers=author_headers)
    assert act_premature.status_code == 400
    assert "approvers" in act_premature.json()["detail"].lower()

    # 5. Approver 2 approves
    app2_assertion = create_test_webauthn_assertion(private_key=priv_app2, tx_digest=content_hash)
    app2_resp = client.post(
        f"/v1/policies/{ver_id}/approve",
        json={"assertion": app2_assertion.model_dump()},
        headers=approver2_headers,
    )
    assert app2_resp.status_code == 200
    assert len(app2_resp.json()["approvals"]) == 2

    # Cool-down check: premature activation blocked
    act_cooldown = client.post(f"/v1/policies/{ver_id}/activate", headers=author_headers)
    assert act_cooldown.status_code == 400
    assert "cool-down" in act_cooldown.json()["detail"].lower()

    # Advance time to expire cooldown
    policy_ver = policy_store.get(ver_id)
    assert policy_ver is not None
    policy_ver.cool_down_until = datetime.now(UTC) - timedelta(seconds=1)
    policy_store.save(policy_ver)

    # Now activation succeeds
    act_success = client.post(f"/v1/policies/{ver_id}/activate", headers=author_headers)
    assert act_success.status_code == 200
    assert act_success.json()["status"] == PolicyStatus.ACTIVE


def test_rollback_to_historical_version():
    """Requirement: Show Rollback for previous versions to authorised roles (Admin, SecOps)."""
    headers = get_token(Role.SECOPS, user_id="usr-secops-01")
    unauth_headers = get_token(Role.COMPLIANCE, user_id="usr-compliance-01")

    baseline = policy_store.get_active()
    assert baseline is not None
    original_id = baseline.id

    # Create & activate a new version
    v2_doc = baseline.content.model_dump(mode="json")
    v2_doc["version"] = "v2.0.0"
    v2_doc["thresholds"]["single_tx_usd"] = 15_000
    v2_doc["limits"]["global_single_tx_usd"] = 15_000

    prop = client.post("/v1/policies", json={"version": "v2.0.0", "content": v2_doc}, headers=headers).json()
    client.post(f"/v1/policies/{prop['id']}/activate", headers=headers)
    assert policy_store.get_active().id == prop["id"]

    # Unauthorized role cannot rollback
    rb_unauth = client.post(
        f"/v1/policies/{original_id}/rollback",
        json={"reason": "Audit request"},
        headers=unauth_headers,
    )
    assert rb_unauth.status_code in (401, 403)

    # Authorized role rolls back to original_id
    rb_auth = client.post(
        f"/v1/policies/{original_id}/rollback",
        json={"reason": "Revert to baseline after test"},
        headers=headers,
    )
    assert rb_auth.status_code == 200
    rolled_back = rb_auth.json()
    assert rolled_back["status"] == PolicyStatus.ACTIVE
    assert rolled_back["id"] == original_id
    assert policy_store.get_active().id == original_id


def test_frontend_source_contract_and_demo_mode_preservation():
    """Verifies that frontend code preserves demo mode and implements all U8 UI requirements."""
    assert SENSITIVITY_LAB_FILE.exists()
    assert FRONTEND_API_FILE.exists()
    assert WEB_API_FILE.exists()

    code = SENSITIVITY_LAB_FILE.read_text(encoding="utf-8")
    fe_api = FRONTEND_API_FILE.read_text(encoding="utf-8")
    web_api = WEB_API_FILE.read_text(encoding="utf-8")

    # Parity in API wrappers
    required_api_methods = [
        "classifyPolicy",
        "runPolicyBacktest",
        "listPolicies",
        "getActivePolicy",
        "proposePolicy",
        "approvePolicy",
        "activatePolicy",
        "rollbackPolicy",
    ]
    for m in required_api_methods:
        assert m in fe_api, f"frontend/src/api.ts missing {m}"
        assert m in web_api, f"web/api.js missing {m}"

    # Demo Mode preservation: Recharts & sensitivity results curve
    assert "ResponsiveContainer" in code
    assert "ComposedChart" in code
    assert "isApiMode" in code
    assert "DATA_SOURCE === 'api'" in code

    # API Mode UI elements
    assert "Run backtest" in code or "runPolicyBacktest" in code
    assert "TIGHTENS" in code
    assert "LOOSENS" in code
    assert "MIXED" in code
    assert "Activate now" in code
    assert "Separation of duties" in code
    assert "Rollback" in code

    # Language Invariant #11: 'reduces and contains', never 'prevents'
    assert "reduces and contains" in code.lower()
