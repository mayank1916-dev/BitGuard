"""Comprehensive test suite for Task U6 - Circuit Breaker Controls.

Covers:
- GET /v1/breaker operational state, reason, updated_by, token_epoch
- Instant POST /v1/breaker/escalate to LOCKDOWN with token epoch increment
- De-escalation proposal POST /v1/breaker/deescalate-request (only allowed when > NORMAL)
- GET /v1/breaker/deescalate-requests/active
- Two-approver WebAuthn quorum POST /v1/breaker/deescalate-approve:
  - Requester separation of duties check
  - Same approver twice rejected
  - Quorum achieved lowers state back to NORMAL
- Verification of UI and API client implementations for U6 requirements
"""

from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from services.bitguard.approvals.webauthn import (
    approver_registry,
    create_test_webauthn_assertion,
)
from services.bitguard.breaker.store import distributed_breaker_store
from services.bitguard.main import app
from services.bitguard.models import Role
from services.bitguard.rbac import ALL_TEST_USERS, SEEDED_USERS, create_access_token


@pytest.fixture
def test_client() -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_breaker_state() -> Generator[None, None, None]:
    distributed_breaker_store.reset()
    yield
    distributed_breaker_store.reset()


def get_token_for_role(role: Role) -> str:
    user = SEEDED_USERS[role]
    return create_access_token(user)


def get_token_for_user_id(user_id: str) -> str:
    user = ALL_TEST_USERS[user_id]
    return create_access_token(user)


def test_get_breaker_status(test_client: TestClient) -> None:
    """Verifies GET /v1/breaker returns operational status, reason, updated_by, epoch."""
    token = get_token_for_role(Role.OPERATOR)
    res = test_client.get("/v1/breaker", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()

    assert data["state"] == "NORMAL"
    assert "reason" in data
    assert "updated_by" in data
    assert data["token_epoch"] >= 1
    assert data["data_label"] in ["REAL", "SYNTHETIC", "REPORTED"]


def test_instant_escalate_to_lockdown(test_client: TestClient) -> None:
    """SecOps or Admin can instantly escalate to LOCKDOWN, which increments token epoch."""
    secops_token = get_token_for_role(Role.SECOPS)
    initial_res = test_client.get("/v1/breaker", headers={"Authorization": f"Bearer {secops_token}"})
    initial_epoch = initial_res.json()["token_epoch"]

    # Trigger emergency lockdown
    res = test_client.post(
        "/v1/breaker/escalate",
        json={
            "target_state": "LOCKDOWN",
            "reason": "SecOps triggered emergency lockdown due to anomalous spike",
        },
        headers={"Authorization": f"Bearer {secops_token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["state"] == "LOCKDOWN"
    assert "SecOps triggered emergency lockdown" in data["reason"]
    assert data["token_epoch"] == initial_epoch + 1

    # Operator role cannot escalate (RBAC check)
    operator_token = get_token_for_role(Role.OPERATOR)
    unauth_res = test_client.post(
        "/v1/breaker/escalate",
        json={"target_state": "LOCKDOWN", "reason": "Operator attempt"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert unauth_res.status_code == 403


def test_unlock_request_and_two_approver_quorum(test_client: TestClient) -> None:
    """Verifies creating an unlock proposal and achieving 2-approver WebAuthn quorum."""
    admin_token = get_token_for_user_id("usr-admin-01")

    # 1. First escalate breaker to HOLD
    esc_res = test_client.post(
        "/v1/breaker/escalate",
        json={"target_state": "HOLD", "reason": "Investigation underway"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert esc_res.status_code == 200

    # 2. Admin creates unlock proposal to return to NORMAL
    prop_res = test_client.post(
        "/v1/breaker/deescalate-request",
        json={"target_state": "NORMAL", "reason": "Root cause resolved; clear to resume"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert prop_res.status_code == 201
    prop_data = prop_res.json()
    request_id = prop_data["id"]
    challenge = prop_data["challenge"]
    assert prop_data["requested_by"] == "usr-admin-01"
    assert prop_data["target_state"] == "NORMAL"
    assert prop_data["status"] == "PENDING"

    # 3. Fetch active de-escalation request
    active_res = test_client.get("/v1/breaker/deescalate-requests/active", headers={"Authorization": f"Bearer {admin_token}"})
    assert active_res.status_code == 200
    assert active_res.json()["id"] == request_id

    # 4. Separation of duties: requester (usr-admin-01) cannot approve their own unlock request
    priv_key_admin = approver_registry.dev_private_keys["usr-admin-01"]
    admin_assertion = create_test_webauthn_assertion(priv_key_admin, challenge)
    self_approve_res = test_client.post(
        "/v1/breaker/deescalate-approve",
        json={"request_id": request_id, "assertion": admin_assertion.model_dump()},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert self_approve_res.status_code == 400
    assert "Separation of duties" in self_approve_res.json()["detail"]

    # 5. Approver 1 (usr-approver-01) signs with WebAuthn (1 of 2)
    approver1_token = get_token_for_user_id("usr-approver-01")
    priv_key_appr1 = approver_registry.dev_private_keys["usr-approver-01"]
    appr1_assertion = create_test_webauthn_assertion(priv_key_appr1, challenge)
    appr1_res = test_client.post(
        "/v1/breaker/deescalate-approve",
        json={"request_id": request_id, "assertion": appr1_assertion.model_dump()},
        headers={"Authorization": f"Bearer {approver1_token}"},
    )
    assert appr1_res.status_code == 200
    appr1_data = appr1_res.json()
    assert appr1_data["status"] == "PENDING"
    assert appr1_data["approvals_count"] == 1

    # 6. Approver 1 cannot approve a second time
    dup_res = test_client.post(
        "/v1/breaker/deescalate-approve",
        json={"request_id": request_id, "assertion": appr1_assertion.model_dump()},
        headers={"Authorization": f"Bearer {approver1_token}"},
    )
    assert dup_res.status_code == 400
    assert "already approved" in dup_res.json()["detail"]

    # 7. Approver 2 (usr-approver-02) signs with WebAuthn (2 of 2 -> QUORUM REACHED!)
    approver2_token = get_token_for_user_id("usr-approver-02")
    priv_key_appr2 = approver_registry.dev_private_keys["usr-approver-02"]
    appr2_assertion = create_test_webauthn_assertion(priv_key_appr2, challenge)
    appr2_res = test_client.post(
        "/v1/breaker/deescalate-approve",
        json={"request_id": request_id, "assertion": appr2_assertion.model_dump()},
        headers={"Authorization": f"Bearer {approver2_token}"},
    )
    assert appr2_res.status_code == 200
    appr2_data = appr2_res.json()
    assert appr2_data["status"] == "APPROVED"
    assert appr2_data["approvals_count"] == 2
    assert appr2_data["new_breaker_state"] == "NORMAL"

    # 8. Breaker state is now de-escalated to NORMAL
    final_res = test_client.get("/v1/breaker", headers={"Authorization": f"Bearer {admin_token}"})
    assert final_res.status_code == 200
    assert final_res.json()["state"] == "NORMAL"


def test_ui_and_api_files_contain_u6_requirements() -> None:
    """Verifies that the UI components and client modules contain all U6 requirements."""
    # 1. BreakerModal component exists and implements required flows
    modal_file = Path("frontend/src/components/BreakerModal.tsx")
    assert modal_file.exists()
    content = modal_file.read_text(encoding="utf-8")

    assert "Circuit Breaker Controls" in content
    assert "TRIGGER BREAKER LOCKDOWN" in content
    assert "CONFIRM & EXECUTE LOCKDOWN NOW" in content
    assert "CREATE UNLOCK REQUEST" in content
    assert "APPROVE UNLOCK WITH WEBAUTHN HARDWARE KEY" in content
    assert "Separation of duties" in content
    assert "Last State Transition Telemetry" in content
    assert "Triggered By" in content
    assert "Reason Code & Details" in content

    # 2. Navbar has interactive breaker pill
    navbar_file = Path("frontend/src/components/Navbar.tsx")
    nav_content = navbar_file.read_text(encoding="utf-8")
    assert "onOpenBreakerModal" in nav_content
    assert "Click to view and manage Circuit Breaker Controls" in nav_content

    # 3. App wires breaker modal and stream updates
    app_file = Path("frontend/src/App.tsx")
    app_content = app_file.read_text(encoding="utf-8")
    assert "BreakerModal" in app_content
    assert "isBreakerModalOpen" in app_content
    assert "breaker_state_change" in app_content

    # 4. API client modules export required helpers
    api_ts = Path("frontend/src/api.ts").read_text(encoding="utf-8")
    assert "createDeescalationRequest" in api_ts
    assert "approveDeescalation" in api_ts
    assert "fetchActiveDeescalationRequest" in api_ts

    api_js = Path("web/api.js").read_text(encoding="utf-8")
    assert "createDeescalationRequest" in api_js
    assert "approveDeescalation" in api_js
    assert "fetchActiveDeescalationRequest" in api_js
