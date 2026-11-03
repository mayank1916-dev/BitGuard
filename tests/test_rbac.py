"""Unit and integration tests for development-grade RBAC, JWT tokens, permission matrix, and access logs (Milestone S05 / F9 basic)."""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from services.bitguard.config import settings
from services.bitguard.main import app
from services.bitguard.models import Role
from services.bitguard.rbac import (
    SEEDED_USERS,
    access_denied_log,
    create_access_token,
    decode_access_token,
    hook_policy_author_cannot_approve_own_change,
    hook_requester_cannot_approve_own_request,
)

client = TestClient(app)


def test_dev_login_endpoint_all_roles():
    """POST /v1/auth/dev-token issues valid signed JWTs for all seeded test users."""
    for role in Role:
        response = client.post("/v1/auth/dev-token", json={"role": role.value})
        assert response.status_code == 200, f"Dev login failed for role {role.value}"
        data = response.json()

        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == settings.jwt_expiration_seconds
        assert data["user"]["role"] == role.value
        assert data["user"]["email"] == f"{role.value.lower()}@bitguard.local"

        # Verify cryptographic signature and claims
        payload = decode_access_token(data["access_token"])
        assert payload["role"] == role.value
        assert payload["email"] == f"{role.value.lower()}@bitguard.local"
        assert len(payload["permissions"]) > 0


def test_dev_login_disabled_in_production(monkeypatch: pytest.MonkeyPatch):
    """POST /v1/auth/dev-token returns 403 Forbidden when ENV=production (DEV ONLY)."""
    monkeypatch.setattr(settings, "environment", "production")

    response = client.post("/v1/auth/dev-token", json={"role": "Operator"})
    assert response.status_code == 403
    assert "disabled in production" in response.json()["detail"]


@pytest.mark.parametrize(
    ("role", "can_read_decisions", "can_submit_sign", "can_mark_fp"),
    [
        (Role.VIEWER, True, False, False),
        (Role.OPERATOR, True, True, True),
        (Role.SECOPS, True, True, False),
        (Role.COMPLIANCE, True, False, False),
        (Role.APPROVER, True, False, False),
        (Role.ADMIN, True, True, True),
    ],
)
def test_permission_matrix_across_roles_and_routes(
    role: Role,
    can_read_decisions: bool,
    can_submit_sign: bool,
    can_mark_fp: bool,
):
    """Parametrised permission matrix tests verifying allowed vs forbidden routes per role."""
    # Obtain signed JWT token for this role
    user = SEEDED_USERS[role]
    token = create_access_token(user)
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Test Read Decisions (GET /v1/decisions)
    res_dec = client.get("/v1/decisions", headers=headers)
    if can_read_decisions:
        assert res_dec.status_code == 200
    else:
        assert res_dec.status_code == 403

    # 2. Test Submit Sign Request (POST /v1/sign-requests)
    sign_payload = {
        "id": f"rbac-req-{role.value}",
        "raw_tx": "0x02f87001",
        "chain": "ethereum",
        "wallet": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    }
    res_sign = client.post("/v1/sign-requests", headers=headers, json=sign_payload)
    if can_submit_sign:
        assert res_sign.status_code == 200
    else:
        assert res_sign.status_code == 403

    # 3. Test Mark False Positive (POST /v1/decisions/{id}/false-positive)
    # First create a decision using an admin token so we have a valid blocked candidate
    admin_token = create_access_token(SEEDED_USERS[Role.ADMIN])
    setup_payload = {
        "id": f"fp-candidate-{role.value}",
        "raw_tx": "0x02f87001",
        "chain": "ethereum",
        "wallet": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "metadata": {"simulate_deny": True},
    }
    client.post(
        "/v1/sign-requests",
        headers={"Authorization": f"Bearer {admin_token}"},
        json=setup_payload,
    )

    res_fp = client.post(
        f"/v1/decisions/fp-candidate-{role.value}/false-positive",
        headers=headers,
        json={"reason": "Testing RBAC matrix"},
    )
    if can_mark_fp:
        assert res_fp.status_code == 200
    else:
        assert res_fp.status_code == 403


def test_denied_access_logging():
    """Verify denied access attempts are logged with user, route, method, and timestamp."""
    initial_log_count = len(access_denied_log)

    # Viewer role attempting to submit a signing request
    viewer_token = create_access_token(SEEDED_USERS[Role.VIEWER])
    headers = {"Authorization": f"Bearer {viewer_token}"}
    payload = {
        "id": "denied-test-req",
        "raw_tx": "0x02f87001",
        "chain": "ethereum",
        "wallet": "0x123",
    }

    res = client.post("/v1/sign-requests", headers=headers, json=payload)
    assert res.status_code == 403

    # Check that denied access was captured in the log store
    assert len(access_denied_log) > initial_log_count
    last_log = access_denied_log[-1]
    assert last_log["user"] == "viewer@bitguard.local"
    assert last_log["route"] == "/v1/sign-requests"
    assert last_log["method"] == "POST"
    assert last_log["role"] == "Viewer"
    assert "timestamp" in last_log


def test_unauthenticated_and_invalid_token_handling():
    """Unauthenticated requests or invalid tokens return 401 Unauthorized."""
    # 1. Explicit unauthenticated header
    res_anon = client.get("/v1/decisions", headers={"X-Anonymous": "true"})
    assert res_anon.status_code == 401

    # 2. Malformed token
    res_bad = client.get("/v1/decisions", headers={"Authorization": "Bearer not-a-valid-jwt"})
    assert res_bad.status_code == 401

    # 3. Expired token
    expired_token = create_access_token(
        SEEDED_USERS[Role.ADMIN],
        expires_delta=timedelta(seconds=-10),
    )
    res_expired = client.get("/v1/decisions", headers={"Authorization": f"Bearer {expired_token}"})
    assert res_expired.status_code == 401
    assert "expired" in res_expired.json()["detail"].lower()


def test_separation_of_duties_hooks():
    """Verify rule engine hooks for separation of duties."""
    # Hook 1: Requester cannot approve own request
    assert hook_requester_cannot_approve_own_request("user-alpha", "user-alpha") is False
    assert hook_requester_cannot_approve_own_request("user-alpha", "user-beta") is True

    # Hook 2: Policy author cannot approve own policy change
    assert hook_policy_author_cannot_approve_own_change("author-sec", "author-sec") is False
    assert hook_policy_author_cannot_approve_own_change("author-sec", "approver-ciso") is True
