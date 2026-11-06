"""Integration and unit tests for OIDC SSO, WebAuthn hardware keys, separation of duties, and step-up (Milestone S15 / F9).

Invariants Verified:
- Invariant #1: Key Isolation (BitGuard never holds private signing keys).
- Invariant #3: Fail-Closed Default (invalid tokens, replay attacks, sign count regressions fail closed).
- Invariant #5: WebAuthn Hardware Approvals (hardware keys required for sensitive actions and step-up).
- Invariant #6: Asymmetric Policy Evolution & Dual Control (separation of duties enforced centrally).
- Invariant #7: Immutable Audit Trail (admin actions recorded with webauthn_assertion_ref).
"""

import hashlib
import json
import struct
from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any

import cbor2
import jwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from webauthn.helpers import bytes_to_base64url

from services.bitguard.audit_service import audit_service
from services.bitguard.auth.oidc import oidc_auth_service
from services.bitguard.auth.separation import (
    SeparationOfDutiesError,
    separation_of_duties,
)
from services.bitguard.auth.webauthn_store import (
    challenge_store,
    webauthn_credential_store,
)
from services.bitguard.config import settings
from services.bitguard.main import create_app
from services.bitguard.models import Role


@pytest.fixture(autouse=True)
def clean_auth_state() -> Generator[None, None, None]:
    """Resets credential store, challenges, and audit service before each test."""
    webauthn_credential_store.clear()
    challenge_store.clear()
    audit_service.clear()
    orig_env = settings.environment
    orig_bypass = settings.dev_auth_bypass
    orig_enforce_stepup = settings.enforce_step_up
    yield
    settings.environment = orig_env
    settings.dev_auth_bypass = orig_bypass
    settings.enforce_step_up = orig_enforce_stepup


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


# =========================================================================
# 1. OIDC SSO Login & Role Mapping Tests
# =========================================================================


def test_oidc_role_mapping_precedence() -> None:
    """Verifies Keycloak realm role mapping follows least-privilege precedence."""
    assert oidc_auth_service.map_realm_roles(["Admin"]) == Role.ADMIN
    assert oidc_auth_service.map_realm_roles(["SecOps"]) == Role.SECOPS
    assert oidc_auth_service.map_realm_roles(["Approver"]) == Role.APPROVER
    assert oidc_auth_service.map_realm_roles(["Operator"]) == Role.OPERATOR
    assert oidc_auth_service.map_realm_roles(["Compliance"]) == Role.COMPLIANCE
    assert oidc_auth_service.map_realm_roles(["Viewer"]) == Role.VIEWER

    # Precedence when composite or multiple roles present: Admin wins
    assert oidc_auth_service.map_realm_roles(["Viewer", "Operator", "Admin"]) == Role.ADMIN
    assert oidc_auth_service.map_realm_roles(["Viewer", "SecOps"]) == Role.SECOPS

    # Unknown role falls back to Viewer
    assert oidc_auth_service.map_realm_roles(["unknown_guest_role"]) == Role.VIEWER


def test_oidc_login_flow(client: TestClient) -> None:
    """Tests POST /v1/auth/oidc-login with a simulated Keycloak ID token."""
    # Construct a mock Keycloak OIDC ID token
    token_claims = {
        "sub": "kc-user-secops-99",
        "email": "secops.charlie@bitguard.local",
        "name": "Charlie SecOps Keycloak",
        "preferred_username": "secops_kc",
        "realm_access": {
            "roles": ["SecOps", "default-roles-bitguard", "offline_access"]
        },
        "iss": settings.oidc_issuer_url,
        "aud": settings.oidc_client_id,
        "exp": int(datetime.now(UTC).timestamp()) + 3600,
        "iat": int(datetime.now(UTC).timestamp()),
    }
    mock_id_token = jwt.encode(token_claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)

    resp = client.post(
        "/v1/auth/oidc-login",
        json={"id_token": mock_id_token},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["role"] == "SecOps"
    assert data["user"]["email"] == "secops.charlie@bitguard.local"
    assert "breaker:control" in data["user"]["permissions"]


# =========================================================================
# 2. Production Safety Gate Tests (DEV Login Removed in Production)
# =========================================================================


def test_dev_login_disabled_in_production(client: TestClient) -> None:
    """Verifies DEV login endpoints are strictly forbidden in production."""
    settings.environment = "production"

    # Both /dev-token and /dev-login aliases must return 403
    resp1 = client.post("/v1/auth/dev-token", json={"role": "Admin"})
    assert resp1.status_code == 403
    assert "disabled in production" in resp1.json()["detail"]

    resp2 = client.post("/v1/auth/dev-login", json={"role": "Admin"})
    assert resp2.status_code == 403
    assert "disabled in production" in resp2.json()["detail"]


def test_unauthenticated_dev_bypass_disabled_in_production(client: TestClient) -> None:
    """Verifies that no dev bypass credentials are provided in production."""
    settings.environment = "production"
    settings.dev_auth_bypass = True  # Even if set, must be ignored in production

    resp = client.get("/v1/decisions")
    assert resp.status_code == 401
    assert "Authentication credentials required" in resp.json()["detail"]


# =========================================================================
# 3. WebAuthn Registration and Verification with py_webauthn
# =========================================================================


def _generate_synthetic_registration_credential(
    user_id_bytes: bytes,
    challenge_bytes: bytes,
    rp_id: str = "localhost",
    origin: str = "http://localhost:3000",
) -> tuple[dict[str, Any], ec.EllipticCurvePrivateKey, bytes]:
    """Generates a cryptographically valid WebAuthn registration credential."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()
    x_bytes = public_numbers.x.to_bytes(32, "big")
    y_bytes = public_numbers.y.to_bytes(32, "big")

    cose_key = cbor2.dumps({
        1: 2,    # Key type: EC2
        3: -7,   # Algorithm: ES256
        -1: 1,   # Curve: P-256
        -2: x_bytes,
        -3: y_bytes,
    })

    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    flags = bytes([0x41])  # UP (User Present) | AT (Attested Credential Data)
    sign_count = bytes([0, 0, 0, 0])
    aaguid = bytes(16)
    cred_id = b"test-cred-" + hashlib.sha256(user_id_bytes).digest()[:16]
    cred_id_len = struct.pack(">H", len(cred_id))

    auth_data = rp_id_hash + flags + sign_count + aaguid + cred_id_len + cred_id + cose_key

    attestation_obj = cbor2.dumps({
        "fmt": "none",
        "attStmt": {},
        "authData": auth_data,
    })

    client_data = json.dumps({
        "type": "webauthn.create",
        "challenge": bytes_to_base64url(challenge_bytes),
        "origin": origin,
    }).encode("utf-8")

    cred_json = {
        "id": bytes_to_base64url(cred_id),
        "rawId": bytes_to_base64url(cred_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(client_data),
            "attestationObject": bytes_to_base64url(attestation_obj),
            "transports": ["internal", "usb"],
        },
    }
    return cred_json, private_key, cred_id


def test_webauthn_registration_flow(client: TestClient) -> None:
    """Verifies end-to-end WebAuthn registration options and verification."""
    # 1. Login as Admin
    login_resp = client.post("/v1/auth/dev-token", json={"role": "Admin"})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    user_id = login_resp.json()["user"]["id"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Request registration options
    reg_opts_resp = client.post("/v1/auth/webauthn/register/options", headers=headers)
    assert reg_opts_resp.status_code == 200
    reg_opts_data = reg_opts_resp.json()
    challenge_id = reg_opts_data["challenge_id"]
    challenge_b64 = reg_opts_data["options"]["challenge"]
    from webauthn.helpers import base64url_to_bytes
    challenge_bytes = base64url_to_bytes(challenge_b64)

    # 3. Client generates hardware credential
    cred_json, _priv_key, cred_id_bytes = _generate_synthetic_registration_credential(
        user_id_bytes=user_id.encode("utf-8"),
        challenge_bytes=challenge_bytes,
    )

    # 4. Verify and persist registration
    verify_resp = client.post(
        "/v1/auth/webauthn/register/verify",
        json={"credential": cred_json, "challenge_id": challenge_id},
        headers=headers,
    )
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["verified"] is True
    assert verify_data["credential_id"] == bytes_to_base64url(cred_id_bytes)
    assert verify_data["sign_count"] == 0

    # 5. List user credentials
    list_resp = client.get("/v1/auth/webauthn/credentials", headers=headers)
    assert list_resp.status_code == 200
    creds = list_resp.json()
    assert len(creds) == 1
    assert creds[0]["credential_id"] == bytes_to_base64url(cred_id_bytes)


# =========================================================================
# 4. WebAuthn Authentication, Monotonic Sign Count & Replay Protection
# =========================================================================


def _generate_synthetic_authentication_assertion(
    private_key: ec.EllipticCurvePrivateKey,
    cred_id_bytes: bytes,
    challenge_bytes: bytes,
    sign_count: int,
    rp_id: str = "localhost",
    origin: str = "http://localhost:3000",
) -> dict[str, Any]:
    """Generates a cryptographically valid WebAuthn authentication assertion."""
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    auth_flags = bytes([0x01])  # UP (User Present)
    auth_sign_count = struct.pack(">I", sign_count)
    auth_data = rp_id_hash + auth_flags + auth_sign_count

    client_data = json.dumps({
        "type": "webauthn.get",
        "challenge": bytes_to_base64url(challenge_bytes),
        "origin": origin,
    }).encode("utf-8")

    client_data_hash = hashlib.sha256(client_data).digest()
    data_to_sign = auth_data + client_data_hash

    signature = private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))

    return {
        "id": bytes_to_base64url(cred_id_bytes),
        "rawId": bytes_to_base64url(cred_id_bytes),
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(client_data),
            "authenticatorData": bytes_to_base64url(auth_data),
            "signature": bytes_to_base64url(signature),
        },
    }


def test_webauthn_authentication_and_sign_count_verification(client: TestClient) -> None:
    """Tests authentication assertion ceremony, monotonic sign-count updates, and replay failure."""
    # 1. Register a key first
    login_resp = client.post("/v1/auth/dev-token", json={"role": "Admin"})
    token = login_resp.json()["access_token"]
    user_id = login_resp.json()["user"]["id"]
    headers = {"Authorization": f"Bearer {token}"}

    reg_opts = client.post("/v1/auth/webauthn/register/options", headers=headers).json()
    from webauthn.helpers import base64url_to_bytes
    reg_challenge = base64url_to_bytes(reg_opts["options"]["challenge"])

    cred_json, priv_key, cred_id_bytes = _generate_synthetic_registration_credential(
        user_id_bytes=user_id.encode("utf-8"),
        challenge_bytes=reg_challenge,
    )
    client.post(
        "/v1/auth/webauthn/register/verify",
        json={"credential": cred_json, "challenge_id": reg_opts["challenge_id"]},
        headers=headers,
    )

    # 2. Generate authentication options
    auth_opts = client.post(
        "/v1/auth/webauthn/authenticate/options",
        json={"user_id": user_id},
    ).json()
    auth_challenge = base64url_to_bytes(auth_opts["options"]["challenge"])
    auth_challenge_id = auth_opts["challenge_id"]

    # 3. Perform assertion ceremony with sign_count=1
    assertion_json = _generate_synthetic_authentication_assertion(
        private_key=priv_key,
        cred_id_bytes=cred_id_bytes,
        challenge_bytes=auth_challenge,
        sign_count=1,
    )

    verify_auth_resp = client.post(
        "/v1/auth/webauthn/authenticate/verify",
        json={
            "credential": assertion_json,
            "user_id": user_id,
            "challenge_id": auth_challenge_id,
        },
    )
    assert verify_auth_resp.status_code == 200
    auth_data = verify_auth_resp.json()
    assert auth_data["verified"] is True
    assert auth_data["new_sign_count"] == 1
    assert "step_up_token" in auth_data
    assert "assertion_ref" in auth_data
    assert len(auth_data["step_up_token"]) > 0
    assert len(auth_data["assertion_ref"]) > 0

    # 4. Attempt REPLAY ATTACK or DECREMENTED SIGN COUNT (Cloned Key)
    # Replay with same sign_count=1 should be rejected by py_webauthn
    auth_opts_2 = client.post(
        "/v1/auth/webauthn/authenticate/options",
        json={"user_id": user_id},
    ).json()
    auth_challenge_2 = base64url_to_bytes(auth_opts_2["options"]["challenge"])

    stale_assertion = _generate_synthetic_authentication_assertion(
        private_key=priv_key,
        cred_id_bytes=cred_id_bytes,
        challenge_bytes=auth_challenge_2,
        sign_count=1,  # Not greater than previous count of 1!
    )

    replay_resp = client.post(
        "/v1/auth/webauthn/authenticate/verify",
        json={
            "credential": stale_assertion,
            "user_id": user_id,
            "challenge_id": auth_opts_2["challenge_id"],
        },
    )
    # Fail-closed: Must fail due to InvalidSignCountError
    assert replay_resp.status_code == 400
    assert "sign count" in replay_resp.json()["detail"].lower()


# =========================================================================
# 5. Step-Up Policy and Signed Admin Audit Logging Tests
# =========================================================================


def test_step_up_required_for_admin_actions(client: TestClient) -> None:
    """Verifies Admin/SecOps/Approver require WebAuthn step-up and record signed audit records."""
    # Enable strict step-up requirement
    settings.enforce_step_up = True

    login_resp = client.post("/v1/auth/dev-token", json={"role": "Admin"})
    token = login_resp.json()["access_token"]
    user_id = login_resp.json()["user"]["id"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Attempt sensitive admin action without step-up -> 403 Forbidden
    resp_denied = client.post(
        "/v1/auth/admin/action",
        json={"action": "RESTRICTED_HSM_CONFIG_UPDATE", "details": {"param": "val"}},
        headers=headers,
    )
    assert resp_denied.status_code == 403
    assert "requires a WebAuthn-verified session" in resp_denied.json()["detail"]

    # 2. Register hardware key and complete WebAuthn ceremony to get step-up token
    reg_opts = client.post("/v1/auth/webauthn/register/options", headers=headers).json()
    from webauthn.helpers import base64url_to_bytes
    reg_challenge = base64url_to_bytes(reg_opts["options"]["challenge"])

    cred_json, priv_key, cred_id_bytes = _generate_synthetic_registration_credential(
        user_id_bytes=user_id.encode("utf-8"),
        challenge_bytes=reg_challenge,
    )
    client.post(
        "/v1/auth/webauthn/register/verify",
        json={"credential": cred_json, "challenge_id": reg_opts["challenge_id"]},
        headers=headers,
    )

    auth_opts = client.post(
        "/v1/auth/webauthn/authenticate/options",
        json={"user_id": user_id},
    ).json()
    auth_challenge = base64url_to_bytes(auth_opts["options"]["challenge"])
    assertion_json = _generate_synthetic_authentication_assertion(
        private_key=priv_key,
        cred_id_bytes=cred_id_bytes,
        challenge_bytes=auth_challenge,
        sign_count=1,
    )
    verify_auth_resp = client.post(
        "/v1/auth/webauthn/authenticate/verify",
        json={
            "credential": assertion_json,
            "user_id": user_id,
            "challenge_id": auth_opts["challenge_id"],
        },
    )
    step_up_token = verify_auth_resp.json()["step_up_token"]

    # 3. Execute sensitive action WITH X-Step-Up-Token header -> 200 OK
    headers_with_stepup = {
        "Authorization": f"Bearer {token}",
        "X-Step-Up-Token": step_up_token,
    }
    resp_success = client.post(
        "/v1/auth/admin/action",
        json={"action": "RESTRICTED_HSM_CONFIG_UPDATE", "details": {"param": "val"}},
        headers=headers_with_stepup,
    )
    assert resp_success.status_code == 200
    res_data = resp_success.json()
    assert res_data["status"] == "SUCCESS"
    assert "webauthn_assertion_ref" in res_data
    assertion_ref = res_data["webauthn_assertion_ref"]

    # 4. Invariant #7: Verify an immutable audit record was written with assertion reference
    entries = audit_service.get_entries()
    matching = [e for e in entries if e.action == "ADMIN_ACTION:RESTRICTED_HSM_CONFIG_UPDATE"]
    assert len(matching) == 1
    audit_entry = matching[0]
    assert audit_entry.actor == "admin@bitguard.local"
    assert audit_entry.payload["webauthn_assertion_ref"] == assertion_ref
    assert audit_entry.payload["user"] == user_id
    assert "time" in audit_entry.payload


# =========================================================================
# 6. Centralized Separation of Duties Rules Tests
# =========================================================================


def test_separation_of_duties_requester_cannot_approve() -> None:
    """Verifies that a transaction requester cannot approve their own hold ticket."""
    # Same user ID -> must raise SeparationOfDutiesError (403)
    with pytest.raises(SeparationOfDutiesError) as exc_info:
        separation_of_duties.enforce_requester_cannot_approve(
            requester_id="usr-trader-01",
            approver_id="usr-trader-01",
        )
    assert exc_info.value.status_code == 403
    assert "REQUESTER_CANNOT_APPROVE" in exc_info.value.detail

    # Distinct user ID -> must succeed cleanly
    separation_of_duties.enforce_requester_cannot_approve(
        requester_id="usr-trader-01",
        approver_id="usr-approver-02",
    )


def test_separation_of_duties_policy_author_cannot_approve() -> None:
    """Verifies that a policy change author cannot approve their own policy manifest."""
    # Same user ID -> must raise SeparationOfDutiesError (403)
    with pytest.raises(SeparationOfDutiesError) as exc_info:
        separation_of_duties.enforce_policy_author_cannot_approve(
            author_id="usr-admin-01",
            approver_id="usr-admin-01",
        )
    assert exc_info.value.status_code == 403
    assert "POLICY_AUTHOR_CANNOT_APPROVE" in exc_info.value.detail

    # Distinct user ID -> must succeed cleanly
    separation_of_duties.enforce_policy_author_cannot_approve(
        author_id="usr-admin-01",
        approver_id="usr-secops-02",
    )


def test_separation_of_duties_quorum_approvers_distinct() -> None:
    """Verifies multi-party quorum requires distinct approver user IDs and distinct roles where configured."""
    # Duplicate approver ID -> must raise SeparationOfDutiesError (400)
    with pytest.raises(SeparationOfDutiesError) as exc_info:
        separation_of_duties.enforce_quorum_approvers_distinct(
            approver1_id="usr-approver-01",
            approver2_id="usr-approver-01",
        )
    assert exc_info.value.status_code == 400
    assert "DUPLICATE_APPROVER" in exc_info.value.detail

    # Distinct IDs -> must succeed
    separation_of_duties.enforce_quorum_approvers_distinct(
        approver1_id="usr-approver-01",
        approver2_id="usr-approver-02",
    )

    # When require_different_roles=True and both hold the same role -> must fail
    with pytest.raises(SeparationOfDutiesError) as exc_role:
        separation_of_duties.enforce_quorum_approvers_distinct(
            approver1_id="usr-user-01",
            approver2_id="usr-user-02",
            approver1_role="SecOps",
            approver2_role="SecOps",
            require_different_roles=True,
        )
    assert exc_role.value.status_code == 403
    assert "DIFFERENT_ROLES_REQUIRED" in exc_role.value.detail

    # Distinct IDs and distinct roles -> must succeed
    separation_of_duties.enforce_quorum_approvers_distinct(
        approver1_id="usr-user-01",
        approver2_id="usr-user-02",
        approver1_role="SecOps",
        approver2_role="Compliance",
        require_different_roles=True,
    )
