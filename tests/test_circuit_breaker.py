"""Comprehensive test suite for Circuit Breaker subsystem (Milestone S18 / F9, F14).

Verifies the 5 core milestone requirements and operating invariants:
1. Escalation is instant (one authorized person, immediate effect).
2. De-escalation with one approver fails (requires 2 distinct approvers with WebAuthn).
3. Revoked tokens are refused by the shim (epoch increment on HOLD/LOCKDOWN).
4. Two gateway instances see the same state (distributed Redis/Postgres state).
5. Redis outage keeps the last known state at least as strict (fail-closed resilience).
6. KeyUsePolicyHook disables keys at KMS/HSM level.
7. Automated triggers (repeated denials, unmatched intents, velocity spike).
"""

from typing import Any

import fakeredis
import pytest
import redis
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from services.bitguard.approvals.webauthn import (
    approver_registry,
    create_test_webauthn_assertion,
)
from services.bitguard.breaker import (
    DistributedBreakerStore,
    breaker_triggers,
    distributed_breaker_store,
    key_policy_hook,
    token_epoch_store,
)
from services.bitguard.breaker.models import BreakerStateEnum
from services.bitguard.db_models import Base
from services.bitguard.decoders.evm import evm_decoder
from services.bitguard.main import app
from services.bitguard.models import Role
from services.bitguard.rbac import SEEDED_USERS, create_access_token
from services.bitguard.tokens import KeySet, token_manager
from services.signer_shim.main import app as shim_app
from services.signer_shim.main import set_public_key_set
from services.signer_shim.nonce_store import nonce_store

client = TestClient(app)
shim_client = TestClient(shim_app)


class ControllableFakeRedis(fakeredis.FakeRedis):
    """Full-featured in-memory Redis client with controllable outage simulation."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.is_down: bool = False

    def execute_command(self, *args: Any, **options: Any) -> Any:
        if self.is_down:
            raise redis.exceptions.ConnectionError("Simulated Redis outage")
        return super().execute_command(*args, **options)


@pytest.fixture(autouse=True)
def setup_breaker_env():
    """Initializes clean in-memory SQLite and mock Redis for each test."""
    test_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=test_engine)
    test_session_factory = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)

    mock_redis = ControllableFakeRedis(decode_responses=True)
    distributed_breaker_store.set_session_factory(test_session_factory)
    distributed_breaker_store.set_redis_client(mock_redis)
    token_epoch_store.set_redis_client(mock_redis)
    nonce_store.set_redis_client(mock_redis)
    distributed_breaker_store.reset()
    token_epoch_store.reset(1)
    key_policy_hook.reset()
    approver_registry.reset_replays()
    breaker_triggers.reset()

    # Sync shim keys
    pub_dict = token_manager.key_set.export_public_key_set()
    set_public_key_set(KeySet.from_public_key_dict(pub_dict))

    try:
        yield {
            "engine": test_engine,
            "session_factory": test_session_factory,
            "mock_redis": mock_redis,
        }
    finally:
        distributed_breaker_store.reset()
        token_epoch_store.reset(1)
        key_policy_hook.reset()
        breaker_triggers.reset()
        distributed_breaker_store.set_redis_client(None)
        distributed_breaker_store.set_session_factory(None)
        token_epoch_store.set_redis_client(None)


def _get_auth_header(role: Role) -> dict[str, str]:
    user = SEEDED_USERS[role]
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


# =====================================================================
# Test 1: Escalation is instant (one authorized person, immediate effect)
# =====================================================================
def test_escalation_is_instant_and_enforces_rbac():
    """SecOps or Admin can escalate to any higher state instantly; Operator cannot."""
    secops_headers = _get_auth_header(Role.SECOPS)
    operator_headers = _get_auth_header(Role.OPERATOR)
    viewer_headers = _get_auth_header(Role.VIEWER)

    # 1. Initial state is NORMAL
    resp_init = client.get("/v1/breaker", headers=viewer_headers)
    assert resp_init.status_code == 200
    assert resp_init.json()["state"] == "NORMAL"

    # 2. Operator cannot escalate (403 Forbidden)
    resp_op = client.post(
        "/v1/breaker/escalate",
        headers=operator_headers,
        json={"target_state": "HOLD", "reason": "Operator attempted escalate"},
    )
    assert resp_op.status_code == 403

    # 3. SecOps escalates instantly to ELEVATED
    resp_elev = client.post(
        "/v1/breaker/escalate",
        headers=secops_headers,
        json={"target_state": "ELEVATED", "reason": "Heightened threat level observed"},
    )
    assert resp_elev.status_code == 200
    assert resp_elev.json()["state"] == "ELEVATED"
    assert distributed_breaker_store.get_state() == BreakerStateEnum.ELEVATED

    # 4. SecOps escalates instantly to LOCKDOWN (skipping HOLD)
    resp_lock = client.post(
        "/v1/breaker/escalate",
        headers=secops_headers,
        json={"target_state": "LOCKDOWN", "reason": "Active intrusion containment"},
    )
    assert resp_lock.status_code == 200
    assert resp_lock.json()["state"] == "LOCKDOWN"
    assert distributed_breaker_store.get_state() == BreakerStateEnum.LOCKDOWN

    # 5. Cannot escalate to lower or same state (returns 400 Bad Request)
    resp_bad = client.post(
        "/v1/breaker/escalate",
        headers=secops_headers,
        json={"target_state": "NORMAL", "reason": "Invalid escalation to lower state"},
    )
    assert resp_bad.status_code == 400


# =====================================================================
# Test 2: De-escalation with one approver fails (needs 2 with WebAuthn)
# =====================================================================
def test_deescalation_requires_two_approvers_with_webauthn():
    """Lowering state requires proposal and 2 distinct approvers signing challenge with WebAuthn."""
    secops_headers = _get_auth_header(Role.SECOPS)
    admin_headers = _get_auth_header(Role.ADMIN)
    approver_headers = _get_auth_header(Role.APPROVER)

    # 1. Escalate to LOCKDOWN first
    client.post(
        "/v1/breaker/escalate",
        headers=secops_headers,
        json={"target_state": "LOCKDOWN", "reason": "Emergency lockdown"},
    )
    assert distributed_breaker_store.get_state() == BreakerStateEnum.LOCKDOWN

    # 2. SecOps initiates de-escalation proposal to NORMAL
    resp_req = client.post(
        "/v1/breaker/deescalate-request",
        headers=secops_headers,
        json={"target_state": "NORMAL", "reason": "Incident investigated and mitigated"},
    )
    assert resp_req.status_code == 201
    req_data = resp_req.json()
    req_id = req_data["id"]
    challenge = req_data["challenge"]
    assert req_data["status"] == "PENDING"
    assert len(challenge) > 10

    # 3. Requester (SecOps) cannot approve their own proposal (Separation of duties)
    assertion_secops = create_test_webauthn_assertion(
        private_key=approver_registry.dev_private_keys["usr-admin-01"],
        tx_digest=challenge,
    )
    resp_self_approve = client.post(
        "/v1/breaker/deescalate-approve",
        headers=secops_headers,  # SecOps role cannot approve, and requester == approver
        json={"request_id": req_id, "assertion": assertion_secops.model_dump()},
    )
    assert resp_self_approve.status_code == 403

    # 4. Approver 1 submits valid WebAuthn assertion
    priv1 = approver_registry.dev_private_keys["usr-approver-01"]
    assertion1 = create_test_webauthn_assertion(private_key=priv1, tx_digest=challenge, sign_count=1)
    resp_appr1 = client.post(
        "/v1/breaker/deescalate-approve",
        headers=approver_headers,
        json={"request_id": req_id, "assertion": assertion1.model_dump()},
    )
    assert resp_appr1.status_code == 200
    assert resp_appr1.json()["status"] == "PENDING"
    assert resp_appr1.json()["approvals_count"] == 1
    # Breaker MUST still be in LOCKDOWN!
    assert distributed_breaker_store.get_state() == BreakerStateEnum.LOCKDOWN

    # 5. Approver 1 attempts to approve a second time -> Rejected
    resp_dup = client.post(
        "/v1/breaker/deescalate-approve",
        headers=approver_headers,
        json={"request_id": req_id, "assertion": assertion1.model_dump()},
    )
    assert resp_dup.status_code == 400
    assert "already approved" in resp_dup.json()["detail"]

    # 6. Approver 2 (Admin with separate key usr-admin-01) submits second assertion
    priv2 = approver_registry.dev_private_keys["usr-admin-01"]
    assertion2 = create_test_webauthn_assertion(private_key=priv2, tx_digest=challenge, sign_count=1)
    resp_appr2 = client.post(
        "/v1/breaker/deescalate-approve",
        headers=admin_headers,
        json={"request_id": req_id, "assertion": assertion2.model_dump()},
    )
    assert resp_appr2.status_code == 200
    assert resp_appr2.json()["status"] == "APPROVED"
    assert resp_appr2.json()["approvals_count"] == 2
    assert resp_appr2.json()["new_breaker_state"] == "NORMAL"

    # 7. Breaker state is now de-escalated to NORMAL!
    assert distributed_breaker_store.get_state() == BreakerStateEnum.NORMAL


# =====================================================================
# Test 3: Revoked tokens are refused by the shim
# =====================================================================
def test_revoked_tokens_refused_by_shim_on_epoch_increment():
    """Entering HOLD or LOCKDOWN increments token epoch; older tokens are refused by shim."""
    secops_headers = _get_auth_header(Role.SECOPS)
    shim_auth_headers = {"X-BitGuard-Internal-Auth": "bitguard-shim-internal-lab-token-2026"}

    # Legacy transfer payload
    raw_tx = (
        "0xf86c808504a817c80082520894353b306ea86f532917b52188d4086db0bea88f21"
        "880de0b6b3a7640000801ba028b60b240560a8247076a91d9d9ab829596644eb976c"
        "836fe9f592d3f6631620a061b471c9b6851b4793f18e950ec4be3b06a6b579178ad3"
        "3d9c735d5a7d30f5ec"
    )
    decoded_tx = evm_decoder.decode(raw_tx)
    wallet = decoded_tx.from_address
    chain = decoded_tx.chain

    # 1. Issue a valid approval token while in NORMAL (epoch 1)
    token_v1 = token_manager.issue(
        decoded_tx=decoded_tx,
        wallet=wallet,
        chain=chain,
        epoch=1,
    )

    # 2. Verify token works with shim before trip
    resp_shim_ok = shim_client.post(
        "/sign",
        headers=shim_auth_headers,
        json={
            "raw_tx_bytes": raw_tx,
            "token": token_v1,
            "wallet": wallet,
            "chain": chain,
        },
    )
    assert resp_shim_ok.status_code == 200
    assert "signature" in resp_shim_ok.json()

    # 3. Generate a SECOND token for epoch 1 (with new nonce)
    token_v1_second = token_manager.issue(
        decoded_tx=decoded_tx,
        wallet=wallet,
        chain=chain,
        epoch=1,
    )

    # 4. Trip circuit breaker to HOLD -> increments token epoch to 2
    resp_hold = client.post(
        "/v1/breaker/escalate",
        headers=secops_headers,
        json={"target_state": "HOLD", "reason": "Anomaly detected; incrementing epoch"},
    )
    assert resp_hold.status_code == 200
    assert token_epoch_store.get_current_epoch() == 2

    # 5. Submit the old epoch 1 token to the shim -> Refused with REVOKED_TOKEN_EPOCH!
    resp_shim_refused = shim_client.post(
        "/sign",
        headers=shim_auth_headers,
        json={
            "raw_tx_bytes": raw_tx,
            "token": token_v1_second,
            "wallet": wallet,
            "chain": chain,
        },
    )
    assert resp_shim_refused.status_code == 400
    assert resp_shim_refused.json()["reason_code"] == "REVOKED_TOKEN_EPOCH"
    assert "older than current active epoch" in resp_shim_refused.json()["detail"]


# =====================================================================
# Test 4: Two gateway instances see the same state
# =====================================================================
def test_two_gateway_instances_see_same_state(setup_breaker_env):
    """Two separate DistributedBreakerStore instances sharing storage see synchronous state."""
    session_factory = setup_breaker_env["session_factory"]
    mock_redis = setup_breaker_env["mock_redis"]

    # Gateway Instance 1 and Gateway Instance 2
    gw1 = DistributedBreakerStore(redis_client=mock_redis, session_factory=session_factory)
    gw2 = DistributedBreakerStore(redis_client=mock_redis, session_factory=session_factory)

    assert gw1.get_state() == BreakerStateEnum.NORMAL
    assert gw2.get_state() == BreakerStateEnum.NORMAL

    # Instance 1 escalates to HOLD
    gw1.escalate(
        target_state=BreakerStateEnum.HOLD,
        reason="Instance 1 detected multi-wallet spray",
        updated_by="gw1-operator",
    )

    # Instance 2 immediately reflects HOLD
    assert gw2.get_state() == BreakerStateEnum.HOLD
    assert gw2.get_status().state == BreakerStateEnum.HOLD


# =====================================================================
# Test 5: Redis outage keeps the last known state at least as strict
# =====================================================================
def test_redis_outage_preserves_strictest_state(setup_breaker_env):
    """Redis outage falls back to DB/local memory and never downgrades to a less strict state."""
    mock_redis: ControllableFakeRedis = setup_breaker_env["mock_redis"]
    secops_headers = _get_auth_header(Role.SECOPS)

    # 1. Escalate to LOCKDOWN
    client.post(
        "/v1/breaker/escalate",
        headers=secops_headers,
        json={"target_state": "LOCKDOWN", "reason": "Pre-outage lockdown"},
    )
    assert distributed_breaker_store.get_state() == BreakerStateEnum.LOCKDOWN

    # 2. Simulate Redis failure
    mock_redis.is_down = True

    # 3. Read state during outage: remains LOCKDOWN (fail closed)
    assert distributed_breaker_store.get_state() == BreakerStateEnum.LOCKDOWN
    status = distributed_breaker_store.get_status()
    assert status.state == BreakerStateEnum.LOCKDOWN

    # 4. Redis recovers
    mock_redis.is_down = False
    assert distributed_breaker_store.get_state() == BreakerStateEnum.LOCKDOWN


# =====================================================================
# Test 6: KeyUsePolicyHook disables keys at KMS/HSM level
# =====================================================================
def test_key_use_policy_hook_disables_keys():
    """HOLD or LOCKDOWN disables keys via KeyUsePolicyHook; shim refuses signing on disabled keys."""
    secops_headers = _get_auth_header(Role.SECOPS)
    shim_auth_headers = {"X-BitGuard-Internal-Auth": "bitguard-shim-internal-lab-token-2026"}

    raw_tx = (
        "0xf86c808504a817c80082520894353b306ea86f532917b52188d4086db0bea88f21"
        "880de0b6b3a7640000801ba028b60b240560a8247076a91d9d9ab829596644eb976c"
        "836fe9f592d3f6631620a061b471c9b6851b4793f18e950ec4be3b06a6b579178ad3"
        "3d9c735d5a7d30f5ec"
    )
    decoded_tx = evm_decoder.decode(raw_tx)

    # Initially key is enabled
    assert key_policy_hook.is_key_enabled("bg-ed25519-v1") is True

    # Escalate to HOLD
    client.post(
        "/v1/breaker/escalate",
        headers=secops_headers,
        json={"target_state": "HOLD", "reason": "Test hook"},
    )

    # Key is now disabled by hook
    assert key_policy_hook.is_key_enabled("bg-ed25519-v1") is False

    # Issue token with current epoch
    token = token_manager.issue(
        decoded_tx=decoded_tx,
        wallet=decoded_tx.from_address,
        chain=decoded_tx.chain,
        epoch=token_epoch_store.get_current_epoch(),
    )

    # Shim refuses signing due to KEY_DISABLED_AT_KMS
    resp_shim = shim_client.post(
        "/sign",
        headers=shim_auth_headers,
        json={
            "raw_tx_bytes": raw_tx,
            "token": token,
            "wallet": decoded_tx.from_address,
            "chain": decoded_tx.chain,
        },
    )
    assert resp_shim.status_code == 400
    assert resp_shim.json()["reason_code"] == "KEY_DISABLED_AT_KMS"


# =====================================================================
# Test 7: Automated Triggers
# =====================================================================
def test_automated_triggers_escalate_breaker():
    """Denials, unmatched intents, and velocity spikes automatically trip breaker."""
    breaker_triggers.enabled = True
    try:
        # 1. Repeated denials trigger ELEVATED
        assert distributed_breaker_store.get_state() == BreakerStateEnum.NORMAL
        for i in range(5):
            breaker_triggers.record_denial(f"dec-denial-{i}", reason="TEST_REASON")

        assert distributed_breaker_store.get_state() in [BreakerStateEnum.ELEVATED, BreakerStateEnum.HOLD]

        # 2. Multiple unmatched intents escalate to HOLD
        distributed_breaker_store.reset()
        assert distributed_breaker_store.get_state() == BreakerStateEnum.NORMAL
        for i in range(3):
            breaker_triggers.record_unmatched_intent(f"intent-{i}", reason="INTENT_MISSING")

        assert distributed_breaker_store.get_state() == BreakerStateEnum.HOLD

        # 3. Velocity spike escalates to HOLD
        distributed_breaker_store.reset()
        assert distributed_breaker_store.get_state() == BreakerStateEnum.NORMAL
        breaker_triggers.record_velocity(amount_usd=2_500_000.0)
        assert distributed_breaker_store.get_state() == BreakerStateEnum.HOLD
    finally:
        breaker_triggers.enabled = False
