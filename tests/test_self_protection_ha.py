"""Tests for Self-Protection, HA, Dead-Man Heartbeat, Rate Limiting, and Break-Glass (Milestone S24 / F17)."""

import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from services.bitguard.break_glass import BreakGlassState, break_glass_store
from services.bitguard.breaker.models import BreakerStateEnum
from services.bitguard.breaker.store import distributed_breaker_store
from services.bitguard.config import settings
from services.bitguard.integrity import ConfigIntegrityChecker, config_integrity_checker
from services.bitguard.main import create_app
from services.bitguard.metrics import (
    record_decision,
    record_reservation_failure,
    record_stage_duration,
    record_token_issue,
    record_token_refusal,
    record_unmatched_intent,
    update_breaker_state_metric,
    update_heartbeat_age_metric,
)
from services.bitguard.policy.crypto import compute_content_hash, sign_content_hash
from services.bitguard.policy.store import policy_store
from services.bitguard.rate_limiter import rate_limiter
from services.signer_shim.config import settings as shim_settings
from services.signer_shim.heartbeat import HeartbeatMessage, HeartbeatTracker
from services.signer_shim.main import app as shim_app
from services.signer_shim.main import heartbeat_tracker as global_shim_tracker


@pytest.fixture(autouse=True)
def clean_state():
    """Resets shared state before each test."""
    distributed_breaker_store.reset()
    break_glass_store.reset()
    rate_limiter.reset()
    global_shim_tracker.reset()
    config_integrity_checker.is_healthy = True
    config_integrity_checker.last_errors = []
    yield
    distributed_breaker_store.reset()
    break_glass_store.reset()
    rate_limiter.reset()
    global_shim_tracker.reset()


# ==============================================================================
# 1. Dead-Man Heartbeat Tests
# ==============================================================================


def test_heartbeat_tracker_freshness_and_expiration():
    """Verifies that the dead-man tracker rejects signing when heartbeat expires."""
    tracker = HeartbeatTracker(timeout_seconds=20.0)

    # Initial state: no heartbeat received yet
    assert not tracker.is_healthy()
    assert tracker.get_heartbeat_age() > 20.0

    now = 1000.0
    # Construct valid signed heartbeat
    canonical_str = f"{now:.3f}:bitguard-1:hash-v1"
    digest = compute_content_hash({"heartbeat": canonical_str})
    sig = sign_content_hash(digest)

    msg = HeartbeatMessage(
        timestamp=now,
        instance_id="bitguard-1",
        policy_hash="hash-v1",
        signature=sig,
    )

    # Record valid heartbeat
    ok, err = tracker.record_heartbeat(msg, now=now)
    assert ok, err
    assert tracker.is_healthy(now=now)
    assert tracker.get_heartbeat_age(now=now) == 0.0

    # 15 seconds later: still within 20s timeout
    assert tracker.is_healthy(now=now + 15.0)
    assert tracker.get_heartbeat_age(now=now + 15.0) == 15.0

    # 21 seconds later: dead-man switch triggers, unhealthy
    assert not tracker.is_healthy(now=now + 21.0)
    assert tracker.get_heartbeat_age(now=now + 21.0) == 21.0

    # New heartbeat arrives -> recovers immediately
    now2 = now + 25.0
    canonical_str2 = f"{now2:.3f}:bitguard-1:hash-v1"
    digest2 = compute_content_hash({"heartbeat": canonical_str2})
    sig2 = sign_content_hash(digest2)
    msg2 = HeartbeatMessage(
        timestamp=now2,
        instance_id="bitguard-1",
        policy_hash="hash-v1",
        signature=sig2,
    )
    ok2, _ = tracker.record_heartbeat(msg2, now=now2)
    assert ok2
    assert tracker.is_healthy(now=now2)


def test_heartbeat_signature_and_clock_skew_validation():
    """Verifies that forged or replays outside clock skew are rejected."""
    tracker = HeartbeatTracker(timeout_seconds=20.0)
    now = 1000.0

    # Test 1: Invalid signature
    bad_msg = HeartbeatMessage(
        timestamp=now,
        instance_id="bitguard-1",
        policy_hash="hash-v1",
        signature="badf00d" * 8,
    )
    ok, err = tracker.record_heartbeat(bad_msg, now=now)
    assert not ok
    assert "signature" in err.lower()
    assert not tracker.is_healthy(now=now)

    # Test 2: Clock skew exceeded (> 60s)
    canonical_str = f"{now - 120.0:.3f}:bitguard-1:hash-v1"
    digest = compute_content_hash({"heartbeat": canonical_str})
    sig = sign_content_hash(digest)
    skewed_msg = HeartbeatMessage(
        timestamp=now - 120.0,
        instance_id="bitguard-1",
        policy_hash="hash-v1",
        signature=sig,
    )
    ok_skew, err_skew = tracker.record_heartbeat(skewed_msg, now=now)
    assert not ok_skew
    assert "skew" in err_skew.lower()


def test_signer_shim_refuses_token_when_heartbeat_expired():
    """Verifies Signer Shim endpoint returns 400 DEADMAN_HEARTBEAT_EXPIRED when heartbeat has stopped."""
    client = TestClient(shim_app)
    headers = {"X-BitGuard-Internal-Auth": shim_settings.internal_auth_token}

    # Reset tracker to ensure dead-man expiration
    global_shim_tracker.reset()

    # Attempt to sign a transaction
    req_payload = {
        "raw_tx_bytes": "0x02f86b0180843b9aca008502540be400825208940000000000000000000000000000000000000001872386f26fc1000080c0",
        "token": "dummy-token-for-test",
    }
    resp = client.post("/sign", json=req_payload, headers=headers)
    assert resp.status_code == 400
    data = resp.json()
    assert data["status"].upper() == "REFUSED"
    assert data["reason_code"] == "DEADMAN_HEARTBEAT_EXPIRED"

    # Now deliver a valid heartbeat to the shim /heartbeat endpoint
    now = time.time()
    canonical_str = f"{now:.3f}:bitguard-1:active-hash"
    digest = compute_content_hash({"heartbeat": canonical_str})
    sig = sign_content_hash(digest)
    hb_payload = {
        "timestamp": now,
        "instance_id": "bitguard-1",
        "policy_hash": "active-hash",
        "signature": sig,
    }
    hb_resp = client.post("/heartbeat", json=hb_payload, headers=headers)
    assert hb_resp.status_code == 200
    assert hb_resp.json()["status"] in ["ok", "accepted"]
    assert global_shim_tracker.is_healthy()


# ==============================================================================
# 2. Config Integrity Checks & Fail-Closed Behavior
# ==============================================================================


def test_config_integrity_detects_policy_tampering_and_fails_closed():
    """Verifies that policy hash tampering causes integrity check to trip breaker to HOLD."""
    checker = ConfigIntegrityChecker()

    from services.bitguard.policy.models import PolicyDocument, ThresholdsPolicy
    from services.bitguard.policy.models import PolicyVersion as S20PolicyVersion
    # Set up a mock active policy with a tampered content hash
    tampered_pv = S20PolicyVersion(
        id="pv-tampered",
        version="v1.0.0",
        content=PolicyDocument(thresholds=ThresholdsPolicy(single_tx_usd=50000.0)),
        content_hash="forged-or-corrupted-hash",
        author="attacker",
        signatures=[],
    )
    with patch.object(policy_store, "get_active", return_value=tampered_pv):
        ok, errors = checker.perform_full_check()
        assert not ok
        assert not checker.is_healthy
        assert any("mismatch" in e.lower() for e in errors)

        # Breaker must have tripped to HOLD
        state = distributed_breaker_store.get_state()
        assert state == BreakerStateEnum.HOLD


def test_config_integrity_production_flag_invariants():
    """Verifies that dangerous flags in production fail integrity check."""
    checker = ConfigIntegrityChecker()

    with patch.object(settings, "environment", "production"):
        with patch.object(settings, "dev_auth_bypass", True):
            ok, errors = checker.perform_full_check()
            assert not ok
            assert any("production" in e.lower() for e in errors)


# ==============================================================================
# 3. Rate Limiting Middleware Tests
# ==============================================================================


def test_rate_limiting_admin_vs_standard():
    """Verifies that admin endpoints enforce strict rate limits while standard endpoints allow normal traffic."""
    app = create_app()
    client = TestClient(app)

    # Headers for simulated SecOps caller
    headers = {
        "X-Caller-ID": "test-caller-secops",
        "X-Dev-Role": "SECOPS",
    }

    # Set strict limit of 3 for testing
    with patch.object(settings, "rate_limit_admin_per_minute", 3):
        # 3 calls succeed
        for _ in range(3):
            resp = client.get("/v1/breaker", headers=headers)
            assert resp.status_code == 200

        # 4th call exceeds limit -> 429 Too Many Requests
        resp_blocked = client.get("/v1/breaker", headers=headers)
        assert resp_blocked.status_code == 429
        assert "Rate limit exceeded" in resp_blocked.json()["detail"]
        assert resp_blocked.headers.get("Retry-After") == "60"

    # Reset for standard endpoints
    rate_limiter.reset()
    with patch.object(settings, "rate_limit_standard_per_minute", 10):
        # 5 evaluation calls succeed easily
        for _ in range(5):
            resp = client.get("/healthz")
            assert resp.status_code == 200


# ==============================================================================
# 4. Emergency Break-Glass Mechanism & Quorum Overrides
# ==============================================================================


def test_break_glass_quorum_and_allowlist_enforcement():
    """Verifies two-person quorum, separation of duties, and allowlist routing under break-glass."""
    app = create_app()
    client = TestClient(app)

    # 1. Propose break-glass override by SecOps
    propose_payload = {
        "reason": "Custody RPC partition: sweep to cold storage",
        "allowed_destinations": ["0x000000000000000000000000000000000000b001"],
        "duration_seconds": 3600,
    }
    resp1 = client.post(
        "/v1/break-glass/propose",
        json=propose_payload,
        headers={"X-Dev-Role": "SECOPS", "X-Dev-User": "initiator-secops"},
    )
    assert resp1.status_code == 201
    manifest = resp1.json()
    override_id = manifest["id"]
    assert manifest["state"] == "PENDING"
    assert len(manifest["approvals"]) == 0

    # 2. Separation of duties check: Proposer cannot approve their own request!
    resp_self = client.post(
        f"/v1/break-glass/{override_id}/approve",
        json={},
        headers={"X-Dev-Role": "SECOPS", "X-Dev-User": "initiator-secops"},
    )
    assert resp_self.status_code == 403
    assert "Separation of duties" in resp_self.json()["detail"]

    # 3. First distinct approver (Admin)
    resp_app1 = client.post(
        f"/v1/break-glass/{override_id}/approve",
        json={},
        headers={"X-Dev-Role": "ADMIN", "X-Dev-User": "admin-1"},
    )
    assert resp_app1.status_code == 200
    assert resp_app1.json()["state"] == "PENDING"
    assert len(resp_app1.json()["approvals"]) == 1

    # Cannot approve twice with same identity
    resp_dup = client.post(
        f"/v1/break-glass/{override_id}/approve",
        json={},
        headers={"X-Dev-Role": "ADMIN", "X-Dev-User": "admin-1"},
    )
    assert resp_dup.status_code == 400

    # 4. Second distinct approver (SecOps on-call) -> Reaches quorum (2 approvers)
    resp_app2 = client.post(
        f"/v1/break-glass/{override_id}/approve",
        json={},
        headers={"X-Dev-Role": "SECOPS", "X-Dev-User": "secops-2"},
    )
    assert resp_app2.status_code == 200
    activated = resp_app2.json()
    assert activated["state"] == "ACTIVE"
    assert activated["activated_at"] is not None
    assert activated["expires_at"] is not None

    # Check store status
    active_manifest = break_glass_store.get_active()
    assert active_manifest is not None
    assert active_manifest.state == BreakGlassState.ACTIVE

    # Verify allowlist check: permitted destination allowed, other destination not allowed
    assert break_glass_store.is_destination_allowed("0x000000000000000000000000000000000000b001")
    assert not break_glass_store.is_destination_allowed("0x000000000000000000000000000000000000b999")

    # 5. Revocation by single operator (tightening: instant single-operator)
    resp_rev = client.post(
        f"/v1/break-glass/{override_id}/revoke",
        json={"reason": "Emergency resolved"},
        headers={"X-Dev-Role": "SECOPS", "X-Dev-User": "secops-3"},
    )
    assert resp_rev.status_code == 200
    assert resp_rev.json()["state"] == "REVOKED"
    assert break_glass_store.get_active() is None
    assert not break_glass_store.is_destination_allowed("0x000000000000000000000000000000000000b001")


# ==============================================================================
# 5. Prometheus /metrics Endpoint & Metric Observability
# ==============================================================================


def test_prometheus_metrics_endpoint():
    """Verifies /metrics endpoint exports all required metrics with correct names."""
    app = create_app()
    client = TestClient(app)

    # Record some sample metric observations
    record_decision("ALLOW", "ethereum")
    record_decision("DENY", "arbitrum")
    record_stage_duration("decode", 0.002)
    record_stage_duration("limits", 0.005)
    record_reservation_failure("USDC", "ethereum")
    record_unmatched_intent("ethereum")
    record_token_issue("bg-ed25519-v1")
    record_token_refusal("breaker_lockdown")
    update_breaker_state_metric("NORMAL")
    update_heartbeat_age_metric(4.2)

    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    text = resp.text

    # Verify all required metric names exist in the exposition
    expected_metrics = [
        "bitguard_decisions_total",
        "bitguard_stage_duration_seconds",
        "bitguard_reservation_failures_total",
        "bitguard_unmatched_intents_total",
        "bitguard_token_issues_total",
        "bitguard_token_refusals_total",
        "bitguard_breaker_state",
        "bitguard_heartbeat_age_seconds",
    ]
    for metric_name in expected_metrics:
        assert metric_name in text, f"Missing metric {metric_name} in Prometheus export"


# ==============================================================================
# 6. High Availability: Multi-Replica State Sharing & Failover
# ==============================================================================


def test_multi_replica_shared_state_and_failover():
    """Verifies that killing or switching between replicas maintains uninterrupted service.

    Shared state (circuit breaker, policy versions, limit stores) lives in Postgres/Redis,
    allowing Replica 2 to seamlessly continue when Replica 1 is stopped.
    """
    app1 = create_app()
    app2 = create_app()

    client1 = TestClient(app1)
    client2 = TestClient(app2)

    # Both replicas start healthy
    resp1 = client1.get("/healthz")
    resp2 = client2.get("/healthz")
    assert resp1.status_code == 200
    assert resp2.status_code == 200

    # Replica 1 escalates breaker state to ELEVATED
    esc_resp = client1.post(
        "/v1/breaker/escalate",
        json={"target_state": "ELEVATED", "reason": "Anomaly detected by replica 1"},
        headers={"X-Dev-Role": "SECOPS"},
    )
    assert esc_resp.status_code == 200

    # Simulate 'killing' Replica 1 (stop sending requests to it)
    # Replica 2 must immediately observe the shared ELEVATED state from shared store
    brk_resp2 = client2.get("/v1/breaker")
    assert brk_resp2.status_code == 200
    assert brk_resp2.json()["state"] == "ELEVATED"

    # Replica 2 can handle evaluations without interruption
    eval_resp = client2.get("/healthz")
    assert eval_resp.status_code == 200
