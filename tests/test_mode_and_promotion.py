"""Unit and integration tests for wallet group modes (SIMULATION, SHADOW, ENFORCE) and promotion rules (Milestone S04 / F7)."""

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from services.bitguard.audit_service import audit_service
from services.bitguard.main import app
from services.bitguard.mode_service import mode_service
from services.bitguard.models import (
    OperationMode,
    WalletGroupConfig,
)

client = TestClient(app)


def test_simulation_mode_evaluation():
    """SIMULATION mode evaluates dry-run without altering metrics counters."""
    group = WalletGroupConfig(
        id="test-sim-group",
        name="Test Simulation Wallets",
        mode=OperationMode.SIMULATION,
        wallets=["0xsim001"],
    )
    mode_service.register_wallet_group(group)

    payload = {
        "id": "sim-req-01",
        "raw_tx": "0x02f87001legit",
        "chain": "ethereum",
        "wallet": "0xsim001",
        "wallet_group": "test-sim-group",
        "metadata": {"amount_usd": 75000.0},  # Exceeds single tx limit ($50k)
    }

    response = client.post("/v1/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["mode"] == "SIMULATION"
    assert data["verdict"] == "HOLD"
    assert data["would_have_verdict"] is None

    # Check metrics are empty / unchanged for simulation
    metrics = mode_service.get_metrics_for_group("test-sim-group")
    assert len(metrics) == 0


def test_shadow_mode_pass_through_and_would_have_verdict():
    """SHADOW mode evaluates fully, stores would_have_verdict, returns pass-through ALLOW for policy limits."""
    group = WalletGroupConfig(
        id="test-shadow-group",
        name="Test Shadow Wallets",
        mode=OperationMode.SHADOW,
        wallets=["0xshadow001"],
        shadow_started_at=datetime.now(UTC),
    )
    mode_service.register_wallet_group(group)

    # 1. Policy limit exceeded (Amount $80k > $50k) -> would have been HOLD
    payload_limit = {
        "id": "shadow-req-limit",
        "raw_tx": "0x02f87001legit",
        "chain": "ethereum",
        "wallet": "0xshadow001",
        "wallet_group": "test-shadow-group",
        "metadata": {"amount_usd": 80000.0},
    }
    res_limit = client.post("/v1/sign-requests", json=payload_limit)
    assert res_limit.status_code == 200
    data_limit = res_limit.json()

    assert data_limit["mode"] == "SHADOW"
    assert data_limit["verdict"] == "ALLOW"  # Pass-through for policy verdicts
    assert data_limit["would_have_verdict"] == "HOLD"
    assert data_limit["risk_score"] == 65

    # 2. Suspicious delegation -> would have been DENY
    payload_deny = {
        "id": "shadow-req-deny",
        "raw_tx": "0x02f87001legit",
        "chain": "ethereum",
        "wallet": "0xshadow001",
        "wallet_group": "test-shadow-group",
        "metadata": {"simulate_deny": True, "amount_usd": 1000.0},
    }
    res_deny = client.post("/v1/sign-requests", json=payload_deny)
    assert res_deny.status_code == 200
    data_deny = res_deny.json()

    assert data_deny["mode"] == "SHADOW"
    assert data_deny["verdict"] == "ALLOW"  # Pass-through
    assert data_deny["would_have_verdict"] == "DENY"

    # 3. Legitimate small transfer -> ALLOW
    payload_ok = {
        "id": "shadow-req-ok",
        "raw_tx": "0x02f87001legit",
        "chain": "ethereum",
        "wallet": "0xshadow001",
        "wallet_group": "test-shadow-group",
        "metadata": {"amount_usd": 500.0},
    }
    res_ok = client.post("/v1/sign-requests", json=payload_ok)
    assert res_ok.status_code == 200
    data_ok = res_ok.json()

    assert data_ok["verdict"] == "ALLOW"
    assert data_ok["would_have_verdict"] is None

    # Verify daily counters
    metrics = mode_service.get_metrics_for_group("test-shadow-group")
    assert len(metrics) == 1
    m = metrics[0]
    assert m.would_have_blocked_count == 2
    assert m.would_have_blocked_value == 81000.0
    assert m.allowed_count == 1
    assert m.false_positive_count == 0


def test_shadow_mode_security_invariants_still_deny():
    """SHADOW mode still strictly denies when tx cannot be decoded or caller identity is invalid."""
    group = WalletGroupConfig(
        id="test-shadow-security",
        name="Test Shadow Security Wallets",
        mode=OperationMode.SHADOW,
        wallets=["0xsec001"],
    )
    mode_service.register_wallet_group(group)

    # 1. Cannot be decoded -> DENY (not pass-through!)
    payload_malformed = {
        "id": "shadow-malformed",
        "raw_tx": "",
        "chain": "ethereum",
        "wallet": "0xsec001",
        "wallet_group": "test-shadow-security",
    }
    res_malformed = client.post("/v1/sign-requests", json=payload_malformed)
    assert res_malformed.status_code == 200
    data_malformed = res_malformed.json()
    assert data_malformed["verdict"] == "DENY"
    assert data_malformed["reasons"][0]["code"] == "DECODE_ERROR"
    assert group.unexplained_decode_failures == 1

    # 2. Invalid caller identity -> DENY (not pass-through!)
    payload_caller = {
        "id": "shadow-caller-invalid",
        "raw_tx": "0x02f87001",
        "chain": "ethereum",
        "wallet": "0xsec001",
        "wallet_group": "test-shadow-security",
        "metadata": {"simulate_invalid_caller": True},
    }
    res_caller = client.post("/v1/sign-requests", json=payload_caller)
    assert res_caller.status_code == 200
    data_caller = res_caller.json()
    assert data_caller["verdict"] == "DENY"
    assert data_caller["reasons"][0]["code"] == "INVALID_CALLER_IDENTITY"


def test_enforce_mode_binding_verdict():
    """ENFORCE mode verdicts are binding."""
    group = WalletGroupConfig(
        id="test-enforce-group",
        name="Test Enforce Wallets",
        mode=OperationMode.ENFORCE,
        wallets=["0xenforce001"],
    )
    mode_service.register_wallet_group(group)

    # Policy limit exceeded -> HOLD is binding (NOT passed through)
    payload_limit = {
        "id": "enforce-req-limit",
        "raw_tx": "0x02f87001",
        "chain": "ethereum",
        "wallet": "0xenforce001",
        "wallet_group": "test-enforce-group",
        "metadata": {"amount_usd": 90000.0},
    }
    res_limit = client.post("/v1/sign-requests", json=payload_limit)
    assert res_limit.status_code == 200
    data_limit = res_limit.json()
    assert data_limit["mode"] == "ENFORCE"
    assert data_limit["verdict"] == "HOLD"
    assert data_limit["would_have_verdict"] is None

    # Legitimate transfer -> ALLOW is binding
    payload_ok = {
        "id": "enforce-req-ok",
        "raw_tx": "0x02f87001",
        "chain": "ethereum",
        "wallet": "0xenforce001",
        "wallet_group": "test-enforce-group",
        "metadata": {"amount_usd": 100.0},
    }
    res_ok = client.post("/v1/sign-requests", json=payload_ok)
    assert res_ok.status_code == 200
    data_ok = res_ok.json()
    assert data_ok["verdict"] == "ALLOW"


def test_false_positive_labeling_and_role_protection():
    """POST /v1/decisions/{id}/false-positive labels would-blocks and updates metrics."""
    group = WalletGroupConfig(
        id="test-fp-group",
        name="Test False Positive Wallets",
        mode=OperationMode.SHADOW,
        wallets=["0xfp001"],
    )
    mode_service.register_wallet_group(group)

    # Create a would-block decision
    payload = {
        "id": "fp-eval-req",
        "raw_tx": "0x02f87001",
        "chain": "ethereum",
        "wallet": "0xfp001",
        "wallet_group": "test-fp-group",
        "metadata": {"amount_usd": 60000.0},  # trips limit
    }
    res = client.post("/v1/sign-requests", json=payload)
    assert res.status_code == 200
    dec_id = res.json()["request_id"]

    # 1. Non-operator role should be forbidden (403)
    res_forbidden = client.post(
        f"/v1/decisions/{dec_id}/false-positive",
        headers={"X-User-Role": "viewer"},
        json={"reason": "Audited false positive", "operator_id": "alice"},
    )
    assert res_forbidden.status_code == 403

    # 2. Operator role succeeds (200)
    res_label = client.post(
        f"/v1/decisions/{dec_id}/false-positive",
        headers={"X-User-Role": "operator"},
        json={"reason": "Approved business transfer", "operator_id": "bob-secops"},
    )
    assert res_label.status_code == 200
    data_labeled = res_label.json()
    assert data_labeled["is_false_positive"] is True

    # Verify metrics incremented
    metrics = mode_service.get_metrics_for_group("test-fp-group")
    assert metrics[0].false_positive_count == 1

    # 3. Trying to label a legitimate non-blocking transaction returns 400
    ok_payload = {
        "id": "fp-ok-req",
        "raw_tx": "0x02f87001",
        "chain": "ethereum",
        "wallet": "0xfp001",
        "wallet_group": "test-fp-group",
        "metadata": {"amount_usd": 10.0},
    }
    client.post("/v1/sign-requests", json=ok_payload)
    res_bad_label = client.post(
        "/v1/decisions/fp-ok-req/false-positive",
        headers={"X-User-Role": "operator"},
        json={"reason": "Invalid attempt"},
    )
    assert res_bad_label.status_code == 400


def test_promotion_checklist_evaluation():
    """GET /v1/promotion-checklist validates duration, false-positive rate, and decode failures."""
    now = datetime.now(UTC)

    # Group 1: Brand new group in SHADOW (0 days < 14 days) -> fails duration check
    group_new = WalletGroupConfig(
        id="promo-new-group",
        name="New Group",
        mode=OperationMode.SHADOW,
        shadow_started_at=now,
    )
    mode_service.register_wallet_group(group_new)

    res_new = client.get("/v1/promotion-checklist?wallet_group=promo-new-group")
    assert res_new.status_code == 200
    check_data_new = res_new.json()
    assert check_data_new["can_promote"] is False
    assert check_data_new["checks"]["minimum_days_in_shadow"]["passed"] is False
    assert check_data_new["checks"]["zero_unexplained_decode_failures"]["passed"] is True

    # Group 2: Mature shadow group (15 days in shadow, zero decode errors, 0 FP) -> passes!
    group_mature = WalletGroupConfig(
        id="promo-mature-group",
        name="Mature Group",
        mode=OperationMode.SHADOW,
        shadow_started_at=now - timedelta(days=15),
        unexplained_decode_failures=0,
    )
    mode_service.register_wallet_group(group_mature)
    # Add metrics: 1000 allowed, 0 FP
    mode_service.record_metric("promo-mature-group", is_allowed=True)

    res_mature = client.get("/v1/promotion-checklist?wallet_group=promo-mature-group")
    assert res_mature.status_code == 200
    check_data_mature = res_mature.json()
    assert check_data_mature["can_promote"] is True
    assert check_data_mature["checks"]["minimum_days_in_shadow"]["passed"] is True
    assert check_data_mature["checks"]["false_positive_rate"]["passed"] is True
    assert check_data_mature["checks"]["zero_unexplained_decode_failures"]["passed"] is True


def test_promotion_to_enforce_blocked_without_passing_checklist():
    """Changing group to ENFORCE is blocked without passing checklist or explicit override."""
    group = WalletGroupConfig(
        id="promo-block-group",
        name="Blocked Group",
        mode=OperationMode.SHADOW,
        shadow_started_at=datetime.now(UTC) - timedelta(days=2),  # Only 2 days
    )
    mode_service.register_wallet_group(group)

    # 1. Attempt promotion without override -> HTTP 400
    update_payload = {"mode": "ENFORCE", "override": False}
    res = client.post("/v1/wallet-groups/promo-block-group/mode", json=update_payload)
    assert res.status_code == 400
    assert "Promotion rejected" in res.json()["detail"]
    assert group.mode == OperationMode.SHADOW  # Mode unchanged

    # 2. Attempt promotion with override=True but missing override_reason -> HTTP 400
    override_bad_payload = {"mode": "ENFORCE", "override": True, "override_reason": ""}
    res_bad = client.post("/v1/wallet-groups/promo-block-group/mode", json=override_bad_payload)
    assert res_bad.status_code == 400
    assert "override_reason is required" in res_bad.json()["detail"]

    # 3. Promotion with override=True and valid override_reason -> succeeds and records audit entry
    initial_audit_count = len(audit_service.get_entries())
    override_good_payload = {
        "mode": "ENFORCE",
        "override": True,
        "override_reason": "Emergency security lockdown mandated by SecOps Lead",
        "operator_id": "sec-lead",
    }
    res_good = client.post("/v1/wallet-groups/promo-block-group/mode", json=override_good_payload)
    assert res_good.status_code == 200
    assert res_good.json()["mode"] == "ENFORCE"
    assert group.mode == OperationMode.ENFORCE

    # Verify explicit override recorded in audit log (Invariant #7)
    audit_entries = audit_service.get_entries()
    assert len(audit_entries) > initial_audit_count
    override_event = next(e for e in reversed(audit_entries) if e.event_type == "MODE_PROMOTION_OVERRIDE")
    assert override_event.verdict == "OVERRIDE"
    assert "promo-override-promo-block-group" in override_event.request_id

    # Verify audit chain integrity remains intact
    is_valid, corrupted_idx = audit_service.verify_integrity()
    assert is_valid is True
    assert corrupted_idx is None
