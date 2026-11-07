"""Comprehensive test suite for Versioned Policy Management (Milestone S20 / Section D).

Invariants & Requirements:
- Policy schema: limits per wallet/asset/chain/global, hold thresholds, hold_score,
  mode per wallet group, delegate_allowlist (code hash), owned addresses, time-lock, risk weights.
- policy_versions table: id, content, content_hash, author, created_at, status, signatures.
- classify_change(old, new) -> TIGHTEN | LOOSEN | MIXED. MIXED treated as LOOSEN.
- TIGHTEN: one Operator/SecOps/Admin activates instantly.
- LOOSEN: requires 2 approvers with WebAuthn (author cannot approve), cool-down delay,
  attached backtest_report_id (cannot approve without report).
- Activation verifies Ed25519 signature and content hash. Hot-reloads decision engine.
- Auto-rollback: reverts to previous healthy version on validation/health failure and alerts.
- Every change appends to immutable audit interface.
- Integrity check: compares loaded policy hash against ACTIVE record; direct DB tamper
  detected => alerts and fails closed (reverts engine to last verified safe version and trips breaker to HOLD).
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from services.bitguard.approvals.webauthn import (
    approver_registry,
    create_test_webauthn_assertion,
)
from services.bitguard.audit_service import audit_service
from services.bitguard.breaker import distributed_breaker_store
from services.bitguard.breaker.models import BreakerStateEnum
from services.bitguard.engine.pipeline import decision_engine
from services.bitguard.main import app
from services.bitguard.models import OperationMode, Role
from services.bitguard.policy.classifier import classify_change
from services.bitguard.policy.crypto import (
    DEV_RELEASE_PRIVATE_KEY,
    compute_content_hash,
    sign_content_hash,
)
from services.bitguard.policy.models import (
    ChangeClassification,
    PolicyStatus,
    ProposePolicyRequest,
    WalletGroupPolicy,
)
from services.bitguard.policy.service import policy_service
from services.bitguard.policy.store import policy_store
from services.bitguard.rbac import ALL_TEST_USERS, SEEDED_USERS, create_access_token

client = TestClient(app)

WATCHED_WALLET = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
BENIGN_HASH = "0x1111111111111111111111111111111111111111111111111111111111111111"
NEW_HASH = "0x2222222222222222222222222222222222222222222222222222222222222222"


@pytest.fixture(autouse=True)
def reset_policy_environment():
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


def get_auth_header(role: Role = Role.SECOPS, user_id: str | None = None) -> dict[str, str]:
    """Generates valid JWT Bearer header for test users."""
    user = SEEDED_USERS.get(role)
    if not user:
        for u in ALL_TEST_USERS.values():
            if u.role == role:
                user = u
                break
    assert user is not None
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Test 1: Policy Schema & Canonical Serialization
# ---------------------------------------------------------------------------
def test_policy_schema_and_canonical_hash():
    """Validates policy schema fields and deterministic hashing."""
    baseline = policy_service.get_or_create_baseline()
    assert baseline.version == "v1.0.0"
    assert baseline.status == PolicyStatus.ACTIVE
    assert len(baseline.content_hash) == 64

    # Recomputed content hash must match exactly
    recomputed = compute_content_hash(baseline.content)
    assert recomputed == baseline.content_hash

    # Check schema elements
    doc = baseline.content
    assert doc.limits.global_daily_usd == 1_000_000.0
    assert doc.thresholds.single_tx_usd == 50_000.0
    assert doc.thresholds.hold_score == 50
    assert "default" in doc.wallet_groups
    assert doc.time_lock.delay_seconds == 3600
    assert "NEW_CONTRACT" in doc.risk_weights


# ---------------------------------------------------------------------------
# Test 2: Policy Diff Classifier (classify_change)
# ---------------------------------------------------------------------------
def test_classify_change_transitions():
    """Tests all change classification transitions: TIGHTEN, LOOSEN, MIXED."""
    base_doc = policy_service.get_or_create_baseline().content

    # 1. Pure tightening: lowering single_tx threshold from 50k to 25k
    tighten_doc = base_doc.model_copy(deep=True)
    tighten_doc.thresholds.single_tx_usd = 25_000.0
    assert classify_change(base_doc, tighten_doc) == ChangeClassification.TIGHTEN

    # 2. Pure loosening: raising global daily limit from 1M to 2M
    loosen_doc = base_doc.model_copy(deep=True)
    loosen_doc.limits.global_daily_usd = 2_000_000.0
    assert classify_change(base_doc, loosen_doc) == ChangeClassification.LOOSEN

    # 3. Allowlist addition: adding a new delegate code hash -> LOOSEN
    loosen_allowlist_doc = base_doc.model_copy(deep=True)
    loosen_allowlist_doc.delegate_allowlist.append(NEW_HASH)
    assert classify_change(base_doc, loosen_allowlist_doc) == ChangeClassification.LOOSEN

    # 4. Mode change loosening: ENFORCE -> SHADOW or SHADOW -> SIMULATION
    mode_tighten_doc = base_doc.model_copy(deep=True)
    mode_tighten_doc.wallet_groups["default"] = WalletGroupPolicy(
        mode=OperationMode.ENFORCE,
        wallets=[WATCHED_WALLET],
    )
    assert classify_change(base_doc, mode_tighten_doc) == ChangeClassification.TIGHTEN

    mode_loosen_doc = mode_tighten_doc.model_copy(deep=True)
    mode_loosen_doc.wallet_groups["default"] = WalletGroupPolicy(
        mode=OperationMode.SHADOW,
        wallets=[WATCHED_WALLET],
    )
    assert classify_change(mode_tighten_doc, mode_loosen_doc) == ChangeClassification.LOOSEN

    # 5. Mixed changes: lowering a limit (TIGHTEN) but adding an allowed delegate (LOOSEN)
    mixed_doc = base_doc.model_copy(deep=True)
    mixed_doc.thresholds.single_tx_usd = 10_000.0  # TIGHTEN
    mixed_doc.delegate_allowlist.append(NEW_HASH)  # LOOSEN
    assert classify_change(base_doc, mixed_doc) == ChangeClassification.MIXED


# ---------------------------------------------------------------------------
# Test 3: Instant Activation for Tightening Policy
# ---------------------------------------------------------------------------
def test_tightening_policy_activates_instantly_without_quorum():
    """TIGHTEN change can be proposed and activated instantly by one Operator/SecOps/Admin."""
    operator_user = SEEDED_USERS[Role.OPERATOR]
    base_doc = policy_service.get_or_create_baseline().content

    new_doc = base_doc.model_copy(deep=True)
    new_doc.version = "v1.1.0"
    new_doc.thresholds.single_tx_usd = 20_000.0  # Tightening: 50k -> 20k

    # Propose
    req = ProposePolicyRequest(version="v1.1.0", content=new_doc)
    pv = policy_service.propose_policy(req, author_user=operator_user)
    assert pv.change_type == ChangeClassification.TIGHTEN
    assert pv.cool_down_until is None

    # Instant activation by Operator (no quorum or cool-down needed)
    activated = policy_service.activate_policy(pv.id, activator_user=operator_user)
    assert activated.status == PolicyStatus.ACTIVE
    assert activated.activated_at is not None

    # Decision engine now reflects tightened 20k threshold
    assert decision_engine.config.single_tx_usd_threshold == 20_000.0
    assert decision_engine.config.policy_version == "v1.1.0"


# ---------------------------------------------------------------------------
# Test 4: Loosening Governance: Quorum, Backtest Report, Separation of Duties
# ---------------------------------------------------------------------------
def test_loosening_policy_requires_quorum_backtest_report_and_cooldown():
    """LOOSEN policy change requires 2 WebAuthn approvers, backtest report, and author cannot self-approve."""
    secops_user = SEEDED_USERS[Role.SECOPS]
    approver1_user = SEEDED_USERS[Role.APPROVER]
    admin_user = SEEDED_USERS[Role.ADMIN]

    base_doc = policy_service.get_or_create_baseline().content
    loosen_doc = base_doc.model_copy(deep=True)
    loosen_doc.version = "v2.0.0"
    loosen_doc.limits.global_daily_usd = 5_000_000.0  # Loosening: 1M -> 5M
    loosen_doc.delegate_allowlist.append(NEW_HASH)

    # 1. Propose without backtest report
    req_no_report = ProposePolicyRequest(version="v2.0.0", content=loosen_doc)
    pv = policy_service.propose_policy(req_no_report, author_user=secops_user)
    assert pv.change_type == ChangeClassification.LOOSEN
    assert pv.cool_down_until is not None

    # 2. Attempt to approve without attached backtest report -> Rejected
    priv_appr1 = approver_registry.dev_private_keys["usr-approver-01"]
    assertion1 = create_test_webauthn_assertion(
        private_key=priv_appr1,
        tx_digest=pv.content_hash,
        sign_count=1,
    )
    with pytest.raises(ValueError, match="requires an attached backtest_report_id"):
        policy_service.approve_policy(pv.id, approver_user=approver1_user, assertion=assertion1)

    # Attach backtest report with matching draft policy hash (TASK S22 Hook)
    from services.bitguard.backtest.models import BacktestReport
    from services.bitguard.backtest.service import backtest_service

    btr = BacktestReport(
        id="rep-s22-backtest-9823",
        draft_policy_id=pv.id,
        draft_policy_hash=pv.content_hash,
        total_events=10,
        real_events_count=10,
        synthetic_events_count=0,
        allowed_count=10,
        held_count=0,
        denied_count=0,
        holds_per_day=0.0,
        estimated_false_positives=0,
        synthetic_loss_prevented_usd=0.0,
        synthetic_loss_allowed_usd=0.0,
        policy_diff={},
        summary={},
        steps=[],
    )
    backtest_service.save_report(btr)
    pv.backtest_report_id = "rep-s22-backtest-9823"
    policy_store.save(pv)

    # 3. Author (SecOps) attempts to approve their own change -> Forbidden (Separation of duties)
    priv_secops = approver_registry.dev_private_keys["usr-secops-01"]
    assertion_author = create_test_webauthn_assertion(
        private_key=priv_secops,
        tx_digest=pv.content_hash,
        sign_count=1,
    )
    with pytest.raises(PermissionError, match="author cannot approve"):
        policy_service.approve_policy(pv.id, approver_user=secops_user, assertion=assertion_author)

    # 4. Approver 1 approves with WebAuthn -> 1 approval recorded
    pv = policy_service.approve_policy(pv.id, approver_user=approver1_user, assertion=assertion1)
    assert len(pv.approvals) == 1

    # 5. Approver 1 attempts second approval -> Rejected (Duplicate)
    with pytest.raises(ValueError, match="already approved"):
        policy_service.approve_policy(pv.id, approver_user=approver1_user, assertion=assertion1)

    # 6. Approver 2 (Admin) approves with WebAuthn -> 2 approvals recorded (Quorum reached)
    priv_admin = approver_registry.dev_private_keys["usr-admin-01"]
    assertion2 = create_test_webauthn_assertion(
        private_key=priv_admin,
        tx_digest=pv.content_hash,
        sign_count=1,
    )
    pv = policy_service.approve_policy(pv.id, approver_user=admin_user, assertion=assertion2)
    assert len(pv.approvals) == 2

    # 7. Attempt activation before cool-down delay elapses -> Rejected
    with pytest.raises(ValueError, match="in cool-down delay"):
        policy_service.activate_policy(pv.id, activator_user=secops_user)

    # 8. Fast-forward past cool-down delay -> Activation succeeds
    pv.cool_down_until = datetime.now(UTC) - timedelta(seconds=1)
    policy_store.save(pv)

    activated = policy_service.activate_policy(pv.id, activator_user=secops_user)
    assert activated.status == PolicyStatus.ACTIVE
    assert decision_engine.config.policy_version == "v2.0.0"


# ---------------------------------------------------------------------------
# Test 5: Ed25519 Cryptographic Signature Verification on Activation
# ---------------------------------------------------------------------------
def test_ed25519_signature_verification_enforced():
    """Activation strictly verifies Ed25519 signature over content hash; invalid signature fails."""
    operator_user = SEEDED_USERS[Role.OPERATOR]
    base_doc = policy_service.get_or_create_baseline().content

    tighten_doc = base_doc.model_copy(deep=True)
    tighten_doc.version = "v1.2.0"
    tighten_doc.thresholds.hold_score = 40  # Tighten: 50 -> 40

    req = ProposePolicyRequest(version="v1.2.0", content=tighten_doc)
    pv = policy_service.propose_policy(req, author_user=operator_user)

    # Corrupt the Ed25519 signature
    bad_sig = "00" * 64
    with pytest.raises(ValueError, match="Invalid Ed25519 release authority signature"):
        policy_service.activate_policy(pv.id, activator_user=operator_user, ed25519_sig_override=bad_sig)

    # Valid Ed25519 signature succeeds
    good_sig = sign_content_hash(pv.content_hash, private_key=DEV_RELEASE_PRIVATE_KEY)
    activated = policy_service.activate_policy(pv.id, activator_user=operator_user, ed25519_sig_override=good_sig)
    assert activated.status == PolicyStatus.ACTIVE


# ---------------------------------------------------------------------------
# Test 6: Auto-Rollback on Validation Failure During Activation
# ---------------------------------------------------------------------------
def test_auto_rollback_on_health_failure():
    """If a new policy fails validation/health check, auto_rollback reverts to previous healthy version."""
    operator_user = SEEDED_USERS[Role.OPERATOR]
    baseline = policy_service.get_or_create_baseline()

    # Create and activate a valid v1.1.0
    v11_doc = baseline.content.model_copy(deep=True)
    v11_doc.version = "v1.1.0"
    v11_doc.thresholds.single_tx_usd = 45_000.0
    pv11 = policy_service.propose_policy(ProposePolicyRequest(version="v1.1.0", content=v11_doc), author_user=operator_user)
    policy_service.activate_policy(pv11.id, activator_user=operator_user)
    assert decision_engine.config.policy_version == "v1.1.0"

    # Now simulate an auto-rollback due to health failure
    reverted = policy_service.auto_rollback(
        version_id=pv11.id,
        reason="Health check alert: unexpected decode failures",
    )

    # Engine reverted to baseline
    assert reverted.status == PolicyStatus.ACTIVE
    assert reverted.version == "v1.0.0"
    assert decision_engine.config.policy_version == "v1.0.0"

    # Audit entry logged
    entries = audit_service.get_entries()
    assert any("POLICY_AUTO_ROLLEDBACK" in (e.action or "") for e in entries)


# ---------------------------------------------------------------------------
# Test 7: Direct Database Edit Detected by Periodic Integrity Check (Fail-Closed)
# ---------------------------------------------------------------------------
def test_direct_database_edit_detected_by_integrity_check_fails_closed():
    """Tamper Detection: Raising a limit via direct SQL edit is caught by integrity check, alerting and failing closed."""
    baseline = policy_service.get_or_create_baseline()
    assert decision_engine.active_policy_hash == baseline.content_hash

    # Initial integrity check: Clean
    res_clean = policy_service.run_integrity_check()
    assert res_clean.valid is True
    assert distributed_breaker_store.get_state() == BreakerStateEnum.NORMAL

    # Simulate rogue administrator or attacker editing database record directly
    # Attacker inflates global limit from $1,000,000 to $99,000,000 directly in SQL content
    tampered_pv = policy_store.get(baseline.id)
    assert tampered_pv is not None
    tampered_pv.content.limits.global_daily_usd = 99_000_000.0
    # Save directly to store bypassing propose/activate signing validation
    policy_store.save(tampered_pv)

    # Run integrity check
    res_tampered = policy_service.run_integrity_check()
    assert res_tampered.valid is False
    assert "Direct DB content edit detected" in res_tampered.details

    # Invariant #3: Fail-Closed Default
    # 1. Breaker escalated to HOLD to contain unauthorized signing risk
    assert distributed_breaker_store.get_state() == BreakerStateEnum.HOLD

    # 2. Immutable audit trail recorded
    entries = audit_service.get_entries()
    assert any("POLICY_INTEGRITY_TAMPER_DETECTED" in (e.action or "") for e in entries)


# ---------------------------------------------------------------------------
# Test 8: Policy REST API Endpoints
# ---------------------------------------------------------------------------
def test_policy_api_endpoints():
    """Validates policy REST API endpoints for propose, list, active, approve, activate, rollback, and check."""
    secops_headers = get_auth_header(Role.SECOPS)
    operator_headers = get_auth_header(Role.OPERATOR)

    base_doc = policy_service.get_or_create_baseline().content
    new_doc = base_doc.model_copy(deep=True)
    new_doc.version = "v1.5.0"
    new_doc.thresholds.single_tx_usd = 30_000.0  # Tighten

    # 1. POST /v1/policies (Propose)
    resp_prop = client.post(
        "/v1/policies",
        headers=operator_headers,
        json={"version": "v1.5.0", "content": new_doc.model_dump(mode="json")},
    )
    assert resp_prop.status_code == 201
    pv_id = resp_prop.json()["id"]
    assert resp_prop.json()["change_type"] == "TIGHTEN"

    # 2. GET /v1/policies
    resp_list = client.get("/v1/policies", headers=operator_headers)
    assert resp_list.status_code == 200
    assert any(p["id"] == pv_id for p in resp_list.json())

    # 3. GET /v1/policies/active
    resp_act = client.get("/v1/policies/active", headers=operator_headers)
    assert resp_act.status_code == 200
    assert resp_act.json()["version"] == "v1.0.0"

    # 4. GET /v1/policies/{id}
    resp_get = client.get(f"/v1/policies/{pv_id}", headers=operator_headers)
    assert resp_get.status_code == 200
    assert resp_get.json()["version"] == "v1.5.0"

    # 5. POST /v1/policies/{id}/activate
    resp_activate = client.post(f"/v1/policies/{pv_id}/activate", headers=operator_headers)
    assert resp_activate.status_code == 200
    assert resp_activate.json()["status"] == "ACTIVE"

    # 6. POST /v1/policies/integrity-check
    resp_check = client.post("/v1/policies/integrity-check", headers=secops_headers)
    assert resp_check.status_code == 200
    assert resp_check.json()["valid"] is True

    # 7. POST /v1/policies/{id}/rollback
    resp_roll = client.post(
        f"/v1/policies/{pv_id}/rollback",
        headers=secops_headers,
        json={"reason": "Test rollback API"},
    )
    assert resp_roll.status_code == 200
    assert resp_roll.json()["status"] == "ACTIVE"
    assert resp_roll.json()["version"] == "v1.0.0"


# ---------------------------------------------------------------------------
# Test 9: Hash-Chained Audit Trail Integrity
# ---------------------------------------------------------------------------
def test_policy_hash_chained_audit_trail():
    """Verifies that all policy modifications append to the hash-chained audit ledger."""
    secops_user = SEEDED_USERS[Role.SECOPS]
    initial_count = len(audit_service.get_entries())

    base_doc = policy_service.get_or_create_baseline().content
    new_doc = base_doc.model_copy(deep=True)
    new_doc.version = "v1.9.0"
    new_doc.thresholds.single_tx_usd = 15_000.0

    pv = policy_service.propose_policy(ProposePolicyRequest(version="v1.9.0", content=new_doc), author_user=secops_user)
    policy_service.activate_policy(pv.id, activator_user=secops_user)

    entries = audit_service.get_entries()
    assert len(entries) >= initial_count + 2

    # Verify cryptographic hash-chain integrity
    assert audit_service.verify_chain().ok is True


# ---------------------------------------------------------------------------
# Test 10: Engines Poll and Hot-Reload Active Version Pointer
# ---------------------------------------------------------------------------
def test_engine_polls_and_hot_reloads_active_pointer():
    """Engines hot-reload by polling the active version pointer."""
    operator_user = SEEDED_USERS[Role.OPERATOR]
    baseline = policy_service.get_or_create_baseline()

    new_doc = baseline.content.model_copy(deep=True)
    new_doc.version = "v1.3.0"
    new_doc.thresholds.single_tx_usd = 22_000.0

    pv = policy_service.propose_policy(
        ProposePolicyRequest(version="v1.3.0", content=new_doc),
        author_user=operator_user,
    )
    policy_service.activate_policy(pv.id, activator_user=operator_user)

    # Simulate another engine instance with older memory hash
    decision_engine.active_policy_hash = "0xold_outdated_hash"
    reloaded = policy_service.poll_active_version()
    assert reloaded is not None
    assert reloaded.version == "v1.3.0"
    assert decision_engine.active_policy_hash == pv.content_hash
    assert decision_engine.config.single_tx_usd_threshold == 22_000.0
