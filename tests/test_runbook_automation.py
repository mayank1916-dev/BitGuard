"""Comprehensive test suite for Incident Runbook Automation and Escalation (Milestone S19 / F14).

Invariants & Acceptance Criteria:
- Declarative runbooks in policy/runbooks/*.yaml: automatic, manual, approval steps.
- Runbook executor executes automatic actions: set_breaker_state, revoke_tokens, notify_oncall,
  open_incident, freeze_withdrawals_flag.
- S17 Delegation Watcher detection triggers runbook automatically.
- Breaker reaches HOLD automatically upon detection.
- time_to_contain is recorded and is under configured target in the lab (< 100 ms).
- Manual checklist items (rotate deposit addresses, neutralise delegation, sweep to cold,
  contact issuers, publish status) can be ticked with timestamp and user attribution.
- Approval steps require WebAuthn hardware key assertions from authorized roles.
- Tiered escalation: unacknowledged incidents escalate to next tier and page on-call.
- On-call notifications contain console links only, never inline approve buttons (Invariant #5).
- All transitions and actions append to immutable hash-chained audit trail (Invariant #7).
"""

import asyncio
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from services.bitguard.approvals.webauthn import (
    approver_registry,
    create_test_webauthn_assertion,
)
from services.bitguard.audit_service import audit_service
from services.bitguard.breaker import distributed_breaker_store, token_epoch_store
from services.bitguard.breaker.models import BreakerStateEnum
from services.bitguard.config import settings
from services.bitguard.incidents.escalation import escalation_manager
from services.bitguard.incidents.executor import runbook_executor
from services.bitguard.incidents.models import (
    IncidentStatus,
    StepType,
)
from services.bitguard.incidents.notifiers import oncall_notifier
from services.bitguard.incidents.store import incident_store
from services.bitguard.main import app
from services.bitguard.models import CreateWatchedAddressRequest, Role
from services.bitguard.rbac import ALL_TEST_USERS, SEEDED_USERS, create_access_token
from services.bitguard.rpc.client import MockRpcClient
from services.bitguard.watcher.provider_pool import provider_pool
from services.bitguard.watcher.store import watched_address_store
from services.bitguard.watcher.worker import delegation_watcher

client = TestClient(app)

WATCHED_HOT_WALLET = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
UNAPPROVED_DELEGATE_ADDR = "0x9999999999999999999999999999999999999999"
UNAPPROVED_7702_BYTECODE = "0xef0100" + UNAPPROVED_DELEGATE_ADDR[2:].lower()


@pytest.fixture(autouse=True)
def reset_incident_environment():
    """Resets all relevant stores and notifiers between tests."""
    incident_store.clear()
    watched_address_store.clear()
    distributed_breaker_store.reset()
    token_epoch_store.reset()
    oncall_notifier.clear()
    approver_registry.reset_replays()
    approver_registry._init_dev_approvers()
    runbook_executor.load_runbooks()

    yield

    incident_store.clear()
    watched_address_store.clear()
    distributed_breaker_store.reset()
    oncall_notifier.clear()
    approver_registry.reset_replays()


def get_auth_header(role: Role = Role.SECOPS, user_id: str | None = None) -> dict[str, str]:
    """Generates valid JWT Bearer header for test users."""
    user = SEEDED_USERS.get(role)
    if not user:
        for u in ALL_TEST_USERS.values():
            if u.role == role:
                user = u
                break
    assert user is not None, f"No seeded user for role {role}"
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Test 1: Runbook Manifest Loading & Schema Validation
# ---------------------------------------------------------------------------
def test_shipped_runbooks_loaded_and_valid():
    """Validates that all three mandatory runbooks exist and parse into models."""
    runbooks = runbook_executor.runbooks
    assert "DELEGATION_DETECTED" in runbooks
    assert "VELOCITY_SPIKE" in runbooks
    assert "MANUAL_LOCKDOWN" in runbooks

    rb_del = runbooks["DELEGATION_DETECTED"]
    assert rb_del.id == "delegation_detected"
    assert rb_del.severity == "CRITICAL"
    assert rb_del.target_time_to_contain_ms <= 100.0

    action_names = [s.action for s in rb_del.steps]
    step_types = [s.type for s in rb_del.steps]

    # Automatic actions
    assert "open_incident" in action_names
    assert "set_breaker_state" in action_names
    assert "revoke_tokens" in action_names
    assert "freeze_withdrawals_flag" in action_names
    assert "notify_oncall" in action_names

    # Manual remediation steps
    assert "neutralise_delegation" in action_names
    assert "sweep_to_cold" in action_names
    assert "rotate_deposit_addresses" in action_names

    # Approval step
    assert "approve_containment_release" in action_names
    assert StepType.APPROVAL in step_types
    assert StepType.MANUAL in step_types
    assert StepType.AUTOMATIC in step_types


# ---------------------------------------------------------------------------
# Test 2: S17 Delegation Detection Triggers Runbook & Measures Containment
# ---------------------------------------------------------------------------
def test_simulated_delegation_triggers_runbook_and_measures_containment():
    """Simulated delegation detection (S17) triggers runbook, trips breaker to HOLD, and records containment time."""
    # 1. Register watched hot wallet
    watched_address_store.create(
        CreateWatchedAddressRequest(
            address=WATCHED_HOT_WALLET,
            chain="ethereum",
            label="Main Hot Wallet",
            allowed_delegates=[],
        )
    )

    # 2. Deploy unapproved EIP-7702 delegate code on RPC
    mock_rpc_1 = MockRpcClient()
    mock_rpc_2 = MockRpcClient()
    mock_rpc_1.set_contract(WATCHED_HOT_WALLET, UNAPPROVED_7702_BYTECODE)
    mock_rpc_2.set_contract(WATCHED_HOT_WALLET, UNAPPROVED_7702_BYTECODE)
    provider_pool.providers = [("rpc_1", mock_rpc_1), ("rpc_2", mock_rpc_2)]

    initial_epoch = token_epoch_store.get_current_epoch()

    # 3. Scan block with delegation watcher
    alerts = delegation_watcher.scan_block(block_number=100)
    assert len(alerts) > 0
    crit_alerts = [a for a in alerts if a.severity == "CRITICAL"]
    assert len(crit_alerts) == 1
    assert crit_alerts[0].breaker_tripped is True

    # 4. Verify Breaker automatically reached HOLD
    assert distributed_breaker_store.get_state() == BreakerStateEnum.HOLD

    # 5. Verify Token Epoch was incremented (tokens revoked)
    assert token_epoch_store.get_current_epoch() > initial_epoch

    # 6. Verify Incident was created in store
    incidents = incident_store.list_all(trigger="DELEGATION_DETECTED")
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.status == IncidentStatus.CONTAINED
    assert inc.runbook_id == "delegation_detected"
    assert inc.contained_at is not None

    # 7. Verify time_to_contain is recorded and strictly under configured target (100 ms)
    assert inc.time_to_contain_ms is not None
    assert inc.time_to_contain_ms > 0.0
    assert inc.time_to_contain_ms < settings.incident_target_time_to_contain_ms
    # Measured latency in memory should typically be under 50 ms
    assert inc.time_to_contain_ms < 50.0

    # 8. Verify On-Call notification dispatched
    assert len(oncall_notifier.mock_notifier.dispatched_pages) >= 1
    page = oncall_notifier.mock_notifier.dispatched_pages[0]
    assert page["incident_id"] == inc.id
    assert page["level"] == 1

    # 9. Verify Hot Wallet Withdrawal Freeze Flag
    assert inc.metadata.get("withdrawals_frozen") is True

    # 10. Verify Timeline events
    event_types = [t.event_type for t in inc.timeline]
    assert "INCIDENT_OPENED" in event_types
    assert "INCIDENT_CONTAINED" in event_types
    assert "TOKENS_REVOKED" in event_types
    assert "WITHDRAWALS_FROZEN" in event_types
    assert "ONCALL_PAGED" in event_types


# ---------------------------------------------------------------------------
# Test 3: Manual Remediation Checklist Items & Attribution
# ---------------------------------------------------------------------------
def test_manual_checklist_items_ticking_and_attribution():
    """Manual remediation checklist items can be ticked with operator attribution and timestamp."""
    inc = runbook_executor.trigger_runbook("DELEGATION_DETECTED")

    checklist_actions = [c.action for c in inc.checklist]
    assert "neutralise_delegation" in checklist_actions
    assert "sweep_to_cold" in checklist_actions
    assert "rotate_deposit_addresses" in checklist_actions

    # Tick via executor
    updated_inc = runbook_executor.tick_checklist_item(
        incident_id=inc.id,
        action="neutralise_delegation",
        ticked_by="operator@bitguard.exchange",
        notes="Submitted Type-4 clearing transaction 0xabc123",
    )

    ticked_item = next(c for c in updated_inc.checklist if c.action == "neutralise_delegation")
    assert ticked_item.ticked is True
    assert ticked_item.ticked_by == "operator@bitguard.exchange"
    assert ticked_item.ticked_at is not None
    assert ticked_item.notes == "Submitted Type-4 clearing transaction 0xabc123"

    # Verify timeline event recorded
    tle = next(t for t in updated_inc.timeline if t.event_type == "CHECKLIST_TICKED")
    assert "neutralise_delegation" in tle.message

    # Ticking nonexistent action raises ValueError
    with pytest.raises(ValueError, match="does not exist"):
        runbook_executor.tick_checklist_item(inc.id, "nonexistent_action")


# ---------------------------------------------------------------------------
# Test 4: WebAuthn Hardware Approval Gate & Incident Resolution
# ---------------------------------------------------------------------------
def test_webauthn_hardware_approval_gate_and_resolution():
    """WebAuthn hardware assertion approves gate; completing all items marks incident RESOLVED."""
    inc = runbook_executor.trigger_runbook("DELEGATION_DETECTED")

    # Find pending approval gate
    assert len(inc.approvals) == 1
    approval = inc.approvals[0]
    assert approval.status == "PENDING"
    assert approval.required_role == Role.SECOPS
    challenge = approval.challenge

    secops_user = SEEDED_USERS[Role.SECOPS]
    secops_priv = approver_registry.dev_private_keys["usr-secops-01"]

    # 1. Attempt approval with unauthorized role (Viewer) -> Fails
    viewer_user = SEEDED_USERS[Role.VIEWER]
    assertion = create_test_webauthn_assertion(
        private_key=secops_priv,
        tx_digest=challenge,
        sign_count=1,
    )
    with pytest.raises(PermissionError, match="not authorized"):
        runbook_executor.approve_step(
            incident_id=inc.id,
            step_action=approval.action,
            approver_user=viewer_user,
            assertion=assertion,
        )

    # 2. Approve with valid SecOps WebAuthn assertion -> Succeeds
    approved_inc = runbook_executor.approve_step(
        incident_id=inc.id,
        step_action=approval.action,
        approver_user=secops_user,
        assertion=assertion,
    )
    assert approved_inc.approvals[0].status == "APPROVED"
    assert approved_inc.approvals[0].approved_by == secops_user.id
    assert approved_inc.approvals[0].webauthn_assertion_ref is not None

    # Incident is not resolved yet because manual checklist items remain unticked
    assert approved_inc.status != IncidentStatus.RESOLVED

    # 3. Tick all remaining checklist items
    for item in approved_inc.checklist:
        runbook_executor.tick_checklist_item(
            incident_id=inc.id,
            action=item.action,
            ticked_by="secops@bitguard.exchange",
        )

    resolved_inc = incident_store.get(inc.id)
    assert resolved_inc is not None
    assert resolved_inc.status == IncidentStatus.RESOLVED
    assert resolved_inc.resolved_at is not None


# ---------------------------------------------------------------------------
# Test 5: Tiered On-Call Escalation & Invariant #5 Verification
# ---------------------------------------------------------------------------
def test_tiered_oncall_escalation_and_link_only_invariant():
    """Unacknowledged incident escalates to Level 2; notifications contain links only."""
    async def _async_test():
        inc = runbook_executor.trigger_runbook("DELEGATION_DETECTED")
        assert inc.acknowledged is False
        assert inc.escalation_level == 1

        # Simulate 6 minutes passing (configured timeout is 300s = 5m)
        future_time = inc.detected_at + timedelta(seconds=350)

        escalated = await escalation_manager.check_and_escalate_incidents(
            now=future_time,
            ack_timeout_seconds=300,
        )
        assert len(escalated) == 1
        assert escalated[0].id == inc.id
        assert escalated[0].escalation_level == 2
        assert escalated[0].status == IncidentStatus.ESCALATED

        # Verify Level 2 page dispatched
        pages = [p for p in oncall_notifier.mock_notifier.dispatched_pages if p["level"] == 2]
        assert len(pages) == 1
        assert pages[0]["incident_id"] == inc.id

        # Invariant #5: Check Slack notification format contains deep link, NEVER inline approve button
        slack_payload = oncall_notifier.notifiers[0].format_payload(inc, level=2, message="Test")  # type: ignore[attr-defined]
        slack_text = slack_payload["text"]
        assert "https://console.bitguard.exchange/incidents/" in slack_text
        assert "approve_button" not in slack_payload

        # On-call engineer acknowledges incident
        ack_inc = await escalation_manager.acknowledge_incident(
            incident_id=inc.id,
            acknowledged_by="alice_oncall@bitguard.exchange",
        )
        assert ack_inc.acknowledged is True
        assert ack_inc.acknowledged_by == "alice_oncall@bitguard.exchange"
        assert ack_inc.acknowledged_at is not None

        # Subsequent check does NOT escalate acknowledged incident
        further_future = future_time + timedelta(seconds=600)
        further_escalated = await escalation_manager.check_and_escalate_incidents(now=further_future)
        assert len(further_escalated) == 0

    asyncio.run(_async_test())


# ---------------------------------------------------------------------------
# Test 6: Velocity Spike Runbook Execution
# ---------------------------------------------------------------------------
def test_velocity_spike_runbook():
    """Velocity spike runbook executes automatic actions and registers contact_issuers checklist."""
    inc = runbook_executor.trigger_runbook("VELOCITY_SPIKE", {"surge_rate": "350%", "asset": "USDC"})
    assert inc.severity == "HIGH"
    assert distributed_breaker_store.get_state() == BreakerStateEnum.HOLD
    assert inc.status == IncidentStatus.CONTAINED

    checklist_actions = [c.action for c in inc.checklist]
    assert "contact_issuers" in checklist_actions
    assert "publish_status" in checklist_actions


# ---------------------------------------------------------------------------
# Test 7: Manual Emergency Lockdown Runbook Execution
# ---------------------------------------------------------------------------
def test_manual_lockdown_runbook():
    """Manual lockdown executes immediate platform LOCKDOWN and revokes all tokens."""
    inc = runbook_executor.trigger_runbook("MANUAL_LOCKDOWN", {"initiated_by": "SecOps"})
    assert inc.severity == "CRITICAL"
    assert distributed_breaker_store.get_state() == BreakerStateEnum.LOCKDOWN
    assert inc.status == IncidentStatus.CONTAINED

    checklist_actions = [c.action for c in inc.checklist]
    assert "sweep_to_cold" in checklist_actions
    assert "publish_status" in checklist_actions

    # Quorum unlock requires Admin role
    approval = inc.approvals[0]
    assert approval.required_role == Role.ADMIN


# ---------------------------------------------------------------------------
# Test 8: REST API Endpoints (/v1/incidents & /v1/runbooks)
# ---------------------------------------------------------------------------
def test_incident_api_endpoints():
    """Verifies all incident and runbook REST API endpoints."""
    secops_headers = get_auth_header(Role.SECOPS)
    operator_headers = get_auth_header(Role.OPERATOR)

    # 1. Trigger incident via API
    resp_trig = client.post(
        "/v1/incidents/trigger",
        headers=secops_headers,
        json={"trigger": "DELEGATION_DETECTED", "context": {"note": "Test trigger"}},
    )
    assert resp_trig.status_code == 201
    inc_data = resp_trig.json()
    inc_id = inc_data["id"]
    assert inc_data["status"] == "CONTAINED"
    assert inc_data["time_to_contain_ms"] is not None

    # 2. GET /v1/incidents
    resp_list = client.get("/v1/incidents", headers=secops_headers)
    assert resp_list.status_code == 200
    assert len(resp_list.json()) >= 1
    assert any(i["id"] == inc_id for i in resp_list.json())

    # 3. GET /v1/incidents/{id}
    resp_get = client.get(f"/v1/incidents/{inc_id}", headers=operator_headers)
    assert resp_get.status_code == 200
    assert resp_get.json()["id"] == inc_id

    # 4. Tick checklist item via API
    resp_tick = client.post(
        f"/v1/incidents/{inc_id}/checklist/neutralise_delegation/tick",
        headers=operator_headers,
        json={"notes": "Neutralised via API"},
    )
    assert resp_tick.status_code == 200
    checklist_resp = resp_tick.json()["checklist"]
    neut_item = next(c for c in checklist_resp if c["action"] == "neutralise_delegation")
    assert neut_item["ticked"] is True

    # 5. Acknowledge on-call page via API
    resp_ack = client.post(
        f"/v1/incidents/{inc_id}/acknowledge",
        headers=operator_headers,
        json={"acknowledged_by": "oncall_bot"},
    )
    assert resp_ack.status_code == 200
    assert resp_ack.json()["acknowledged"] is True
    assert resp_ack.json()["acknowledged_by"] == "oncall_bot"

    # 6. Manually escalate via API
    resp_esc = client.post(
        f"/v1/incidents/{inc_id}/escalate?reason=Manual+Escalation+Test",
        headers=secops_headers,
    )
    assert resp_esc.status_code == 200
    assert resp_esc.json()["escalation_level"] >= 2

    # 7. GET /v1/runbooks
    resp_rbs = client.get("/v1/runbooks", headers=operator_headers)
    assert resp_rbs.status_code == 200
    rb_list = resp_rbs.json()
    assert len(rb_list) >= 3
    assert any(r["id"] == "delegation_detected" for r in rb_list)

    # 8. GET /v1/runbooks/{id}
    resp_rb = client.get("/v1/runbooks/delegation_detected", headers=operator_headers)
    assert resp_rb.status_code == 200
    assert resp_rb.json()["id"] == "delegation_detected"


# ---------------------------------------------------------------------------
# Test 9: Invariants & Immutable Audit Trail
# ---------------------------------------------------------------------------
def test_incident_audit_trail_and_strict_invariants():
    """All runbook actions and checklist ticks append to the immutable hash-chained audit log."""
    initial_chain_length = len(audit_service.get_entries())

    inc = runbook_executor.trigger_runbook("DELEGATION_DETECTED")
    runbook_executor.tick_checklist_item(inc.id, "sweep_to_cold", ticked_by="secops")

    # Verify audit entries were appended
    entries = audit_service.get_entries()
    assert len(entries) > initial_chain_length
    runbook_entries = [
        e for e in entries
        if "RUNBOOK" in (e.action or "") or "CHECKLIST" in (e.action or "")
    ]
    assert len(runbook_entries) >= 2

    # Verify hash-chain integrity
    assert audit_service.verify_chain().ok is True
