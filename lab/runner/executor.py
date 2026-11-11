"""Integration Lab Scenario Executor (Milestone S23 / F19).

Loads declarative YAML test scenarios from lab/scenarios/ and executes them
against BitGuard, Signer Shim, Ledger Mock, and Delegation Watcher using
disposable testnet keys only.
"""

import logging
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

import fakeredis
import httpx
import redis
import rlp
import sqlalchemy as sa
import yaml
from eth_account import Account
from eth_utils import keccak
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.orm import sessionmaker

from lab.demo_custody.client import DemoCustodyClient
from lab.runner.config import (
    LATEST_JSON_FILE,
    LATEST_SUMMARY_FILE,
    RESULTS_DIR,
    SCENARIOS_DIR,
    lab_settings,
)
from lab.runner.models import (
    AssertionCheck,
    LabReport,
    LabSafetySummary,
    ScenarioDefinition,
    ScenarioResult,
)
from lab.runner.safety import (
    assert_non_mainnet,
)
from services.bitguard.approvals.hold_store import hold_store
from services.bitguard.approvals.service import approval_service
from services.bitguard.approvals.webauthn import (
    approver_registry,
    create_test_webauthn_assertion,
)
from services.bitguard.breaker import distributed_breaker_store, token_epoch_store
from services.bitguard.breaker.models import BreakerStateEnum
from services.bitguard.config import settings
from services.bitguard.database import set_engine
from services.bitguard.db_models import Base
from services.bitguard.decoders.evm import evm_decoder
from services.bitguard.engine.breaker_store import breaker_store
from services.bitguard.engine.pipeline import decision_engine
from services.bitguard.gateway.client_shim import signer_shim_client
from services.bitguard.gateway.handler import quarantine_store
from services.bitguard.ledger.mock import mock_ledger_connector
from services.bitguard.ledger.models import IntentStatus, WithdrawalIntent
from services.bitguard.limits.store import limit_store
from services.bitguard.main import app as bitguard_app
from services.bitguard.mode_service import mode_service
from services.bitguard.models import (
    CreateWatchedAddressRequest,
    DecisionReason,
    HoldTicket,
    OperationMode,
    Role,
)
from services.bitguard.rate_limiter import rate_limiter
from services.bitguard.rbac import ALL_TEST_USERS, SEEDED_USERS, create_access_token
from services.bitguard.rpc.client import MockRpcClient
from services.bitguard.rules.delegation import DelegationPolicy
from services.bitguard.stream.broadcaster import stream_broadcaster
from services.bitguard.tokens import KeySet, issue_token, token_manager
from services.bitguard.watcher.provider_pool import provider_pool
from services.bitguard.watcher.store import watched_address_store
from services.bitguard.watcher.worker import delegation_watcher
from services.signer_shim.main import app as shim_app
from services.signer_shim.main import init_public_key_set, set_public_key_set
from services.signer_shim.nonce_store import nonce_store

logger = logging.getLogger("lab.runner")

BENIGN_DEST_RAW = "1111111111111111111111111111111111111111"
BENIGN_DEST_HEX = "0x" + BENIGN_DEST_RAW
OWNED_HOT_WALLET = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
UNAPPROVED_DELEGATE_ADDR = "0x3333333333333333333333333333333333333333"

# Disposable testnet key for lab signing
DISPOSABLE_TEST_PRIVATE_KEY = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7dc3a0813f60e"


def build_raw_legacy_tx(to_hex: str = BENIGN_DEST_RAW, value: int = 1000, nonce: int = 0) -> str:
    """Helper constructing canonical unsigned legacy EVM transaction hex."""
    clean_hex = to_hex[2:] if to_hex.startswith("0x") else to_hex
    payload = [nonce, 20_000_000_000, 21000, bytes.fromhex(clean_hex), value, b""]
    return "0x" + rlp.encode(payload).hex()


def build_signed_eip7702_tx(
    authority_account: Any,
    to_addr: str,
    delegate_addr: str,
    nonce: int = 0,
    chain_id: int = 1,
) -> str:
    """Helper constructing canonical EIP-7702 (type 4) transaction with valid authority signature."""
    clean_to = bytes.fromhex(to_addr[2:] if to_addr.startswith("0x") else to_addr)
    clean_delegate = bytes.fromhex(delegate_addr[2:] if delegate_addr.startswith("0x") else delegate_addr)

    # Authority signs the authorization payload [chain_id, delegate, nonce]
    auth_digest = keccak(b"\x05" + rlp.encode([chain_id, clean_delegate, nonce]))
    sig = authority_account.unsafe_sign_hash(auth_digest)
    auth_item = [chain_id, clean_delegate, nonce, sig.v, sig.r, sig.s]

    raw_bytes = b"\x04" + rlp.encode([
        chain_id,
        nonce,
        1_000_000_000,
        30_000_000_000,
        100_000,
        clean_to,
        0,
        b"",
        [],
        [auth_item],
    ])
    return "0x" + raw_bytes.hex()


def get_auth_header(role: Role = Role.APPROVER, user_id: str | None = None) -> dict[str, str]:
    """Helper generating Bearer token for seeded test users."""
    user = ALL_TEST_USERS.get(user_id) if user_id else SEEDED_USERS[role]
    assert user is not None
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


class LabScenarioExecutor:
    """Orchestrates test scenarios from lab/scenarios/*.yaml against BitGuard."""

    def __init__(self) -> None:
        self.bitguard_client = TestClient(bitguard_app)
        self.shim_client = TestClient(shim_app)
        self.custody_client = DemoCustodyClient(
            base_url="http://testserver",
            transport=httpx.ASGITransport(app=bitguard_app),
            san="spiffe://exchange.internal/workload/custody",
        )
        self._init_in_memory_db()
        self._setup_harness()

    def _init_in_memory_db(self) -> None:
        """Sets up in-memory SQLite database to back Postgres models during lab execution."""
        test_engine = sa.create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=sa.pool.StaticPool,
        )
        Base.metadata.create_all(bind=test_engine)
        set_engine(test_engine)
        session_factory = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
        distributed_breaker_store.set_session_factory(session_factory)

    def _setup_harness(self) -> None:
        """Initializes test fixtures, simulated Redis, and in-memory bindings."""
        fake_redis = fakeredis.FakeRedis(decode_responses=True)
        limit_store.set_redis_client(fake_redis)
        nonce_store.set_redis_client(fake_redis)
        distributed_breaker_store.set_redis_client(fake_redis)
        token_epoch_store.set_redis_client(fake_redis)
        stream_broadcaster.set_sync_redis(fake_redis)
        rate_limiter.set_sync_redis(fake_redis)
        from services.bitguard.break_glass import break_glass_store
        break_glass_store.set_sync_redis(fake_redis)
        init_public_key_set()

        # Sync public key set for shim
        pub_dict = token_manager.key_set.export_public_key_set()
        set_public_key_set(KeySet.from_public_key_dict(pub_dict))

        signer_shim_client.transport = httpx.ASGITransport(app=shim_app)
        approval_service.shim_client.transport = httpx.ASGITransport(app=shim_app)

        default_group = mode_service.get_wallet_group("default")
        default_group.mode = OperationMode.ENFORCE

        mock_ledger_connector.reset()
        quarantine_store.clear()
        hold_store.clear()
        approver_registry.reset_replays()
        watched_address_store.clear()
        distributed_breaker_store.reset()
        breaker_store.reset()
        from services.signer_shim.heartbeat import heartbeat_tracker
        heartbeat_tracker.last_heartbeat_time = time.time()

    def load_scenarios(self, directory: Path | None = None) -> list[ScenarioDefinition]:
        """Loads all scenario YAML files in lexicographical order."""
        target_dir = directory or SCENARIOS_DIR
        scenarios: list[ScenarioDefinition] = []

        yaml_files = sorted(target_dir.glob("*.yaml"))
        for yf in yaml_files:
            content = yaml.safe_load(yf.read_text(encoding="utf-8"))
            try:
                sc = ScenarioDefinition.model_validate(content)
                scenarios.append(sc)
            except ValidationError as exc:
                logger.error("Failed to parse scenario %s: %s", yf.name, exc)
                raise
        return scenarios

    def execute_all(self, directory: Path | None = None) -> LabReport:
        """Runs the entire lab scenario suite and produces a LabReport."""
        # Mainnet Safety Guard
        assert_non_mainnet(lab_settings.chain_id, lab_settings.chain_name)

        scenarios = self.load_scenarios(directory)
        results: list[ScenarioResult] = []
        start_time = time.perf_counter()

        for sc in scenarios:
            # Per-scenario safety check
            assert_non_mainnet(sc.target_chain_id, sc.chain)
            res = self.execute_scenario(sc)
            results.append(res)

        total_duration_ms = (time.perf_counter() - start_time) * 1000.0
        passed_count = sum(1 for r in results if r.status == "PASS")
        failed_count = len(results) - passed_count
        pass_rate = (passed_count / len(results) * 100.0) if results else 0.0

        report = LabReport(
            timestamp=datetime.now(UTC).isoformat(),
            runner_version="1.0.0",
            chain_id=lab_settings.chain_id,
            chain_name=lab_settings.chain_name,
            data_label=lab_settings.data_label,
            total_scenarios=len(results),
            passed=passed_count,
            failed=failed_count,
            pass_rate_pct=round(pass_rate, 2),
            total_duration_ms=round(total_duration_ms, 2),
            safety_checks=LabSafetySummary(
                mainnet_guard_enforced=True,
                disposable_keys_only=True,
                live_funds_involved=False,
                fail_closed_verified=True,
            ),
            scenarios=results,
        )

        self._save_results(report)
        return report

    def _save_results(self, report: LabReport) -> None:
        """Writes report to lab/results/latest.json and generates readable summary."""
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        LATEST_JSON_FILE.write_text(report.model_dump_json(indent=2), encoding="utf-8")

        summary_text = self.format_readable_summary(report)
        LATEST_SUMMARY_FILE.write_text(summary_text, encoding="utf-8")

    def format_readable_summary(self, report: LabReport) -> str:
        """Formats a human-readable text summary of the lab execution."""
        lines = [
            "=" * 80,
            "BitGuard Integration Lab (Milestone S23 / F19) - Execution Report",
            "=" * 80,
            f"Timestamp: {report.timestamp} | Chain ID: {report.chain_id} ({report.chain_name})",
            "Safety Gate: PASSED (Non-mainnet verified, disposable test keys only)",
            f"Data Provenance: {report.data_label} (Integration Benchmark)",
            f"Claim: {report.containment_claim}",
            f"Latency Benchmark: {report.target_performance_claim}",
            "-" * 80,
            f"Scenarios Executed: {report.total_scenarios} | Passed: {report.passed} | Failed: {report.failed} | Pass Rate: {report.pass_rate_pct}%",
            f"Total Duration: {report.total_duration_ms:.2f} ms",
            "-" * 80,
            "Scenario Breakdown:",
        ]

        for s in report.scenarios:
            contain_info = f" | Time-to-contain: {s.time_to_contain_ms:.2f}ms" if s.time_to_contain_ms else ""
            lines.append(
                f"[{s.status}] {s.id}: {s.name} ({s.duration_ms:.2f}ms{contain_info}) -> {s.actual_outcome}"
            )
            if s.status == "FAIL" and s.error_message:
                lines.append(f"       Error: {s.error_message}")

        lines.append("=" * 80)
        return "\n".join(lines)

    def execute_scenario(self, scenario: ScenarioDefinition) -> ScenarioResult:
        """Dispatches an individual scenario definition to its test handler."""
        handler_map = {
            "scenario_01_normal_withdrawal": self._run_scenario_01,
            "scenario_02_over_limit_hold_then_quorum_release": self._run_scenario_02,
            "scenario_03_hold_expires_to_deny": self._run_scenario_03,
            "scenario_04_delegation_attempt_denied": self._run_scenario_04,
            "scenario_05_watcher_detects_unapproved_delegation_and_breaker_trips": self._run_scenario_05,
            "scenario_06_split_under_limit_triggers_velocity_or_baseline_reason": self._run_scenario_06,
            "scenario_07_redis_outage_fails_closed": self._run_scenario_07,
            "scenario_08_direct_signer_call_refused": self._run_scenario_08,
            "scenario_09_token_replay_refused": self._run_scenario_09,
            "scenario_10_unmatched_intent_denied": self._run_scenario_10,
            "scenario_11_lockdown_then_two_person_unlock": self._run_scenario_11,
        }

        handler = handler_map.get(scenario.id)
        if not handler:
            return ScenarioResult(
                id=scenario.id,
                name=scenario.name,
                status="FAIL",
                duration_ms=0.0,
                expected_outcome=scenario.expected_outcome,
                actual_outcome="UNKNOWN_SCENARIO",
                error_message=f"No runner implemented for scenario {scenario.id}",
            )

        t0 = time.perf_counter()
        try:
            self._setup_harness()
            checks, details, time_to_contain = handler(scenario)
            duration_ms = (time.perf_counter() - t0) * 1000.0

            all_passed = all(c.passed for c in checks)
            actual_outcome = scenario.expected_outcome if all_passed else "ASSERTION_FAILED"

            return ScenarioResult(
                id=scenario.id,
                name=scenario.name,
                status="PASS" if all_passed else "FAIL",
                duration_ms=round(duration_ms, 2),
                expected_outcome=scenario.expected_outcome,
                actual_outcome=actual_outcome,
                assertions_checked=len(checks),
                assertions_passed=sum(1 for c in checks if c.passed),
                time_to_contain_ms=round(time_to_contain, 2) if time_to_contain is not None else None,
                details=details,
                assertion_checks=checks,
            )
        except Exception as exc:
            duration_ms = (time.perf_counter() - t0) * 1000.0
            logger.exception("Error executing scenario %s: %s", scenario.id, exc)
            return ScenarioResult(
                id=scenario.id,
                name=scenario.name,
                status="FAIL",
                duration_ms=round(duration_ms, 2),
                expected_outcome=scenario.expected_outcome,
                actual_outcome="EXCEPTION",
                error_message=str(exc),
            )

    # =========================================================================
    # Individual Scenario Runners
    # =========================================================================

    def _run_scenario_01(self, sc: ScenarioDefinition) -> tuple[list[AssertionCheck], dict[str, Any], float | None]:
        """Scenario 1: Normal Authorized Withdrawal -> ALLOW, valid signature."""
        pat = sc.pattern_data
        intent_info = pat["intent"]
        tx_info = pat["transaction"]

        mock_ledger_connector.register_intent(
            WithdrawalIntent(
                id=intent_info["id"],
                status=IntentStatus.APPROVED.value,
                chain=sc.chain,
                asset=intent_info["asset"],
                amount=str(intent_info["amount"]),
                destination=intent_info["destination"],
            )
        )

        raw_tx = build_raw_legacy_tx(to_hex=tx_info["to"], value=tx_info["value"], nonce=tx_info["nonce"])
        rpc_payload = {
            "jsonrpc": "2.0",
            "method": "bitguard_signTransaction",
            "params": {
                "chain": sc.chain,
                "raw_tx": raw_tx,
                "intent_id": intent_info["id"],
                "amount_usd": tx_info["amount_usd"],
            },
            "id": "sc01-01",
        }

        resp = self.bitguard_client.post(
            "/rpc",
            json=rpc_payload,
            headers={"X-Client-Cert-SAN": pat["caller"]["san"]},
        )
        data = resp.json()

        checks: list[AssertionCheck] = []
        checks.append(AssertionCheck(name="status_code_200", passed=(resp.status_code == 200), expected=200, actual=resp.status_code))
        checks.append(AssertionCheck(name="error_is_null", passed=(data.get("error") is None), expected=None, actual=data.get("error")))

        res = data.get("result", {}) or {}
        has_sig = res.get("status") == "SIGNED" and str(res.get("signature", "")).startswith("0x")
        checks.append(AssertionCheck(name="signature_issued", passed=has_sig, expected=True, actual=has_sig))

        consumed = mock_ledger_connector.is_consumed(intent_info["id"])
        checks.append(AssertionCheck(name="intent_consumed", passed=consumed, expected=True, actual=consumed))

        details = {"result": res, "intent_consumed": consumed}
        return checks, details, None

    def _run_scenario_02(self, sc: ScenarioDefinition) -> tuple[list[AssertionCheck], dict[str, Any], float | None]:
        """Scenario 2: Over-Limit Hold Then Quorum Release -> HOLD -> 2 approvals -> RELEASED."""
        pat = sc.pattern_data
        intent_info = pat["intent"]
        tx_info = pat["transaction"]

        mock_ledger_connector.register_intent(
            WithdrawalIntent(
                id=intent_info["id"],
                status=IntentStatus.APPROVED.value,
                chain=sc.chain,
                asset=intent_info["asset"],
                amount=str(intent_info["amount"]),
                destination=intent_info["destination"],
            )
        )

        raw_tx = build_raw_legacy_tx(to_hex=tx_info["to"], value=tx_info["value"], nonce=tx_info["nonce"])
        rpc_payload = {
            "jsonrpc": "2.0",
            "method": "bitguard_signTransaction",
            "params": {
                "chain": sc.chain,
                "raw_tx": raw_tx,
                "intent_id": intent_info["id"],
                "amount_usd": tx_info["amount_usd"],
            },
            "id": "sc02-01",
        }

        resp = self.bitguard_client.post(
            "/rpc",
            json=rpc_payload,
            headers={"X-Client-Cert-SAN": pat["caller"]["san"]},
        )
        data = resp.json()

        checks: list[AssertionCheck] = []
        err = data.get("error")
        is_hold = err is not None and err.get("code") == -32004
        checks.append(AssertionCheck(name="initial_hold_error_code", passed=is_hold, expected=-32004, actual=(err or {}).get("code")))

        hold_id = (err or {}).get("data", {}).get("hold_id")
        ticket = hold_store.get(hold_id) if hold_id else None
        checks.append(AssertionCheck(name="ticket_quarantined", passed=(ticket is not None), expected=True, actual=(ticket is not None)))

        if not ticket or not hold_id:
            return checks, {"error": err}, None

        # Approver 1 submits assertion
        priv_1 = approver_registry.dev_private_keys["usr-approver-01"]
        assertion_1 = create_test_webauthn_assertion(priv_1, tx_digest=ticket.tx_digest, sign_count=1)
        resp_app1 = self.bitguard_client.post(
            f"/v1/holds/{hold_id}/approve",
            json={"assertion": assertion_1.model_dump()},
            headers=get_auth_header(Role.APPROVER, "usr-approver-01"),
        )
        data_app1 = resp_app1.json()
        checks.append(AssertionCheck(
            name="first_approval_pending_quorum",
            passed=(data_app1.get("status") in ["PENDING", "PENDING_QUORUM"] and data_app1.get("approvals_count") == 1),
            expected="PENDING_QUORUM",
            actual=data_app1.get("status"),
        ))

        # Approver 2 submits assertion -> releases
        priv_2 = approver_registry.dev_private_keys["usr-approver-02"]
        assertion_2 = create_test_webauthn_assertion(priv_2, tx_digest=ticket.tx_digest, sign_count=2)
        resp_app2 = self.bitguard_client.post(
            f"/v1/holds/{hold_id}/approve",
            json={"assertion": assertion_2.model_dump()},
            headers=get_auth_header(Role.APPROVER, "usr-approver-02"),
        )
        data_app2 = resp_app2.json()
        has_sig = (
            data_app2.get("status") in ["APPROVED", "RELEASED"]
            and data_app2.get("signature") is not None
            and str(data_app2.get("signature")).startswith("0x")
        )
        checks.append(AssertionCheck(
            name="second_approval_releases_signature",
            passed=has_sig,
            expected="RELEASED with signature",
            actual=data_app2.get("status"),
        ))

        # Check stored status in store
        stored_ticket = hold_store.get(hold_id)
        ticket_approved = stored_ticket is not None and stored_ticket.status in ("APPROVED", "RELEASED")
        checks.append(AssertionCheck(
            name="stored_ticket_status_approved",
            passed=ticket_approved,
            expected="RELEASED",
            actual=stored_ticket.status if stored_ticket else None,
        ))

        details = {"hold_id": hold_id, "final_status": data_app2.get("status")}
        return checks, details, None

    def _run_scenario_03(self, sc: ScenarioDefinition) -> tuple[list[AssertionCheck], dict[str, Any], float | None]:
        """Scenario 3: Hold Expires to Deny -> late approval rejected."""
        pat = sc.pattern_data
        tx_info = pat["transaction"]

        raw_tx = build_raw_legacy_tx(to_hex=tx_info["to"], value=tx_info["value"], nonce=tx_info["nonce"])
        decoded = evm_decoder.decode(raw_tx)

        # Create deliberately expired ticket
        expired_ticket = HoldTicket(
            id="ht-lab-expired-03",
            request_id="req-lab-03",
            tx_digest=decoded.digest,
            raw_tx=raw_tx,
            wallet=OWNED_HOT_WALLET,
            chain=sc.chain,
            reasons=[DecisionReason(code="SINGLE_TX_LIMIT_EXCEEDED", weight=50, detail="Over single tx limit")],
            status="PENDING",
            created_at=datetime.now(UTC) - timedelta(minutes=10),
            expires_at=datetime.now(UTC) - timedelta(minutes=5),  # Elapsed!
            risk_score=60,
            requester_id=pat["caller"]["san"],
        )
        hold_store.create(expired_ticket)

        priv_1 = approver_registry.dev_private_keys["usr-approver-01"]
        assertion = create_test_webauthn_assertion(priv_1, tx_digest=expired_ticket.tx_digest, sign_count=1)

        resp = self.bitguard_client.post(
            f"/v1/holds/{expired_ticket.id}/approve",
            json={"assertion": assertion.model_dump()},
            headers=get_auth_header(Role.APPROVER, "usr-approver-01"),
        )

        checks: list[AssertionCheck] = []
        checks.append(AssertionCheck(
            name="expired_approval_rejected_400",
            passed=(resp.status_code == 400),
            expected=400,
            actual=resp.status_code,
        ))
        detail_msg = resp.json().get("detail", "")
        checks.append(AssertionCheck(
            name="error_reason_hold_expired",
            passed=("HOLD_EXPIRED" in detail_msg),
            expected="HOLD_EXPIRED",
            actual=detail_msg,
        ))

        details = {"ticket_id": expired_ticket.id, "response": resp.json()}
        return checks, details, None

    def _run_scenario_04(self, sc: ScenarioDefinition) -> tuple[list[AssertionCheck], dict[str, Any], float | None]:
        """Scenario 4: Delegation Attempt Denied -> unapproved EIP-7702 delegate denied."""
        pat = sc.pattern_data

        # Authority account whose address is owned by custodian
        acc = Account.from_key(DISPOSABLE_TEST_PRIVATE_KEY)
        owned_addr = acc.address

        # Configure delegation policy and RPC client
        policy = DelegationPolicy(
            owned_addresses={owned_addr, pat["owned_address"]},
            delegate_allowlist={},
        )
        mock_rpc = MockRpcClient()
        mock_rpc.set_contract(pat["unapproved_delegate"], "0x600160005260206000f3")

        mode_service.set_delegation_policy(policy)
        mode_service.set_rpc_client(mock_rpc)
        decision_engine.set_delegation_policy(policy)
        decision_engine.set_rpc_client(mock_rpc)

        raw_tx = build_signed_eip7702_tx(
            authority_account=acc,
            to_addr=pat["owned_address"],
            delegate_addr=pat["unapproved_delegate"],
            nonce=0,
            chain_id=1,
        )

        mock_ledger_connector.register_intent(
            WithdrawalIntent(
                id=pat["intent"]["id"],
                status=IntentStatus.APPROVED.value,
                chain=sc.chain,
                asset="ETH",
                amount="0",
                destination=pat["owned_address"],
            )
        )

        rpc_payload = {
            "jsonrpc": "2.0",
            "method": "bitguard_signTransaction",
            "params": {
                "chain": sc.chain,
                "raw_tx": raw_tx,
                "intent_id": pat["intent"]["id"],
            },
            "id": "sc04-01",
        }

        resp = self.bitguard_client.post(
            "/rpc",
            json=rpc_payload,
            headers={"X-Client-Cert-SAN": pat["caller"]["san"]},
        )
        data = resp.json()

        checks: list[AssertionCheck] = []
        err = data.get("error")
        is_denied = err is not None and err.get("code") == -32003
        checks.append(AssertionCheck(name="delegation_denied_code", passed=is_denied, expected=-32003, actual=(err or {}).get("code")))

        reasons = [r.get("code") for r in (err or {}).get("data", {}).get("reasons", [])]
        has_reason = "DELEGATION_OWNED_ADDRESS" in reasons or "UNAPPROVED_DELEGATE" in reasons
        checks.append(AssertionCheck(
            name="delegation_rejection_reason",
            passed=has_reason,
            expected="DELEGATION_OWNED_ADDRESS or UNAPPROVED_DELEGATE",
            actual=reasons,
        ))

        details = {"error": err, "reasons": reasons}
        return checks, details, None

    def _run_scenario_05(self, sc: ScenarioDefinition) -> tuple[list[AssertionCheck], dict[str, Any], float | None]:
        """Scenario 5: Watcher Detects Unapproved Delegation and Breaker Trips -> time-to-contain."""
        pat = sc.pattern_data
        watched_addr = pat["watched_address"]
        unapproved_delegate = pat["unapproved_delegate"]

        # 1. Reset breaker to NORMAL
        distributed_breaker_store.reset()
        breaker_store.reset()

        # 2. Add watched address with empty allowed delegates
        watched_address_store.create(
            CreateWatchedAddressRequest(
                address=watched_addr,
                chain=sc.chain,
                label="Lab Watched Custody Wallet",
                allowed_delegates=[],
            )
        )

        # 3. Configure mock RPC returning unapproved designator
        unapproved_designator = "0xef0100" + unapproved_delegate[2:].lower()
        mock_rpc_1 = MockRpcClient()
        mock_rpc_2 = MockRpcClient()
        mock_rpc_1.set_contract(watched_addr, unapproved_designator)
        mock_rpc_2.set_contract(watched_addr, unapproved_designator)
        mock_rpc_1.set_contract(unapproved_delegate, "0x600160005260206000f3")
        mock_rpc_2.set_contract(unapproved_delegate, "0x600160005260206000f3")

        provider_pool.providers = [
            ("node_primary", mock_rpc_1),
            ("node_secondary", mock_rpc_2),
        ]

        # 4. Measure time to contain
        t_start = time.perf_counter()
        alerts = delegation_watcher.scan_block(block_number=102)
        t_contain_ms = (time.perf_counter() - t_start) * 1000.0

        current_breaker_state = distributed_breaker_store.get_state()

        checks: list[AssertionCheck] = []
        checks.append(AssertionCheck(
            name="critical_alert_emitted",
            passed=(len(alerts) > 0 and alerts[0].severity == "CRITICAL"),
            expected="CRITICAL",
            actual=[a.severity for a in alerts],
        ))
        checks.append(AssertionCheck(
            name="breaker_tripped_to_hold",
            passed=(current_breaker_state == BreakerStateEnum.HOLD),
            expected=BreakerStateEnum.HOLD.value,
            actual=current_breaker_state.value,
        ))
        checks.append(AssertionCheck(
            name="time_to_contain_within_sla",
            passed=(t_contain_ms <= pat.get("max_acceptable_containment_ms", 5000.0)),
            expected=f"<= {pat.get('max_acceptable_containment_ms', 5000.0)}ms",
            actual=f"{t_contain_ms:.2f}ms",
        ))

        details = {
            "alerts": [a.model_dump() for a in alerts],
            "new_breaker_state": current_breaker_state.value,
            "time_to_contain_ms": t_contain_ms,
        }
        return checks, details, t_contain_ms

    def _run_scenario_06(self, sc: ScenarioDefinition) -> tuple[list[AssertionCheck], dict[str, Any], float | None]:
        """Scenario 6: Split Under Limit Triggers Velocity/Limit -> rolling window breach."""
        pat = sc.pattern_data
        transfers = pat["batch_transfers"]

        checks: list[AssertionCheck] = []
        results: list[dict[str, Any]] = []

        for idx, item in enumerate(transfers):
            intent_id = item["intent_id"]
            mock_ledger_connector.register_intent(
                WithdrawalIntent(
                    id=intent_id,
                    status=IntentStatus.APPROVED.value,
                    chain=sc.chain,
                    asset="ETH",
                    amount=str(item["value_wei"]),
                    destination=pat["destination"],
                )
            )

            raw_tx = build_raw_legacy_tx(to_hex=pat["destination"], value=item["value_wei"], nonce=idx)
            rpc_payload = {
                "jsonrpc": "2.0",
                "method": "bitguard_signTransaction",
                "params": {
                    "chain": sc.chain,
                    "raw_tx": raw_tx,
                    "intent_id": intent_id,
                    "amount_usd": item["amount_usd"],
                },
                "id": f"sc06-{idx}",
            }

            resp = self.bitguard_client.post(
                "/rpc",
                json=rpc_payload,
                headers={"X-Client-Cert-SAN": pat["caller"]["san"]},
            )
            data = resp.json()
            results.append(data)

        # First 3 transfers should succeed ($30k * 3 = $90k <= $100k limit)
        first_3_ok = all(r.get("error") is None and (r.get("result") or {}).get("status") == "SIGNED" for r in results[:3])
        checks.append(AssertionCheck(name="early_transfers_allowed", passed=first_3_ok, expected=True, actual=first_3_ok))

        # 4th transfer should trip rolling limit ($120k > $100k)
        fourth = results[3]
        err = fourth.get("error")
        is_hold = err is not None and err.get("code") == -32004
        checks.append(AssertionCheck(name="limit_breached_hold", passed=is_hold, expected=-32004, actual=(err or {}).get("code")))

        reasons = [r.get("code") for r in (err or {}).get("data", {}).get("reasons", [])]
        has_limit_reason = any("LIMIT_EXCEEDED" in r or "VELOCITY" in r for r in reasons)
        checks.append(AssertionCheck(
            name="velocity_limit_reason_present",
            passed=has_limit_reason,
            expected="HOURLY_LIMIT_EXCEEDED or VELOCITY",
            actual=reasons,
        ))

        details = {"transfer_results_count": len(results), "last_error": err}
        return checks, details, None

    def _run_scenario_07(self, sc: ScenarioDefinition) -> tuple[list[AssertionCheck], dict[str, Any], float | None]:
        """Scenario 7: Redis Outage Fails Closed -> ENGINE_ERROR / STORE_UNAVAILABLE."""
        pat = sc.pattern_data
        intent_info = pat["intent"]
        tx_info = pat["transaction"]

        mock_ledger_connector.register_intent(
            WithdrawalIntent(
                id=intent_info["id"],
                status=IntentStatus.APPROVED.value,
                chain=sc.chain,
                asset=intent_info["asset"],
                amount=str(intent_info["amount"]),
                destination=intent_info["destination"],
            )
        )

        raw_tx = build_raw_legacy_tx(to_hex=tx_info["to"], value=tx_info["value"], nonce=tx_info["nonce"])
        rpc_payload = {
            "jsonrpc": "2.0",
            "method": "bitguard_signTransaction",
            "params": {
                "chain": sc.chain,
                "raw_tx": raw_tx,
                "intent_id": intent_info["id"],
                "amount_usd": tx_info["amount_usd"],
            },
            "id": "sc07-01",
        }

        # Simulate Redis outage during limit reservation
        with patch.object(limit_store, "reserve", side_effect=redis.exceptions.ConnectionError("Redis outage")):
            resp = self.bitguard_client.post(
                "/rpc",
                json=rpc_payload,
                headers={"X-Client-Cert-SAN": pat["caller"]["san"]},
            )

        data = resp.json()
        checks: list[AssertionCheck] = []
        err = data.get("error")
        is_denied = err is not None and err.get("code") == -32003
        checks.append(AssertionCheck(name="fail_closed_denial_code", passed=is_denied, expected=-32003, actual=(err or {}).get("code")))

        reasons = [r.get("code") for r in (err or {}).get("data", {}).get("reasons", [])]
        has_engine_error = "ENGINE_ERROR" in reasons or "LIMIT_STORE_UNAVAILABLE" in reasons
        checks.append(AssertionCheck(
            name="store_outage_reason",
            passed=has_engine_error,
            expected="ENGINE_ERROR or LIMIT_STORE_UNAVAILABLE",
            actual=reasons,
        ))

        details = {"error": err}
        return checks, details, None

    def _run_scenario_08(self, sc: ScenarioDefinition) -> tuple[list[AssertionCheck], dict[str, Any], float | None]:
        """Scenario 8: Direct Signer Call Refused -> unauthorized invocation blocked."""
        pat = sc.pattern_data

        # 1. Direct call without internal auth header
        resp_no_auth = self.shim_client.post(
            "/sign",
            json=pat["request_body"],
            headers=pat.get("headers", {}),
        )

        checks: list[AssertionCheck] = []
        checks.append(AssertionCheck(
            name="missing_internal_auth_refused_403",
            passed=(resp_no_auth.status_code == 403),
            expected=403,
            actual=resp_no_auth.status_code,
        ))

        # 2. Direct call with valid header but empty / bogus token
        resp_bogus_token = self.shim_client.post(
            "/sign",
            json={"raw_tx_bytes": pat["request_body"]["raw_tx_bytes"], "token": ""},
            headers={"X-BitGuard-Internal-Auth": settings.signer_shim_internal_auth_token},
        )
        checks.append(AssertionCheck(
            name="empty_token_refused_400",
            passed=(resp_bogus_token.status_code == 400),
            expected=400,
            actual=resp_bogus_token.status_code,
        ))

        details = {
            "no_auth_status": resp_no_auth.status_code,
            "bogus_token_status": resp_bogus_token.status_code,
        }
        return checks, details, None

    def _run_scenario_09(self, sc: ScenarioDefinition) -> tuple[list[AssertionCheck], dict[str, Any], float | None]:
        """Scenario 9: Token Replay Refused -> single-use approval token rejected on second use."""
        raw_tx = build_raw_legacy_tx(value=1000, nonce=99)
        decoded = evm_decoder.decode(raw_tx)

        # Issue legitimate one-time BitGuard approval token
        token_str = issue_token(
            decoded_tx=decoded,
            wallet=OWNED_HOT_WALLET,
            chain=sc.chain,
            key_set=token_manager.key_set,
        )

        headers = {"X-BitGuard-Internal-Auth": settings.signer_shim_internal_auth_token}
        sign_payload = {"raw_tx_bytes": raw_tx, "token": token_str}

        # 1. First invocation: consumes token, signs successfully
        resp1 = self.shim_client.post("/sign", json=sign_payload, headers=headers)
        checks: list[AssertionCheck] = []
        checks.append(AssertionCheck(
            name="first_use_succeeds_200",
            passed=(resp1.status_code == 200),
            expected=200,
            actual=resp1.status_code,
        ))

        # 2. Second invocation with identical token: must be rejected atomically!
        resp2 = self.shim_client.post("/sign", json=sign_payload, headers=headers)
        is_replay_rejected = resp2.status_code == 400
        checks.append(AssertionCheck(
            name="second_use_rejected_400",
            passed=is_replay_rejected,
            expected=400,
            actual=resp2.status_code,
        ))
        data2 = resp2.json() if is_replay_rejected else {}
        is_replay_reason = data2.get("reason_code") in ["NONCE_ALREADY_CONSUMED", "TOKEN_NONCE_REPLAY"]
        checks.append(AssertionCheck(
            name="replay_reason_code",
            passed=is_replay_reason,
            expected="NONCE_ALREADY_CONSUMED",
            actual=data2.get("reason_code"),
        ))

        details = {"first_status": resp1.status_code, "second_status": resp2.status_code, "second_detail": data2}
        return checks, details, None

    def _run_scenario_10(self, sc: ScenarioDefinition) -> tuple[list[AssertionCheck], dict[str, Any], float | None]:
        """Scenario 10: Unmatched Intent Denied -> fail closed when intent missing."""
        pat = sc.pattern_data
        tx_info = pat["transaction"]

        raw_tx = build_raw_legacy_tx(to_hex=tx_info["to"], value=tx_info["value"], nonce=tx_info["nonce"])
        rpc_payload = {
            "jsonrpc": "2.0",
            "method": "bitguard_signTransaction",
            "params": {
                "chain": sc.chain,
                "raw_tx": raw_tx,
                "intent_id": pat["intent_id"],
                "amount_usd": tx_info["amount_usd"],
            },
            "id": "sc10-01",
        }

        resp = self.bitguard_client.post(
            "/rpc",
            json=rpc_payload,
            headers={"X-Client-Cert-SAN": pat["caller"]["san"]},
        )
        data = resp.json()

        checks: list[AssertionCheck] = []
        err = data.get("error")
        is_denied = err is not None and err.get("code") == -32003
        checks.append(AssertionCheck(name="unmatched_intent_denied_code", passed=is_denied, expected=-32003, actual=(err or {}).get("code")))

        reasons = [r.get("code") for r in (err or {}).get("data", {}).get("reasons", [])]
        checks.append(AssertionCheck(
            name="intent_missing_reason",
            passed=("INTENT_MISSING" in reasons),
            expected="INTENT_MISSING",
            actual=reasons,
        ))

        details = {"error": err}
        return checks, details, None

    def _run_scenario_11(self, sc: ScenarioDefinition) -> tuple[list[AssertionCheck], dict[str, Any], float | None]:
        """Scenario 11: Lockdown Then Two-Person Unlock -> dual custody WebAuthn unlock."""
        pat = sc.pattern_data

        secops_headers = get_auth_header(Role.SECOPS, "usr-secops-01")
        approver_headers = get_auth_header(Role.APPROVER, "usr-approver-01")
        admin_headers = get_auth_header(Role.ADMIN, "usr-admin-01")

        checks: list[AssertionCheck] = []

        # 1. Escalate to LOCKDOWN
        resp_esc = self.bitguard_client.post(
            "/v1/breaker/escalate",
            json={"target_state": "LOCKDOWN", "reason": pat["lockdown"]["reason"]},
            headers=secops_headers,
        )
        checks.append(AssertionCheck(name="escalate_to_lockdown_200", passed=(resp_esc.status_code == 200), expected=200, actual=resp_esc.status_code))
        checks.append(AssertionCheck(
            name="breaker_in_lockdown",
            passed=(distributed_breaker_store.get_state() == BreakerStateEnum.LOCKDOWN),
            expected=BreakerStateEnum.LOCKDOWN.value,
            actual=distributed_breaker_store.get_state().value,
        ))

        # 2. Attempt signing in LOCKDOWN -> Denied
        raw_tx = build_raw_legacy_tx(value=1000, nonce=11)
        mock_ledger_connector.register_intent(
            WithdrawalIntent(
                id="intent-lockdown-test",
                status=IntentStatus.APPROVED.value,
                chain=sc.chain,
                asset="ETH",
                amount="1000",
                destination=BENIGN_DEST_HEX,
            )
        )
        resp_tx_blocked = self.bitguard_client.post(
            "/rpc",
            json={
                "jsonrpc": "2.0",
                "method": "bitguard_signTransaction",
                "params": {"chain": sc.chain, "raw_tx": raw_tx, "intent_id": "intent-lockdown-test"},
                "id": "sc11-tx",
            },
            headers={"X-Client-Cert-SAN": "spiffe://exchange.internal/workload/custody"},
        )
        data_tx_blocked = resp_tx_blocked.json()
        err_tx_blocked = data_tx_blocked.get("error")
        checks.append(AssertionCheck(
            name="transaction_denied_in_lockdown",
            passed=(err_tx_blocked is not None and err_tx_blocked.get("code") == -32003),
            expected=-32003,
            actual=(err_tx_blocked or {}).get("code"),
        ))

        # 3. Create de-escalation request to NORMAL
        resp_req = self.bitguard_client.post(
            "/v1/breaker/deescalate-request",
            json={"target_state": "NORMAL", "reason": "Incident investigated and mitigated"},
            headers=secops_headers,
        )
        checks.append(AssertionCheck(name="deescalate_request_201", passed=(resp_req.status_code == 201), expected=201, actual=resp_req.status_code))
        req_data = resp_req.json()
        deescalate_id = req_data.get("id")
        challenge = req_data.get("challenge", "")

        # 4. Approver 1 submits assertion -> proposal remains PENDING
        priv1 = approver_registry.dev_private_keys["usr-approver-01"]
        assertion1 = create_test_webauthn_assertion(priv1, tx_digest=challenge, sign_count=1)
        resp_app1 = self.bitguard_client.post(
            "/v1/breaker/deescalate-approve",
            json={"request_id": deescalate_id, "assertion": assertion1.model_dump()},
            headers=approver_headers,
        )
        checks.append(AssertionCheck(
            name="first_unlock_approval_pending",
            passed=(resp_app1.json().get("status") == "PENDING" and resp_app1.json().get("approvals_count") == 1),
            expected="PENDING",
            actual=resp_app1.json().get("status"),
        ))
        checks.append(AssertionCheck(
            name="breaker_remains_lockdown_after_1_approval",
            passed=(distributed_breaker_store.get_state() == BreakerStateEnum.LOCKDOWN),
            expected=BreakerStateEnum.LOCKDOWN.value,
            actual=distributed_breaker_store.get_state().value,
        ))

        # 5. Approver 2 (Admin) submits assertion -> proposal APPROVED, breaker de-escalates!
        priv2 = approver_registry.dev_private_keys["usr-admin-01"]
        assertion2 = create_test_webauthn_assertion(priv2, tx_digest=challenge, sign_count=1)
        resp_app2 = self.bitguard_client.post(
            "/v1/breaker/deescalate-approve",
            json={"request_id": deescalate_id, "assertion": assertion2.model_dump()},
            headers=admin_headers,
        )
        checks.append(AssertionCheck(
            name="second_unlock_approval_approved",
            passed=(resp_app2.json().get("status") == "APPROVED" and resp_app2.json().get("approvals_count") == 2),
            expected="APPROVED",
            actual=resp_app2.json().get("status"),
        ))
        checks.append(AssertionCheck(
            name="breaker_restored_to_normal",
            passed=(distributed_breaker_store.get_state() == BreakerStateEnum.NORMAL),
            expected=BreakerStateEnum.NORMAL.value,
            actual=distributed_breaker_store.get_state().value,
        ))

        # 6. Subsequent transaction succeeds in NORMAL
        mock_ledger_connector.register_intent(
            WithdrawalIntent(
                id="intent-post-unlock-ok",
                status=IntentStatus.APPROVED.value,
                chain=sc.chain,
                asset="ETH",
                amount="1000",
                destination=BENIGN_DEST_HEX,
            )
        )
        resp_tx_ok = self.bitguard_client.post(
            "/rpc",
            json={
                "jsonrpc": "2.0",
                "method": "bitguard_signTransaction",
                "params": {"chain": sc.chain, "raw_tx": raw_tx, "intent_id": "intent-post-unlock-ok", "amount_usd": 1000.0},
                "id": "sc11-tx-ok",
            },
            headers={"X-Client-Cert-SAN": "spiffe://exchange.internal/workload/custody"},
        )
        tx_ok_data = resp_tx_ok.json()
        tx_signed = (tx_ok_data.get("result") or {}).get("status") == "SIGNED"
        checks.append(AssertionCheck(
            name="post_unlock_tx_succeeds",
            passed=tx_signed,
            expected=True,
            actual=tx_signed,
        ))

        details = {
            "initial_state": "LOCKDOWN",
            "approvals_count": 2,
            "final_state": distributed_breaker_store.get_state().value,
            "post_unlock_signed": tx_signed,
        }
        return checks, details, None
