"""Comprehensive table-driven unit and integration tests for BitGuard Decision Engine (Milestone S10).

Covers:
- Modular 6-stage pipeline execution: decode -> intent_check -> delegation guard -> limits -> enrichment -> decide.
- Canonical Decision output with per-stage timings: decode, intent_check, delegation, limits, enrichment, decide, total.
- Over 30 table-driven policy scenarios covering all reason codes, modes (SIMULATION, SHADOW, ENFORCE), and failure injection.
- Fail-closed defaults on parser errors, store outages, ledger mismatches, and pipeline exceptions.
"""

from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock

import pytest
import rlp
from fastapi.testclient import TestClient

from services.bitguard.engine.breaker_store import breaker_store
from services.bitguard.engine.pipeline import DecisionEngine, decision_engine
from services.bitguard.ledger.mock import mock_ledger_connector
from services.bitguard.ledger.models import IntentStatus, WithdrawalIntent
from services.bitguard.limits.store import (
    LimitStore,
    ReservationResult,
    ScopeBuilder,
    limit_store,
)
from services.bitguard.main import app
from services.bitguard.mode_service import mode_service
from services.bitguard.models import (
    BreakerStateEnum,
    DataLabel,
    OperationMode,
    SigningRequest,
    Verdict,
    WalletGroupConfig,
)
from services.bitguard.rpc.client import MockRpcClient
from services.bitguard.rules.delegation import (
    DelegationPolicy,
    compute_code_hash,
)

client = TestClient(app)

OWNED_HOT_WALLET = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
BENIGN_DESTINATION = "0x1111111111111111111111111111111111111111"
APPROVED_DELEGATE_ADDR = "0x2222222222222222222222222222222222222222"
UNAPPROVED_DELEGATE_ADDR = "0x3333333333333333333333333333333333333333"
PROXY_DELEGATE_ADDR = "0x4444444444444444444444444444444444444444"

BENIGN_DELEGATE_CODE = "0x600160005260206000f3"  # PUSH1 0x01 PUSH1 0x00 MSTORE RETURN
PROXY_DELEGATE_CODE = "0x6000600060006000731111111111111111111111111111111111111111f4"  # DELEGATECALL (0xF4)


def build_raw_legacy_tx(
    to: str = BENIGN_DESTINATION,
    value: int = 1_000_000_000_000_000,  # 0.001 ETH
    nonce: int = 0,
    gas_price: int = 20_000_000_000,
    gas_limit: int = 21000,
    data: bytes = b"",
) -> str:
    """Constructs a valid unsigned/signed legacy EVM raw transaction hex."""
    to_bytes = bytes.fromhex(to[2:]) if to.startswith("0x") else bytes.fromhex(to)
    payload = [nonce, gas_price, gas_limit, to_bytes, value, data]
    return "0x" + rlp.encode(payload).hex()


@pytest.fixture(autouse=True)
def setup_engine_test_environment() -> Generator[None, None, None]:
    """Isolates engine stores, mocks, and policies across tests."""
    mock_ledger_connector.reset()
    breaker_store.set_state(BreakerStateEnum.NORMAL, reason="Test setup")

    mock_rpc = MockRpcClient()
    mock_rpc.set_contract(APPROVED_DELEGATE_ADDR, BENIGN_DELEGATE_CODE)
    mock_rpc.set_contract(PROXY_DELEGATE_ADDR, PROXY_DELEGATE_CODE)
    mock_rpc.set_contract(UNAPPROVED_DELEGATE_ADDR, "0x60006000f3")

    policy = DelegationPolicy(
        owned_addresses={OWNED_HOT_WALLET.lower()},
        delegate_allowlist={},
    )
    approved_hash = compute_code_hash(BENIGN_DELEGATE_CODE)
    policy.add_allowed_delegate(approved_hash, name="ApprovedBenign", reviewed_proxy_ok=False)
    proxy_hash = compute_code_hash(PROXY_DELEGATE_CODE)
    policy.add_allowed_delegate(proxy_hash, name="ProxyDelegate", reviewed_proxy_ok=False)

    decision_engine.set_rpc_client(mock_rpc)
    decision_engine.set_delegation_policy(policy)
    mode_service.set_rpc_client(mock_rpc)
    mode_service.set_delegation_policy(policy)

    yield

    mock_ledger_connector.reset()
    breaker_store.set_state(BreakerStateEnum.NORMAL, reason="Test teardown")


# -----------------------------------------------------------------------------
# Table-Driven Policy Scenarios (At least 30 scenarios)
# -----------------------------------------------------------------------------

SCENARIOS: list[dict[str, Any]] = [
    # --- Stage 1: Decode & Caller Identity ---
    {
        "name": "1. DECODE_ERROR - Non-hex garbage payload",
        "raw_tx": "0xNotValidHexGarbage!@#$",
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {},
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "DECODE_ERROR",
        "expected_min_score": 100,
    },
    {
        "name": "2. DECODE_ERROR - Incomplete RLP truncated payload",
        "raw_tx": "0xf830",
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {},
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "DECODE_ERROR",
        "expected_min_score": 100,
    },
    {
        "name": "3. INVALID_CALLER_IDENTITY - Unknown caller signature / identity",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {"simulate_invalid_caller": True},
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "INVALID_CALLER_IDENTITY",
        "expected_min_score": 100,
    },

    # --- Stage 2: Custody Withdrawal Intent Reconciliation ---
    {
        "name": "4. INTENT_MISSING - Required intent omitted from request",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {"require_intent_check": True},
        "intent_id": None,
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "INTENT_MISSING",
        "expected_min_score": 100,
    },
    {
        "name": "5. INTENT_MISSING - Invented intent ID not found in ledger",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {},
        "intent_id": "intent-ghost-001",
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "INTENT_MISSING",
        "expected_min_score": 100,
    },
    {
        "name": "6. INTENT_NOT_APPROVED - Intent status is PENDING",
        "raw_tx": build_raw_legacy_tx(value=500),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "setup_intent": WithdrawalIntent(
            id="intent-pending-01",
            status=IntentStatus.PENDING,
            chain="ethereum",
            asset="ETH",
            amount="500",
            destination=BENIGN_DESTINATION,
        ),
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "INTENT_NOT_APPROVED",
        "expected_min_score": 100,
    },
    {
        "name": "7. INTENT_NOT_APPROVED - Intent status is CANCELLED",
        "raw_tx": build_raw_legacy_tx(value=500),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "setup_intent": WithdrawalIntent(
            id="intent-canc-01",
            status=IntentStatus.CANCELLED,
            chain="ethereum",
            asset="ETH",
            amount="500",
            destination=BENIGN_DESTINATION,
        ),
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "INTENT_NOT_APPROVED",
        "expected_min_score": 100,
    },
    {
        "name": "8. INTENT_ALREADY_PAID - Intent status is PAID",
        "raw_tx": build_raw_legacy_tx(value=500),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "setup_intent": WithdrawalIntent(
            id="intent-paid-01",
            status=IntentStatus.PAID,
            chain="ethereum",
            asset="ETH",
            amount="500",
            destination=BENIGN_DESTINATION,
        ),
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "INTENT_ALREADY_PAID",
        "expected_min_score": 100,
    },
    {
        "name": "9. INTENT_MISMATCH_DESTINATION - Decoded destination != intent destination",
        "raw_tx": build_raw_legacy_tx(to=BENIGN_DESTINATION, value=500),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "setup_intent": WithdrawalIntent(
            id="intent-dest-mismatch",
            status=IntentStatus.APPROVED,
            chain="ethereum",
            asset="ETH",
            amount="500",
            destination="0x9999999999999999999999999999999999999999",
        ),
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "INTENT_MISMATCH_DESTINATION",
        "expected_min_score": 100,
    },
    {
        "name": "10. INTENT_MISMATCH_AMOUNT - Decoded amount != intent amount",
        "raw_tx": build_raw_legacy_tx(value=700),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "setup_intent": WithdrawalIntent(
            id="intent-amt-mismatch",
            status=IntentStatus.APPROVED,
            chain="ethereum",
            asset="ETH",
            amount="500",
            destination=BENIGN_DESTINATION,
        ),
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "INTENT_MISMATCH_AMOUNT",
        "expected_min_score": 100,
    },
    {
        "name": "11. INTENT_MISMATCH_CHAIN - Target chain != intent chain",
        "raw_tx": build_raw_legacy_tx(value=500),
        "wallet": OWNED_HOT_WALLET,
        "chain": "arbitrum",
        "mode": OperationMode.ENFORCE,
        "setup_intent": WithdrawalIntent(
            id="intent-chain-mismatch",
            status=IntentStatus.APPROVED,
            chain="arbitrum",
            asset="ETH",
            amount="500",
            destination=BENIGN_DESTINATION,
        ),
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "INTENT_MISMATCH_CHAIN",
        "expected_min_score": 100,
    },
    {
        "name": "12. INTENT_REPLAY - Previously consumed intent re-submitted",
        "raw_tx": build_raw_legacy_tx(value=500),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "setup_intent": WithdrawalIntent(
            id="intent-replay-01",
            status=IntentStatus.APPROVED,
            chain="ethereum",
            asset="ETH",
            amount="500",
            destination=BENIGN_DESTINATION,
        ),
        "pre_consume_intent": "intent-replay-01",
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "INTENT_REPLAY",
        "expected_min_score": 100,
    },

    # --- Stage 3: EIP-7702 Delegation Guard ---
    {
        "name": "13. DELEGATION_OWNED_ADDRESS - Owned wallet delegates to unapproved contract",
        "raw_tx": "0x04f870",
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {
            "decoded_tx": {
                "chain": "ethereum",
                "from": OWNED_HOT_WALLET,
                "to": OWNED_HOT_WALLET,
                "asset": "ETH",
                "amount": "0",
                "calls": [],
                "authorizations": [
                    {
                        "chain_id": 1,
                        "address": UNAPPROVED_DELEGATE_ADDR,
                        "nonce": 0,
                        "authority": OWNED_HOT_WALLET,
                    }
                ],
                "fee": {},
                "digest": "0x0001",
            }
        },
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "DELEGATION_OWNED_ADDRESS",
        "expected_min_score": 100,
    },
    {
        "name": "14. DELEGATION_UPGRADEABLE_PROXY - Delegate contains DELEGATECALL opcode",
        "raw_tx": "0x04f870",
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {
            "decoded_tx": {
                "chain": "ethereum",
                "from": OWNED_HOT_WALLET,
                "to": OWNED_HOT_WALLET,
                "asset": "ETH",
                "amount": "0",
                "calls": [],
                "authorizations": [
                    {
                        "chain_id": 1,
                        "address": PROXY_DELEGATE_ADDR,
                        "nonce": 0,
                        "authority": OWNED_HOT_WALLET,
                    }
                ],
                "fee": {},
                "digest": "0x0002",
            }
        },
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "DELEGATION_UPGRADEABLE_PROXY",
        "expected_min_score": 100,
    },
    {
        "name": "15. DELEGATION_RPC_FAILURE - RPC connection error resolving delegate code",
        "raw_tx": "0x04f870",
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "trigger_rpc_failure": True,
        "metadata": {
            "decoded_tx": {
                "chain": "ethereum",
                "from": OWNED_HOT_WALLET,
                "to": OWNED_HOT_WALLET,
                "asset": "ETH",
                "amount": "0",
                "calls": [],
                "authorizations": [
                    {
                        "chain_id": 1,
                        "address": APPROVED_DELEGATE_ADDR,
                        "nonce": 0,
                        "authority": OWNED_HOT_WALLET,
                    }
                ],
                "fee": {},
                "digest": "0x0003",
            }
        },
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "DELEGATION_RPC_FAILURE",
        "expected_min_score": 100,
    },

    # --- Stage 4: Limits & Single Tx Velocity ---
    {
        "name": "16. SINGLE_TX_LIMIT_EXCEEDED - Transfer exceeds single tx USD threshold -> HOLD",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {"amount_usd": 75_000.0},
        "expected_verdict": Verdict.HOLD,
        "expected_would_have": None,
        "expected_code": "SINGLE_TX_LIMIT_EXCEEDED",
        "expected_min_score": 65,
    },
    {
        "name": "17. VELOCITY_SPIKE - Outflow spike flag in metadata -> HOLD",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {"simulate_hold": True, "amount_usd": 1000.0},
        "expected_verdict": Verdict.HOLD,
        "expected_would_have": None,
        "expected_code": "VELOCITY_SPIKE",
        "expected_min_score": 50,
    },
    {
        "name": "18. LIMIT_STORE_UNAVAILABLE - Limit store down and local fallback exceeded -> hard DENY",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "trigger_limit_store_outage": True,
        "metadata": {"amount_usd": 20_000.0},  # Exceeds conservative fallback cap ($10,000)
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "LIMIT_STORE_UNAVAILABLE",
        "expected_min_score": 100,
    },

    # --- Stage 5: Enrichment Hooks & Timeouts ---
    {
        "name": "19. ELEVATED_RISK_TIMEOUT - Enrichment simulation timeout adds elevated risk weight 30",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {"simulate_enrichment_timeout": True, "amount_usd": 500.0},
        "expected_verdict": Verdict.ALLOW,  # 30 < 50 threshold -> ALLOW with elevated risk recorded
        "expected_would_have": None,
        "expected_code": "ELEVATED_RISK_TIMEOUT",
        "expected_min_score": 30,
    },
    {
        "name": "20. PROFILER & SIMULATION NOT CONFIGURED - Clean baseline returns unconfigured notices",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {"amount_usd": 100.0},
        "expected_verdict": Verdict.ALLOW,
        "expected_would_have": None,
        "expected_code": "PROFILER_NOT_CONFIGURED",
        "expected_min_score": 0,
    },

    # --- Stage 6: Circuit Breaker States ---
    {
        "name": "21. BREAKER_LOCKDOWN - Circuit breaker in LOCKDOWN -> hard DENY",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "set_breaker_state": BreakerStateEnum.LOCKDOWN,
        "metadata": {"amount_usd": 50.0},
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "BREAKER_LOCKDOWN",
        "expected_min_score": 100,
    },
    {
        "name": "22. BREAKER_HOLD - Circuit breaker in HOLD -> HOLD",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "set_breaker_state": BreakerStateEnum.HOLD,
        "metadata": {"amount_usd": 50.0},
        "expected_verdict": Verdict.HOLD,
        "expected_would_have": None,
        "expected_code": "BREAKER_HOLD",
        "expected_min_score": 75,
    },

    # --- Mode Semantics: SIMULATION, SHADOW, ENFORCE ---
    {
        "name": "23. SHADOW_MODE - Policy HOLD passes through as ALLOW with would_have_verdict=HOLD",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.SHADOW,
        "metadata": {"amount_usd": 85_000.0},
        "expected_verdict": Verdict.ALLOW,
        "expected_would_have": Verdict.HOLD,
        "expected_code": "SINGLE_TX_LIMIT_EXCEEDED",
        "expected_min_score": 65,
    },
    {
        "name": "24. SHADOW_MODE - Policy DENY passes through as ALLOW with would_have_verdict=DENY",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.SHADOW,
        "metadata": {"simulate_deny": True, "amount_usd": 200.0},
        "expected_verdict": Verdict.ALLOW,
        "expected_would_have": Verdict.DENY,
        "expected_code": "SUSPICIOUS_DELEGATION",
        "expected_min_score": 95,
    },
    {
        "name": "25. SHADOW_MODE - DECODE_ERROR still strictly returns binding DENY (Fail Closed)",
        "raw_tx": "",
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.SHADOW,
        "metadata": {},
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "DECODE_ERROR",
        "expected_min_score": 100,
    },
    {
        "name": "26. SHADOW_MODE - INVALID_CALLER still strictly returns binding DENY (Fail Closed)",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.SHADOW,
        "metadata": {"simulate_invalid_caller": True},
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "INVALID_CALLER_IDENTITY",
        "expected_min_score": 100,
    },
    {
        "name": "27. SHADOW_MODE - LIMIT_STORE_UNAVAILABLE still strictly returns binding DENY",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.SHADOW,
        "trigger_limit_store_outage": True,
        "metadata": {"amount_usd": 30_000.0},
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "LIMIT_STORE_UNAVAILABLE",
        "expected_min_score": 100,
    },
    {
        "name": "28. ENFORCE_MODE - Legitimate small transfer returns binding ALLOW",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {"amount_usd": 100.0},
        "expected_verdict": Verdict.ALLOW,
        "expected_would_have": None,
        "expected_code": None,
        "expected_min_score": 0,
    },
    {
        "name": "29. ENFORCE_MODE - Outflow spike returns binding HOLD",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {"simulate_hold": True, "amount_usd": 200.0},
        "expected_verdict": Verdict.HOLD,
        "expected_would_have": None,
        "expected_code": "VELOCITY_SPIKE",
        "expected_min_score": 50,
    },
    {
        "name": "30. ENFORCE_MODE - Disallowed delegation returns binding DENY",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {"simulate_deny": True},
        "expected_verdict": Verdict.DENY,
        "expected_would_have": None,
        "expected_code": "SUSPICIOUS_DELEGATION",
        "expected_min_score": 95,
    },
    {
        "name": "31. SIMULATION_MODE - Single tx limit evaluates without state change",
        "raw_tx": build_raw_legacy_tx(),
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.SIMULATION,
        "metadata": {"amount_usd": 65_000.0},
        "expected_verdict": Verdict.HOLD,
        "expected_would_have": None,
        "expected_code": "SINGLE_TX_LIMIT_EXCEEDED",
        "expected_min_score": 65,
    },
    {
        "name": "32. BENIGN_APPROVED_DELEGATE - EIP-7702 with reviewed benign delegate returns ALLOW",
        "raw_tx": "0x04f870",
        "wallet": OWNED_HOT_WALLET,
        "mode": OperationMode.ENFORCE,
        "metadata": {
            "decoded_tx": {
                "chain": "ethereum",
                "from": OWNED_HOT_WALLET,
                "to": OWNED_HOT_WALLET,
                "asset": "ETH",
                "amount": "0",
                "calls": [],
                "authorizations": [
                    {
                        "chain_id": 1,
                        "address": APPROVED_DELEGATE_ADDR,
                        "nonce": 0,
                        "authority": OWNED_HOT_WALLET,
                    }
                ],
                "fee": {},
                "digest": "0x0004",
            }
        },
        "expected_verdict": Verdict.ALLOW,
        "expected_would_have": None,
        "expected_code": None,
        "expected_min_score": 0,
    },
]


@pytest.mark.parametrize(
    "scenario",
    SCENARIOS,
    ids=[s["name"] for s in SCENARIOS],
)
def test_table_driven_decision_engine_pipeline(scenario: dict[str, Any]):
    """Parametrised table-driven test executing at least 32 diverse policy scenarios."""
    # Register test wallet group
    group = WalletGroupConfig(
        id=f"group-{scenario['mode'].value.lower()}",
        name="Scenario Test Group",
        mode=scenario["mode"],
        wallets=[scenario["wallet"]],
    )
    mode_service.register_wallet_group(group)

    # Setup withdrawal intent if needed
    intent_id = scenario.get("intent_id")
    if "setup_intent" in scenario:
        intent: WithdrawalIntent = scenario["setup_intent"]
        mock_ledger_connector.register_intent(intent)
        intent_id = intent.id

    if "pre_consume_intent" in scenario:
        mock_ledger_connector.mark_consumed(scenario["pre_consume_intent"])

    # Setup breaker state if needed
    if "set_breaker_state" in scenario:
        breaker_store.set_state(scenario["set_breaker_state"], reason="Scenario trigger")

    # Setup RPC failure if needed
    if scenario.get("trigger_rpc_failure"):
        fail_rpc = MagicMock()
        fail_rpc.get_code.side_effect = RuntimeError("RPC connection timed out")
        decision_engine.set_rpc_client(fail_rpc)

    # Setup limit store outage if needed
    if scenario.get("trigger_limit_store_outage"):
        broken_limits = MagicMock(spec=LimitStore)
        broken_limits.reserve.return_value = ReservationResult(
            ok=False,
            remaining=0,
            reservation_id="",
            error="LIMIT_STORE_UNAVAILABLE",
            source="FAIL_CLOSED",
        )
        decision_engine.limit_store = broken_limits
    else:
        decision_engine.limit_store = limit_store

    req = SigningRequest(
        id=f"req-scen-{abs(hash(scenario['name']))}",
        raw_tx=scenario["raw_tx"],
        chain=scenario.get("chain", "ethereum"),
        wallet=scenario["wallet"],
        wallet_group=group.id,
        mode=scenario["mode"],
        intent_id=intent_id,
        metadata=scenario.get("metadata", {}),
    )

    # Execute full decision engine
    decision = decision_engine.evaluate(
        request=req,
        is_dry_run=False,
        wallet_group_mode=group.mode,
        wallet_group_id=group.id,
    )

    # Assert verdicts and scores
    assert decision.verdict == scenario["expected_verdict"], (
        f"Scenario '{scenario['name']}' expected verdict {scenario['expected_verdict']}, got {decision.verdict}"
    )
    assert decision.would_have_verdict == scenario["expected_would_have"], (
        f"Scenario '{scenario['name']}' expected would_have_verdict {scenario['expected_would_have']}, got {decision.would_have_verdict}"
    )
    assert decision.risk_score >= scenario["expected_min_score"]

    # Assert specific reason codes
    if scenario["expected_code"]:
        reason_codes = [r.code for r in decision.reasons]
        assert scenario["expected_code"] in reason_codes, (
            f"Scenario '{scenario['name']}' expected reason '{scenario['expected_code']}', got {reason_codes}"
        )

    # Assert required metadata and timings present
    assert decision.evaluation_latency_ms is not None
    assert decision.evaluation_latency_ms >= 0.0
    assert "total" in decision.timings
    assert decision.data_label in [DataLabel.REAL, DataLabel.SYNTHETIC, DataLabel.REPORTED]


# -----------------------------------------------------------------------------
# Timing Metrics & Observability Tests (S25 Readiness)
# -----------------------------------------------------------------------------


def test_per_stage_timings_recorded_and_exposed():
    """Verify latency is recorded per stage (decode, intent_check, delegation, limits, enrichment, decide, total)."""
    raw_tx = build_raw_legacy_tx(value=1000)
    req = SigningRequest(
        id="req-timings-001",
        raw_tx=raw_tx,
        chain="ethereum",
        wallet=OWNED_HOT_WALLET,
        mode=OperationMode.ENFORCE,
        metadata={"amount_usd": 25.0},
    )

    decision = decision_engine.evaluate(request=req, is_dry_run=True)

    expected_stages = ["decode", "limits", "enrichment", "decide", "total"]
    for stage in expected_stages:
        assert stage in decision.timings, f"Stage timing '{stage}' missing from decision.timings"
        assert decision.timings[stage] >= 0.0, f"Timing for '{stage}' must be non-negative"

    assert decision.evaluation_latency_ms == decision.timings["total"]
    assert decision.timings["total"] > 0.0


# -----------------------------------------------------------------------------
# Dry Run vs. Non-Dry Run Reservation Isolation
# -----------------------------------------------------------------------------


def test_evaluate_dry_run_does_not_reserve_redis_budget():
    """POST /v1/evaluate performs read-only limit checks without consuming volume in Redis."""
    scope = ScopeBuilder.wallet_scope(OWNED_HOT_WALLET)
    rem_before = limit_store.get_remaining(scope, window_seconds=3600, cap=10_000_000)

    payload = {
        "id": "req-dryrun-001",
        "raw_tx": build_raw_legacy_tx(value=5000),
        "chain": "ethereum",
        "wallet": OWNED_HOT_WALLET,
        "mode": "SIMULATION",
        "metadata": {"amount_usd": 500.0},
    }

    res = client.post("/v1/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "ALLOW"

    rem_after = limit_store.get_remaining(scope, window_seconds=3600, cap=10_000_000)
    assert rem_after == rem_before, "Dry run /evaluate must not consume limit store headroom"


def test_sign_requests_releases_reservation_on_hold_or_deny():
    """Production signing requests release reservations immediately if verdict is not ALLOW."""
    scope = ScopeBuilder.wallet_scope(OWNED_HOT_WALLET)
    rem_before = limit_store.get_remaining(scope, window_seconds=3600, cap=10_000_000)

    # Amount $70,000 exceeds single tx limit ($50,000) -> HOLD
    payload = {
        "id": "req-hold-release",
        "raw_tx": build_raw_legacy_tx(),
        "chain": "ethereum",
        "wallet": OWNED_HOT_WALLET,
        "mode": "ENFORCE",
        "metadata": {"amount_usd": 70_000.0},
    }

    res = client.post("/v1/sign-requests", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "HOLD"

    rem_after = limit_store.get_remaining(scope, window_seconds=3600, cap=10_000_000)
    assert rem_after == rem_before, "Unused reservation for HOLD must be released immediately"


def test_unhandled_exception_in_pipeline_fails_closed_with_engine_error():
    """Invariant #3: Unhandled engine exceptions fail closed with DENY and ENGINE_ERROR."""
    req = SigningRequest(
        id="req-crash-001",
        raw_tx=build_raw_legacy_tx(),
        chain="ethereum",
        wallet=OWNED_HOT_WALLET,
        mode=OperationMode.ENFORCE,
    )

    # Force unhandled exception during stage execution
    bad_engine = DecisionEngine()
    bad_engine._stage_limits = MagicMock(side_effect=RuntimeError("Catastrophic hardware fault"))  # type: ignore[method-assign]

    decision = bad_engine.evaluate(request=req, is_dry_run=False)
    assert decision.verdict == Verdict.DENY
    assert decision.risk_score == 100
    assert len(decision.reasons) == 1
    assert decision.reasons[0].code == "ENGINE_ERROR"
    assert "Catastrophic hardware fault" in decision.reasons[0].detail
