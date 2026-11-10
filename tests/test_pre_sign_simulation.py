"""Comprehensive test suite for Task S28 - Pre-Sign Transaction Simulation (F5).

Invariants Verified:
- Invariant #1: Cached lookups on the async path; never on hot path.
- Invariant #3: Fail-Closed Default. Mismatch holds; timeout adds risk weight, never 'safe'.
- Invariant #9: Environment & Safety Boundary. Local chains with disposable test keys ONLY.
"""

import time
from datetime import UTC, datetime

import pytest
import rlp

from services.bitguard.decoders.evm import CallItem, DecodedTx
from services.bitguard.engine.pipeline import DecisionEngine
from services.bitguard.engine.types import DecisionEngineConfig
from services.bitguard.ledger.mock import mock_ledger_connector
from services.bitguard.ledger.models import IntentStatus, LedgerIntent
from services.bitguard.models import OperationMode, SigningRequest, Verdict
from services.bitguard.rpc.client import MockRpcClient
from services.bitguard.simulation.anvil import (
    TOPIC_ERC20_TRANSFER,
    AnvilForkSimulator,
)
from services.bitguard.simulation.enricher import CachedSimulationEnricher
from services.bitguard.simulation.models import SimulationFlag

HOT_WALLET = "0x742d35cc6634c0532925a3b844bc454e4438f44e"
BENIGN_DEST = "0x1111111111111111111111111111111111111111"
USDC_TOKEN = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
DAI_TOKEN = "0x6b175474e89094c44da98b954eedeac495271d0f"


def build_raw_legacy_tx(to_addr: str, value_wei: int = 0, data: bytes = b"") -> str:
    """Builds valid RLP-encoded raw EVM legacy transaction."""
    clean = to_addr.removeprefix("0x")
    to_bytes = bytes.fromhex(clean)
    payload = [0, 20_000_000_000, 21000, to_bytes, value_wei, data]
    return "0x" + rlp.encode(payload).hex()


@pytest.fixture
def simulation_fixture():
    """Provides isolated mock RPC, Anvil simulator, and cached enricher."""
    mock_ledger_connector.reset()
    mock_rpc = MockRpcClient()
    mock_rpc.set_latest_block(100)
    mock_rpc.set_balance(HOT_WALLET, 10 * 10**18)

    simulator = AnvilForkSimulator(rpc_client=mock_rpc, ttl_seconds=3600)
    enricher = CachedSimulationEnricher(simulator=simulator)

    return {
        "mock_rpc": mock_rpc,
        "simulator": simulator,
        "enricher": enricher,
    }


def test_erc20_transfer_matches_intent_clean(simulation_fixture):
    """Verifies that a benign ERC-20 transfer matching intent simulates cleanly without mismatch."""
    simulator: AnvilForkSimulator = simulation_fixture["simulator"]
    enricher: CachedSimulationEnricher = simulation_fixture["enricher"]

    intent = LedgerIntent(
        id="intent-sim-001",
        chain="ethereum",
        destination=BENIGN_DEST,
        asset="USDC",
        amount="1000000",  # 1 USDC (6 decimals)
        status=IntentStatus.APPROVED.value,
        created_at=datetime.now(UTC),
    )
    mock_ledger_connector.register_intent(intent)

    decoded_tx = DecodedTx(
        chain="ethereum",
        from_address=HOT_WALLET,
        to_address=USDC_TOKEN,
        asset="USDC",
        amount="1000000",
        digest="0x" + "1" * 64,
        calls=[
            CallItem(
                to=USDC_TOKEN,
                call_type="ERC20_TRANSFER",
                recipient=BENIGN_DEST,
                amount="1000000",
                selector="0xa9059cbb",
            )
        ],
    )

    res = simulator.simulate(
        decoded_tx=decoded_tx,
        raw_tx=build_raw_legacy_tx(USDC_TOKEN),
        intent=intent,
    )

    assert res.success is True
    assert res.reverted is False
    assert res.risk_weight == 0
    assert SimulationFlag.SIM_BALANCE_MISMATCH not in res.flags
    assert len(res.balance_deltas) >= 2

    # Verify deltas
    hot_delta = next(d for d in res.balance_deltas if d.address.lower() == HOT_WALLET.lower())
    dest_delta = next(d for d in res.balance_deltas if d.address.lower() == BENIGN_DEST.lower())
    assert hot_delta.delta == -1_000_000
    assert dest_delta.delta == 1_000_000

    # Engine evaluate path returns clean ALLOW
    engine = DecisionEngine(simulation=enricher)
    req = SigningRequest(
        chain="ethereum",
        wallet=HOT_WALLET,
        intent_id="intent-sim-001",
        raw_tx=build_raw_legacy_tx(USDC_TOKEN),
        metadata={
            "enable_simulation": True,
            "decoded_tx": decoded_tx.model_dump(by_alias=True),
        },
    )
    decision = engine.evaluate(req)
    assert decision.verdict == Verdict.ALLOW
    assert not any("SIM_BALANCE_MISMATCH" in r.code for r in decision.reasons)


def test_test_contract_moves_second_token_flagged_mismatch_and_holds(simulation_fixture):
    """Verifies that an unexpected multi-token transfer (second token moved) triggers SIM_BALANCE_MISMATCH and HOLD."""
    simulator: AnvilForkSimulator = simulation_fixture["simulator"]
    mock_rpc: MockRpcClient = simulation_fixture["mock_rpc"]
    enricher: CachedSimulationEnricher = simulation_fixture["enricher"]

    # Intent expects 1,000,000 USDC only
    intent = LedgerIntent(
        id="intent-sim-002",
        chain="ethereum",
        destination=BENIGN_DEST,
        asset="USDC",
        amount="1000000",
        status=IntentStatus.APPROVED.value,
        created_at=datetime.now(UTC),
    )
    mock_ledger_connector.register_intent(intent)

    malicious_contract = "0x6666666666666666666666666666666666666666"

    # Simulate contract execution that emits TWO Transfer events:
    # 1. 1,000,000 USDC to BENIGN_DEST
    # 2. 50,000 DAI to an unauthorized third-party address (unexpected secondary token drain!)
    unauthorized_dest = "0x9999999999999999999999999999999999999999"

    topic_from = "0x" + "0" * 24 + HOT_WALLET.removeprefix("0x").lower()
    topic_dest = "0x" + "0" * 24 + BENIGN_DEST.removeprefix("0x").lower()
    topic_unauth = "0x" + "0" * 24 + unauthorized_dest.removeprefix("0x").lower()

    simulated_logs = [
        # Transfer 1: USDC
        {
            "address": USDC_TOKEN,
            "topics": [TOPIC_ERC20_TRANSFER, topic_from, topic_dest],
            "data": hex(1_000_000),
        },
        # Transfer 2: DAI (Second token moved!)
        {
            "address": DAI_TOKEN,
            "topics": [TOPIC_ERC20_TRANSFER, topic_from, topic_unauth],
            "data": hex(50_000 * 10**18),
        },
    ]

    mock_rpc.set_call_handler("eth_call", lambda params: {"result": "0x", "logs": simulated_logs})

    decoded_tx = DecodedTx(
        chain="ethereum",
        from_address=HOT_WALLET,
        to_address=malicious_contract,
        asset="USDC",
        amount="1000000",
        digest="0x" + "2" * 64,
        calls=[
            CallItem(
                to=malicious_contract,
                call_type="ERC20_TRANSFER",
                recipient=BENIGN_DEST,
                amount="1000000",
                selector="0xa9059cbb",
            )
        ],
    )

    # Simulator runs on fork, parses logs, detects multi-token move
    res = simulator.simulate(
        decoded_tx=decoded_tx,
        raw_tx=build_raw_legacy_tx(malicious_contract),
        intent=intent,
        watched_addresses=[HOT_WALLET],
    )

    assert SimulationFlag.SIM_BALANCE_MISMATCH in res.flags
    assert res.risk_weight >= 75
    assert res.success is False

    # Now verify decision engine puts transaction into HOLD
    engine = DecisionEngine(
        config=DecisionEngineConfig(hold_risk_threshold=50),
        simulation=enricher,
    )
    req = SigningRequest(
        chain="ethereum",
        wallet=HOT_WALLET,
        intent_id="intent-sim-002",
        raw_tx=build_raw_legacy_tx(malicious_contract),
        mode=OperationMode.ENFORCE,
        metadata={
            "enable_simulation": True,
            "decoded_tx": decoded_tx.model_dump(by_alias=True),
        },
    )

    decision = engine.evaluate(req)

    # Requirement: HOLD when mismatch is detected
    assert decision.verdict == Verdict.HOLD
    assert any(r.code == "SIM_BALANCE_MISMATCH" for r in decision.reasons)


def test_reverting_call_flagged_sim_revert(simulation_fixture):
    """Verifies that an execution revert is flagged with SIM_REVERT and elevates risk."""
    simulator: AnvilForkSimulator = simulation_fixture["simulator"]
    mock_rpc: MockRpcClient = simulation_fixture["mock_rpc"]
    enricher: CachedSimulationEnricher = simulation_fixture["enricher"]

    # Configure RPC to raise an execution revert
    mock_rpc.set_call_handler("eth_call", lambda params: (_ for _ in ()).throw(Exception("execution reverted: TransferFailed()")))

    decoded_tx = DecodedTx(
        chain="ethereum",
        from_address=HOT_WALLET,
        to_address=BENIGN_DEST,
        asset="ETH",
        amount="1000",
        digest="0x" + "3" * 64,
    )

    res = simulator.simulate(
        decoded_tx=decoded_tx,
        raw_tx=build_raw_legacy_tx(BENIGN_DEST),
    )

    assert res.reverted is True
    assert SimulationFlag.SIM_REVERT in res.flags
    assert res.risk_weight >= 60

    # Decision engine integration
    engine = DecisionEngine(simulation=enricher)
    req = SigningRequest(
        chain="ethereum",
        wallet=HOT_WALLET,
        raw_tx=build_raw_legacy_tx(BENIGN_DEST),
        metadata={
            "enable_simulation": True,
            "decoded_tx": decoded_tx.model_dump(by_alias=True),
        },
    )
    decision = engine.evaluate(req)
    assert any(r.code == "SIM_REVERT" for r in decision.reasons)
    assert decision.risk_score >= 60


def test_unlimited_approval_flagged(simulation_fixture):
    """Verifies that an unlimited approval call (value >= 2^96) is flagged with SIM_UNLIMITED_APPROVAL."""
    simulator: AnvilForkSimulator = simulation_fixture["simulator"]

    unlimited_val = str(2**256 - 1)
    decoded_tx = DecodedTx(
        chain="ethereum",
        from_address=HOT_WALLET,
        to_address=USDC_TOKEN,
        asset="USDC",
        amount="0",
        digest="0x" + "4" * 64,
        calls=[
            CallItem(
                to=USDC_TOKEN,
                call_type="ERC20_APPROVE",
                recipient=BENIGN_DEST,
                amount=unlimited_val,
                is_unlimited_approval=True,
                selector="0x095ea7b3",
            )
        ],
    )

    res = simulator.simulate(
        decoded_tx=decoded_tx,
        raw_tx=build_raw_legacy_tx(USDC_TOKEN),
    )

    assert SimulationFlag.SIM_UNLIMITED_APPROVAL in res.flags
    assert res.risk_weight >= 50


def test_timeout_path_adds_risk_never_safe(simulation_fixture):
    """Invariant #3: Timeout on async simulation path adds ELEVATED_RISK_TIMEOUT, never treated as safe."""
    simulator: AnvilForkSimulator = simulation_fixture["simulator"]
    mock_rpc: MockRpcClient = simulation_fixture["mock_rpc"]

    # Simulate slow RPC that blocks longer than the 30 ms deadline
    def slow_call(params):
        time.sleep(0.1)
        return "0x"

    mock_rpc.set_call_handler("eth_call", slow_call)

    decoded_tx = DecodedTx(
        chain="ethereum",
        from_address=HOT_WALLET,
        to_address=BENIGN_DEST,
        asset="ETH",
        amount="1000",
        digest="0x" + "5" * 64,
    )

    res = simulator.simulate(
        decoded_tx=decoded_tx,
        raw_tx=build_raw_legacy_tx(BENIGN_DEST),
        timeout_ms=30.0,  # 30 ms deadline triggers timeout
    )

    assert res.timed_out is True
    assert SimulationFlag.SIM_TIMEOUT in res.flags
    assert res.risk_weight == 30  # Elevated risk weight applied


def test_cache_by_digest_and_block_number(simulation_fixture):
    """Verifies that simulation results are cached by digest and block number."""
    simulator: AnvilForkSimulator = simulation_fixture["simulator"]
    mock_rpc: MockRpcClient = simulation_fixture["mock_rpc"]

    mock_rpc.set_latest_block(500)

    decoded_tx = DecodedTx(
        chain="ethereum",
        from_address=HOT_WALLET,
        to_address=BENIGN_DEST,
        asset="ETH",
        amount="1000",
        digest="0x" + "6" * 64,
    )

    # First call: cache miss
    res1 = simulator.simulate(
        decoded_tx=decoded_tx,
        raw_tx=build_raw_legacy_tx(BENIGN_DEST, value_wei=1000),
    )
    assert res1.cached is False

    # Second call on same block height: cache hit!
    res2 = simulator.simulate(
        decoded_tx=decoded_tx,
        raw_tx=build_raw_legacy_tx(BENIGN_DEST, value_wei=1000),
    )
    assert res2.cached is True

    # Third call on a new block height: cache miss!
    mock_rpc.set_latest_block(501)
    res3 = simulator.simulate(
        decoded_tx=decoded_tx,
        raw_tx=build_raw_legacy_tx(BENIGN_DEST, value_wei=1000),
    )
    assert res3.cached is False
