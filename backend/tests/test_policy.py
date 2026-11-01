import pytest
from fastapi.testclient import TestClient

from backend.app.models import SigningRequest, Decision
from backend.app.core.policy import PolicyEngine
from backend.app.core.breaker import Breaker
from backend.app.core.delegation import DelegationGuard
from backend.app.main import app, create_app


def test_legitimate_small_transfers_pass():
    """1. Legitimate small transfers below limits pass (action == 'allow')."""
    engine = PolicyEngine(
        wallet_limit_usd=100_000.0,
        global_limit_usd=500_000.0,
        single_tx_usd=50_000.0,
        new_recipient_usd=10_000.0,
    )
    req = SigningRequest(
        id="req-small-1",
        ts=1700000000.0,
        chain="ethereum",
        wallet="0xHotWallet1",
        kind="transfer",
        asset="ETH",
        amount_usd=2500.0,
        to="0xRecipient1",
    )
    decision = engine.evaluate(req)

    assert decision.action == "allow"
    assert decision.risk == 0
    assert decision.breaker_state == "Normal"
    assert len(decision.reasons) == 0

    # Ensure transaction was recorded into the rolling window
    assert engine.get_wallet_rolling_sum("0xHotWallet1", 1700000000.0) == 2500.0
    assert engine.get_global_rolling_sum(1700000000.0) == 2500.0


def test_single_transfer_exceeding_single_tx_usd_held():
    """2. Single transfer exceeding single_tx_usd gets held (action == 'hold')."""
    engine = PolicyEngine(
        single_tx_usd=50_000.0,
        wallet_limit_usd=200_000.0,
    )
    req = SigningRequest(
        id="req-big-tx",
        ts=1700000000.0,
        chain="ethereum",
        wallet="0xHotWallet1",
        kind="transfer",
        asset="USDC",
        amount_usd=60_000.0,
        to="0xRecipient1",
    )
    decision = engine.evaluate(req)

    assert decision.action == "hold"
    assert any(r["rule"] == "single_tx_limit" for r in decision.reasons)
    # Critical rule: held request does NOT increment sum
    assert engine.get_wallet_rolling_sum("0xHotWallet1", 1700000000.0) == 0.0


def test_outflow_velocity_wallet_or_global_limit_triggers_hold():
    """3. Outflow velocity hitting wallet_limit_usd or global_limit_usd triggers a hold/deny."""
    engine = PolicyEngine(
        wallet_limit_usd=100_000.0,
        global_limit_usd=200_000.0,
        single_tx_usd=50_000.0,
        new_recipient_usd=50_000.0,
    )

    # 1st tx for $45,000 -> allowed
    req1 = SigningRequest(
        id="req-w1",
        ts=1700000000.0,
        chain="ethereum",
        wallet="0xHotWallet1",
        kind="transfer",
        asset="USDC",
        amount_usd=45_000.0,
        to="0xRecipient1",
    )
    d1 = engine.evaluate(req1)
    assert d1.action == "allow"
    assert engine.get_wallet_rolling_sum("0xHotWallet1", 1700000000.0) == 45_000.0

    # 2nd tx for $45,000 -> allowed (wallet sum reaches 90,000)
    req2 = SigningRequest(
        id="req-w2",
        ts=1700000100.0,
        chain="ethereum",
        wallet="0xHotWallet1",
        kind="transfer",
        asset="USDC",
        amount_usd=45_000.0,
        to="0xRecipient2",
    )
    d2 = engine.evaluate(req2)
    assert d2.action == "allow"
    assert engine.get_wallet_rolling_sum("0xHotWallet1", 1700000100.0) == 90_000.0

    # 3rd tx for $20,000 -> wallet limit hit ($90k + $20k = $110k > $100k)
    req3 = SigningRequest(
        id="req-w3",
        ts=1700000200.0,
        chain="ethereum",
        wallet="0xHotWallet1",
        kind="transfer",
        asset="USDC",
        amount_usd=20_000.0,
        to="0xRecipient3",
    )
    d3 = engine.evaluate(req3)
    assert d3.action in ("hold", "deny")
    assert any(r["rule"] == "wallet_limit" for r in d3.reasons)

    # Critical rule verification: held request did NOT increment sum
    assert engine.get_wallet_rolling_sum("0xHotWallet1", 1700000200.0) == 90_000.0

    # Test Global multi-chain limit:
    # Another wallet on another chain
    req_other_chain = SigningRequest(
        id="req-g1",
        ts=1700000300.0,
        chain="arbitrum",
        wallet="0xHotWallet2",
        kind="transfer",
        asset="USDT",
        amount_usd=45_000.0,
        to="0xRecipient4",
    )
    d_g1 = engine.evaluate(req_other_chain)
    assert d_g1.action == "allow"
    # Current global sum = 90k + 45k = 135k

    req_other_chain2 = SigningRequest(
        id="req-g2",
        ts=1700000400.0,
        chain="arbitrum",
        wallet="0xHotWallet2",
        kind="transfer",
        asset="USDT",
        amount_usd=45_000.0,
        to="0xRecipient5",
    )
    d_g2 = engine.evaluate(req_other_chain2)
    assert d_g2.action == "allow"
    # Current global sum = 135k + 45k = 180k

    # This tx of $30k hits global limit ($180k + $30k = $210k > $200k global_limit_usd)
    req_global_overflow = SigningRequest(
        id="req-g-overflow",
        ts=1700000500.0,
        chain="polygon",
        wallet="0xHotWallet3",
        kind="transfer",
        asset="USDC",
        amount_usd=30_000.0,
        to="0xRecipient6",
    )
    d_global = engine.evaluate(req_global_overflow)
    assert d_global.action in ("hold", "deny")
    assert any(r["rule"] == "global_limit" for r in d_global.reasons)
    # Global sum unchanged
    assert engine.get_global_rolling_sum(1700000500.0) == 180_000.0


def test_authorization_7702_unapproved_delegate_denied_immediately():
    """4. An authorization_7702 request with an unapproved delegate is denied immediately (action == 'deny', risk == 100)."""
    engine = PolicyEngine()
    engine.delegation_guard.add_delegate("0xApprovedDelegateContract")

    # Unapproved delegate
    req_unapproved = SigningRequest(
        id="req-7702-unauth",
        ts=1700000000.0,
        chain="ethereum",
        wallet="0xHotWallet1",
        kind="authorization_7702",
        asset="ETH",
        amount_usd=0.0,
        delegate="0xMaliciousAttackerContract",
    )
    decision = engine.evaluate(req_unapproved)

    assert decision.action == "deny"
    assert decision.risk == 100
    assert decision.breaker_state == "Lockdown"
    assert any(r["rule"] == "7702_unauthorized_delegate" for r in decision.reasons)
    assert engine.breaker.is_locked_down()

    # Reset breaker to test approved delegate
    engine.breaker.reset()
    req_approved = SigningRequest(
        id="req-7702-auth",
        ts=1700000010.0,
        chain="ethereum",
        wallet="0xHotWallet1",
        kind="authorization_7702",
        asset="ETH",
        amount_usd=0.0,
        delegate="0xApprovedDelegateContract",
    )
    decision_ok = engine.evaluate(req_approved)
    assert decision_ok.action == "allow"
    assert decision_ok.risk == 0
    assert decision_ok.breaker_state == "Normal"


def test_batch_50_consecutive_nonces_trips_spray_and_forces_lockdown():
    """5. A batch of 50 consecutive nonces trips the spray detector and forces Lockdown."""
    engine = PolicyEngine()

    # Generate 50 consecutive nonce requests (nonces 0 to 49)
    requests = [
        SigningRequest(
            id=f"spray-req-{i}",
            ts=1700000000.0 + i,
            chain="ethereum",
            wallet="0xHotWallet1",
            kind="transfer",
            asset="ETH",
            amount_usd=10.0,
            to="0xRecipient",
            meta={"nonce": i},
        )
        for i in range(50)
    ]

    decisions = engine.replay(requests)

    # First 49 requests (nonces 0..48) should be allowed
    assert all(d.action == "allow" for d in decisions[:49])

    # The 50th consecutive nonce trips the spray detector and triggers Lockdown
    decision_50 = decisions[49]
    assert decision_50.action == "deny"
    assert decision_50.risk == 100
    assert decision_50.breaker_state == "Lockdown"
    assert any(r["rule"] == "nonce_spray_detected" for r in decision_50.reasons)
    assert engine.breaker.is_locked_down()

    # Subsequent transaction must be denied immediately due to Lockdown
    req_after = SigningRequest(
        id="req-blocked-by-lockdown",
        ts=1700000060.0,
        chain="ethereum",
        wallet="0xHotWallet1",
        kind="transfer",
        asset="ETH",
        amount_usd=10.0,
        to="0xRecipient",
        meta={"nonce": 50},
    )
    decision_after = engine.evaluate(req_after)
    assert decision_after.action == "deny"
    assert decision_after.breaker_state == "Lockdown"


def test_critical_rule_denied_requests_do_not_exhaust_limits():
    """
    Verify critical rule: ONLY allowed transactions increment rolling window sums.
    An attacker cannot spam denied or held transactions to exhaust exchange hot wallet limits.
    """
    engine = PolicyEngine(
        wallet_limit_usd=10_000.0,
        single_tx_usd=5_000.0,
    )

    # Spam 10 single-tx-exceeding requests
    for i in range(10):
        attacker_req = SigningRequest(
            id=f"attacker-{i}",
            ts=1700000000.0 + i,
            chain="ethereum",
            wallet="0xHotWallet1",
            kind="transfer",
            asset="USDC",
            amount_usd=60_000.0,  # Exceeds single tx limit
            to="0xAttacker",
        )
        d = engine.evaluate(attacker_req)
        assert d.action == "hold"

    # Wallet rolling sum should still be 0.0
    assert engine.get_wallet_rolling_sum("0xHotWallet1", 1700000100.0) == 0.0

    # A legitimate transfer must still succeed
    legit_req = SigningRequest(
        id="legit-1",
        ts=1700000101.0,
        chain="ethereum",
        wallet="0xHotWallet1",
        kind="transfer",
        asset="USDC",
        amount_usd=3000.0,
        to="0xRecipient",
    )
    d_legit = engine.evaluate(legit_req)
    assert d_legit.action == "allow"
    assert engine.get_wallet_rolling_sum("0xHotWallet1", 1700000101.0) == 3000.0


def test_multi_chain_anomalies_trip_breaker():
    """
    Verify breaker automatically elevates or locks down if anomalous/denied requests
    occur across multiple chains within a 5-minute rolling window.
    """
    engine = PolicyEngine(
        single_tx_usd=1000.0,
    )
    # Tx on Ethereum exceeds single tx limit -> held
    req_eth = SigningRequest(
        id="eth-anomaly",
        ts=1700000000.0,
        chain="ethereum",
        wallet="0xHotWallet1",
        kind="transfer",
        asset="ETH",
        amount_usd=5000.0,
        to="0xRecipient",
    )
    engine.evaluate(req_eth)
    assert engine.breaker.state == "Normal"

    # Tx on Arbitrum within 60s exceeds single tx limit -> 2nd chain anomaly -> Elevated
    req_arb = SigningRequest(
        id="arb-anomaly",
        ts=1700000060.0,
        chain="arbitrum",
        wallet="0xHotWallet2",
        kind="transfer",
        asset="USDT",
        amount_usd=5000.0,
        to="0xRecipient",
    )
    engine.evaluate(req_arb)
    assert engine.breaker.state in ("Elevated", "Lockdown")

    # Tx on BSC within 120s -> 3rd chain anomaly -> Lockdown
    req_bsc = SigningRequest(
        id="bsc-anomaly",
        ts=1700000120.0,
        chain="bsc",
        wallet="0xHotWallet3",
        kind="transfer",
        asset="BNB",
        amount_usd=5000.0,
        to="0xRecipient",
    )
    engine.evaluate(req_bsc)
    assert engine.breaker.state == "Lockdown"


def test_api_endpoints():
    """Verify FastAPI endpoints: /api/health, /api/evaluate, /api/replay, /api/reset."""
    custom_engine = PolicyEngine(
        wallet_limit_usd=50_000.0,
        single_tx_usd=20_000.0,
    )
    test_app = create_app(custom_engine)
    client = TestClient(test_app)

    # 1. Health check
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"
    assert res.json()["breaker_state"] == "Normal"

    # 2. Single evaluate
    req_payload = {
        "id": "api-req-1",
        "ts": 1700000000.0,
        "chain": "ethereum",
        "wallet": "0xHotWallet1",
        "kind": "transfer",
        "asset": "USDC",
        "amount_usd": 1500.0,
        "to": "0xRecipient1",
        "meta": {},
    }
    res = client.post("/api/evaluate", json=req_payload)
    assert res.status_code == 200
    body = res.json()
    assert body["request_id"] == "api-req-1"
    assert body["action"] == "allow"
    assert body["breaker_state"] == "Normal"

    # 3. Batch replay
    batch_payload = {
        "events": [
            {
                "id": "replay-1",
                "ts": 1700000010.0,
                "chain": "ethereum",
                "wallet": "0xHotWallet1",
                "kind": "transfer",
                "asset": "USDC",
                "amount_usd": 1000.0,
                "to": "0xRecipient1",
                "meta": {},
            },
            {
                "id": "replay-2",
                "ts": 1700000020.0,
                "chain": "ethereum",
                "wallet": "0xHotWallet1",
                "kind": "authorization_7702",
                "asset": "ETH",
                "amount_usd": 0.0,
                "delegate": "0xBadActor",
                "meta": {},
            },
        ]
    }
    res = client.post("/api/replay", json=batch_payload)
    assert res.status_code == 200
    replay_body = res.json()
    assert replay_body["total_evaluated"] == 2
    assert replay_body["allowed_count"] == 1
    assert replay_body["denied_count"] == 1
    assert replay_body["breaker_state"] == "Lockdown"
