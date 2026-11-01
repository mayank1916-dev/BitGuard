from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.models import SigningRequest
from backend.app.core.replay import ReplayRunner, ReplayReport
from backend.app.main import app, create_app


def test_binance_replay_blocks_attack_cascade_and_trips_lockdown():
    """
    Verify that running replay_binance_like.json blocks the attack cascade,
    caps protected loss significantly below the unprotected total (~$4.39B),
    and trips the Breaker into Lockdown.
    """
    dataset_file = Path(__file__).resolve().parent.parent / "data" / "replay_binance_like.json"
    assert dataset_file.exists(), "Synthetic dataset file must exist"

    runner = ReplayRunner(dataset_path=dataset_file)
    report: ReplayReport = runner.run()
    summary = report.summary

    # Event counts
    assert summary.total_requests == 75
    assert summary.normal_requests_count == 12
    assert summary.attack_requests_count == 63

    # Baseline vs Protected Loss
    # Unprotected loss should be ~$4.39 Billion
    assert summary.unprotected_loss_usd > 4_300_000_000.0
    # BitGuard protection must cap the protected loss to 0 (or near 0)
    assert summary.protected_loss_usd < 1_000_000.0
    assert summary.loss_prevented_usd > 4_300_000_000.0
    assert summary.loss_prevented_pct >= 99.9

    # Containment & Breaker State
    assert summary.breaker_final_state == "Lockdown"
    assert summary.first_blocked_event is not None
    assert summary.first_blocked_event["request_id"] == "atk-xrp-01"
    assert summary.first_blocked_event["rule"] in ("single_tx_limit", "wallet_limit")
    assert summary.first_blocked_event["action"] in ("hold", "deny")
    assert summary.time_to_contain_seconds == 0.0

    # Zero false positives on legitimate background traffic
    assert summary.false_positive_count == 0


def test_normal_background_traffic_zero_false_positives():
    """Verify that all normal customer withdrawals preceding the incident are allowed."""
    runner = ReplayRunner()
    report = runner.run()

    normal_steps = [s for s in report.steps if s.scenario == "normal"]
    assert len(normal_steps) == 12
    for step in normal_steps:
        assert step.protected_decision.action == "allow"
        assert step.protected_decision.risk == 0
        assert step.protected_decision.breaker_state == "Normal"


def test_eip_7702_sweep_blocked_in_lockdown():
    """
    Verify that the $2.18B sweep contract call and secondary pulls at T+35m and T+55m
    are strictly denied due to circuit breaker Lockdown.
    """
    runner = ReplayRunner()
    report = runner.run()

    # Find the massive sweep event
    sweep_steps = [s for s in report.steps if s.request_id == "atk-the-sweep-01"]
    assert len(sweep_steps) == 1
    sweep_step = sweep_steps[0]
    assert sweep_step.protected_decision.action == "deny"
    assert sweep_step.protected_decision.breaker_state == "Lockdown"

    # Find secondary sweeps at T+35m and T+55m
    secondary_steps = [
        s for s in report.steps
        if s.request_id in ("atk-secondary-sweep-35m", "atk-secondary-sweep-55m")
    ]
    assert len(secondary_steps) == 2
    for step in secondary_steps:
        assert step.protected_decision.action == "deny"
        assert step.protected_decision.breaker_state == "Lockdown"


def test_replay_with_custom_policy_overrides():
    """
    Verify sensitivity testing: with single_tx_usd relaxed to $30M, the first XRP drain
    passes, but the multi-chain velocity limits and 7702 guard still contain the cascade.
    """
    overrides = {
        "single_tx_usd": 30_000_000.0,
        "wallet_limit_usd": 50_000_000.0,
        "global_limit_usd": 100_000_000.0,
    }
    runner = ReplayRunner(policy_overrides=overrides)
    report = runner.run()
    summary = report.summary

    # Even with relaxed limits, the multi-billion dollar drain is capped
    assert summary.protected_loss_usd < summary.unprotected_loss_usd * 0.1
    assert summary.loss_prevented_pct > 90.0
    assert summary.breaker_final_state == "Lockdown"


def test_api_replay_endpoint():
    """
    Verify POST /api/replay endpoint returns the full step-by-step event stream
    and aggregate summary metrics.
    """
    client = TestClient(app)

    # Replay default Binance dataset
    response = client.post("/api/replay", json={})
    assert response.status_code == 200
    data = response.json()

    assert "summary" in data
    assert "steps" in data
    assert data["summary"]["total_requests"] == 75
    assert data["summary"]["unprotected_loss_usd"] > 4_300_000_000.0
    assert data["summary"]["loss_prevented_usd"] > 4_300_000_000.0
    assert data["summary"]["breaker_final_state"] == "Lockdown"
    assert data["breaker_state"] == "Lockdown"
    assert len(data["steps"]) == 75

    # Replay with policy overrides
    override_payload = {
        "policy_overrides": {
            "single_tx_usd": 10_000.0,
            "wallet_limit_usd": 25_000.0,
        }
    }
    res_override = client.post("/api/replay", json=override_payload)
    assert res_override.status_code == 200
    data_override = res_override.json()
    assert data_override["summary"]["breaker_final_state"] == "Lockdown"
