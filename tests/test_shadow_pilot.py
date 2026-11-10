"""Unit and integration tests for Shadow-Mode Pilot and Traffic Generator (Milestone S26)."""

import json
from pathlib import Path

from scripts.generate_traffic import (
    DEFAULT_CHAIN,
    DEFAULT_WALLET,
    STABLE_DESTINATIONS,
    generate_synthetic_traffic,
    import_real_log,
)
from scripts.run_shadow_pilot import run_shadow_pilot
from services.bitguard.decoders.evm import evm_decoder


def test_traffic_generator_14_days_seasonality_and_tail(tmp_path: Path):
    """Verifies generated traffic has >=14 days, diurnal variation, Pareto tail, and decodable bytes."""
    events = generate_synthetic_traffic(
        days=14,
        base_events_per_day=50,  # Compact count for fast test execution
        seed=1337,
    )

    # 1. Total events and minimum 14 simulated days
    assert len(events) >= 700
    timestamps = [float(e["ts"]) for e in events]
    min_ts, max_ts = min(timestamps), max(timestamps)
    duration_days = (max_ts - min_ts) / 86400.0
    assert duration_days >= 13.9, f"Expected at least 14 days of traffic, got {duration_days:.2f}"

    # 2. Seasonality: peak hours (10:00-18:00 UTC) have higher volume than night hours (00:00-06:00 UTC)
    daytime_events = sum(1 for e in events if 10 <= e["hour_utc"] <= 18)
    nighttime_events = sum(1 for e in events if 0 <= e["hour_utc"] <= 6)
    assert daytime_events > nighttime_events, "Diurnal curve should produce more daytime than nighttime events"

    # 3. Heavy tail of transfer amounts: Pareto/log-normal distribution
    amounts = [float(e["amount_usd"]) for e in events]
    whales = [a for a in amounts if a >= 50_000.0]
    retail = [a for a in amounts if a < 3_000.0]
    assert len(whales) > 0, "Expected whale transfers (>= $50k) in the heavy tail"
    assert len(retail) > len(whales) * 5, "Retail transfers should dominate the volume"

    # 4. Destination distribution: Stable pool vs new destinations
    stable_dest_count = sum(1 for e in events if e["destination"] in STABLE_DESTINATIONS)
    new_dest_count = sum(1 for e in events if e.get("is_new_destination"))
    assert stable_dest_count > new_dest_count, "Stable destinations should represent the majority"
    assert new_dest_count > 0, "Occasional new destinations should be introduced"

    # 5. Raw byte source of truth: EVM decoder successfully unpacks raw_tx
    sample_legacy = events[0]
    decoded_legacy = evm_decoder.decode(sample_legacy["raw_tx"])
    assert decoded_legacy.to_address.lower() == sample_legacy["destination"].lower()
    assert decoded_legacy.chain == DEFAULT_CHAIN

    # 6. Type-4 EIP-7702 delegation raw bytes are decoded
    delegation_events = [e for e in events if e.get("delegate")]
    assert len(delegation_events) > 0, "Expected at least one EIP-7702 delegation event"
    sample_del = delegation_events[0]
    decoded_del = evm_decoder.decode(sample_del["raw_tx"])
    assert len(decoded_del.authorizations) > 0
    assert decoded_del.authorizations[0].address.lower() == sample_del["delegate"].lower()


def test_import_real_log_support(tmp_path: Path):
    """Verifies that an exported real log file is imported and labeled REAL."""
    real_log_path = tmp_path / "real_exported_history.jsonl"
    events_to_write = [
        {
            "id": "real-tx-001",
            "ts": 1730000000.0,
            "chain": "ethereum",
            "wallet": DEFAULT_WALLET,
            "asset": "ETH",
            "amount_usd": 1500.0,
            "destination": "0x1111111111111111111111111111111111111111",
        },
        {
            "id": "real-tx-002",
            "ts": 1730000060.0,
            "chain": "ethereum",
            "wallet": DEFAULT_WALLET,
            "asset": "ETH",
            "amount_usd": 75000.0,
            "destination": "0x2222222222222222222222222222222222222222",
        },
    ]
    with real_log_path.open("w", encoding="utf-8") as f:
        for ev in events_to_write:
            f.write(json.dumps(ev) + "\n")

    imported = import_real_log(real_log_path)
    assert len(imported) == 2
    assert imported[0]["data_label"] == "REAL"
    assert imported[1]["data_label"] == "REAL"
    assert "raw_tx" in imported[0]
    decoded = evm_decoder.decode(imported[0]["raw_tx"])
    assert decoded.to_address.lower() == "0x1111111111111111111111111111111111111111".lower()


def test_shadow_mode_pilot_execution(tmp_path: Path):
    """Executes the full shadow pilot runner and verifies all report metrics."""
    test_traffic_path = tmp_path / "test_shadow_traffic.jsonl"
    events = generate_synthetic_traffic(
        days=14,
        base_events_per_day=30,  # Compact count for fast test run
        seed=999,
    )
    with test_traffic_path.open("w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    results = run_shadow_pilot(traffic_file=test_traffic_path)

    # 1. Pilot summary assertions
    summary = results["pilot_summary"]
    assert summary["total_events"] == len(events)
    assert summary["time_span_days"] >= 13.9
    assert summary["would_have_allowed_count"] > 0
    assert summary["would_have_blocked_count"] > 0
    assert summary["invariant_denials"] == 0

    # 2. Ground truth analysis assertions
    gt = results["ground_truth_analysis"]
    assert gt["benign_events_count"] > 0
    assert gt["anomaly_events_count"] > 0
    assert gt["false_positives_count"] >= 0
    assert gt["true_positives_count"] >= 0
    assert 0.0 <= gt["false_positive_rate"] <= 1.0

    # 3. Promotion checklist structure
    checklist = results["promotion_checklist"]
    assert checklist["current_mode"] == "SHADOW"
    assert "minimum_days_in_shadow" in checklist["checks"]
    assert checklist["checks"]["minimum_days_in_shadow"]["passed"] is True
    assert "zero_unexplained_decode_failures" in checklist["checks"]
    assert checklist["checks"]["zero_unexplained_decode_failures"]["passed"] is True

    # 4. Asymmetric policy evolution results
    evolution = results["asymmetric_policy_evolution"]
    assert evolution["tightening_activation"] == "INSTANT_1_PERSON"
    assert evolution["loosening_activation"] == "QUORUM_COOLDOWN_BACKTEST"
    assert evolution["approvers_count"] == 2
    assert evolution["backtest_report_id"].startswith("btr-loosen-")
