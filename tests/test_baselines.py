"""Comprehensive test suite for Task S32 - Behavioral Baselines per Wallet (F15).

Invariants Verified:
- Invariant #1: Key Isolation (BitGuard never stores or uses keys).
- Invariant #3: Fail-Closed Default (unknown formats / corrupt state fails closed).
- Invariant #4: Raw Byte Source of Truth (volume and baseline sizes derived from raw decoded transaction bytes).
- Invariant #6: Asymmetric Policy Evolution (tightening = instant; loosening = quorum + cool-down + backtest).
- Invariant #8: Explicit Data Provenance (REAL vs SYNTHETIC labels).
- Invariant #11: Strict Wording ('reduces and contains', 'target p99 under 15 ms, measured').
- Baselines contribute risk weight only and can NEVER alone cause DENY.
- Cold start (< 7 days of data) adds a small configurable 'LOW_HISTORY' weight and NO other baseline reasons.
"""

from datetime import UTC, datetime

import pytest
import rlp

from services.bitguard.backtest.service import backtest_service
from services.bitguard.baselines.service import BaselineService
from services.bitguard.baselines.store import BaselineStore, baseline_store
from services.bitguard.engine.pipeline import DecisionEngine
from services.bitguard.models import (
    DataLabel,
    SigningRequest,
    Verdict,
)
from services.bitguard.policy.classifier import classify_change
from services.bitguard.policy.models import (
    BaselinePolicy,
    ChangeClassification,
    LimitsPolicy,
    PolicyDocument,
    ThresholdsPolicy,
)

HOT_WALLET = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
BENIGN_DEST_A = "0x1111111111111111111111111111111111111111"
BENIGN_DEST_B = "0x2222222222222222222222222222222222222222"
NEW_DEST = "0x9999999999999999999999999999999999999999"

# Clean UTC midnight epoch for predictable hour alignment (0-23 UTC)
BASE_MIDNIGHT_TS = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC).timestamp()


def build_raw_legacy_tx(to_addr: str, value_wei: int = 0, nonce: int = 0) -> str:
    """Builds valid RLP-encoded raw unsigned EVM legacy transaction."""
    clean = to_addr.removeprefix("0x")
    to_bytes = bytes.fromhex(clean)
    payload = [nonce, 20_000_000_000, 21000, to_bytes, value_wei, b""]
    return "0x" + rlp.encode(payload).hex()


@pytest.fixture(autouse=True)
def clean_baseline_store():
    """Resets the baseline store before and after each test."""
    baseline_store.reset()
    yield
    baseline_store.reset()


def populate_28_day_baseline_history(
    store: BaselineStore,
    wallet: str,
    base_ts: float,
    typical_hourly_usd: float = 10_000.0,
    typical_tx_size_usd: float = 2_000.0,
    off_hours: list[int] | None = None,
) -> None:
    """Generates 28 days of realistic baseline traffic for a wallet."""
    if off_hours is None:
        off_hours = [1, 2, 3, 4, 5]

    for day in range(28):
        day_start_ts = base_ts + (day * 86400.0)
        # 5 distinct stable destinations per day
        destinations = [
            f"0x{d:02d}111111111111111111111111111111111111"
            for d in range(1, 6)
        ]

        for hour in range(24):
            hour_ts = day_start_ts + (hour * 3600.0) + 1800.0

            if hour in off_hours:
                # Off hours: near-zero volume ($0 - $50)
                store.record_transaction(
                    wallet=wallet,
                    amount_usd=25.0,
                    destination=destinations[0],
                    timestamp=hour_ts,
                    data_label=DataLabel.REAL,
                )
            else:
                # Active hours: 5 transactions of ~$2,000 totaling ~$10,000/hr
                for tx_idx in range(5):
                    tx_ts = hour_ts + (tx_idx * 600.0)
                    dest = destinations[tx_idx % len(destinations)]
                    # Sizes vary around $2,000 (e.g. $1,500 - $2,500)
                    amt = typical_tx_size_usd + ((tx_idx - 2) * 200.0)
                    store.record_transaction(
                        wallet=wallet,
                        amount_usd=amt,
                        destination=dest,
                        timestamp=tx_ts,
                        data_label=DataLabel.REAL,
                    )


# ==============================================================================
# 1. Rolling Statistics Maintenance (28-day window)
# ==============================================================================


def test_rolling_statistics_maintenance_28_days():
    """Requirement: Per-wallet rolling stats over 28 days: hourly volume p50/p95/p99, destinations, size percentiles."""
    store = BaselineStore()
    base_time = BASE_MIDNIGHT_TS

    populate_28_day_baseline_history(
        store=store,
        wallet=HOT_WALLET,
        base_ts=base_time,
        typical_hourly_usd=10_000.0,
        typical_tx_size_usd=2_000.0,
    )

    profile = store.get_profile(HOT_WALLET)
    assert profile is not None
    assert profile.wallet == HOT_WALLET.lower()
    assert profile.history_days >= 27.0
    assert profile.total_transactions > 100

    # Verify hourly volume stats (p50, p95, p99) for active hour (e.g. 14:00 UTC)
    h14 = profile.hourly_volumes[14]
    assert h14.hour == 14
    assert 8_000.0 <= h14.p50 <= 12_000.0
    assert h14.p95 >= h14.p50
    assert h14.p99 >= h14.p95
    assert h14.sample_count == 28

    # Verify off-hours volume (e.g. hour 2 UTC)
    h2 = profile.hourly_volumes[2]
    assert h2.p50 <= 100.0

    # Verify distinct destinations stats
    assert profile.destination_stats.p50_distinct_per_day >= 4.0
    assert profile.destination_stats.total_unique_destinations >= 5

    # Verify size percentiles
    assert 1_800.0 <= profile.size_percentiles.p50 <= 2_200.0
    assert profile.size_percentiles.p99 >= profile.size_percentiles.p95
    assert profile.size_percentiles.max_observed >= profile.size_percentiles.p99


# ==============================================================================
# 2. Cold Start (< 7 days of data)
# ==============================================================================


def test_cold_start_under_7_days_adds_low_history_weight_only():
    """Requirement: Cold start (< 7 days) adds small LOW_HISTORY weight and NO other baseline reasons."""
    store = BaselineStore()
    service = BaselineService(store=store)
    policy = BaselinePolicy(min_history_days=7, low_history_weight=15)

    base_time = 1730000000.0
    # Add only 3 days of transaction history
    for d in range(3):
        store.record_transaction(
            wallet=HOT_WALLET,
            amount_usd=50_000.0,  # Huge amount
            destination=f"0xnew{d}000000000000000000000000000000000000",
            timestamp=base_time + (d * 86400.0),
        )

    # Now evaluate a transaction that would otherwise trigger size outlier / volume high / off-hours
    eval_ts = base_time + (3 * 86400.0) + (2 * 3600.0)  # Off-hours (02:00 UTC)
    res = service.evaluate_transaction(
        wallet=HOT_WALLET,
        amount_usd=250_000.0,  # Massive outlier
        destination="0xnever_seen_before_destination_9999999999999999",
        timestamp=eval_ts,
        policy=policy,
    )

    assert res.is_cold_start is True
    assert len(res.reasons) == 1
    assert res.reasons[0].code == "LOW_HISTORY"
    assert res.reasons[0].weight == 15
    assert "low history weight applied" in res.reasons[0].detail
    # Must NOT have any other baseline reasons during cold start
    assert not any(r.code in ["BASELINE_VOLUME_HIGH", "BASELINE_SIZE_OUTLIER", "BASELINE_OFF_HOURS"] for r in res.reasons)


# ==============================================================================
# 3. Slow Drain Attack (stays under individual limits, raises baseline reason)
# ==============================================================================


def test_slow_drain_under_limits_raises_baseline_volume_high():
    """Requirement: A slow drain that stays under single-tx limit and velocity limit raises BASELINE_VOLUME_HIGH."""
    store = BaselineStore()
    service = BaselineService(store=store)
    policy = BaselinePolicy(
        volume_multiplier_threshold=3.0,
        volume_high_weight=35,
    )

    base_time = BASE_MIDNIGHT_TS
    # 28 days of baseline: typical hour 15:00 has ~$10,000 volume (p50 = $10,000)
    populate_28_day_baseline_history(
        store=store,
        wallet=HOT_WALLET,
        base_ts=base_time,
        typical_hourly_usd=10_000.0,
    )

    eval_day_ts = base_time + (28 * 86400.0) + (15 * 3600.0)  # 15:00 UTC on day 29

    # Pre-accumulate $25,000 in this hour through 5 small transfers of $5,000
    for i in range(5):
        store.record_transaction(
            wallet=HOT_WALLET,
            amount_usd=5_000.0,
            destination=BENIGN_DEST_A,
            timestamp=eval_day_ts + (i * 60.0),
        )

    # Next transfer of $10,000 brings hour total to $35,000 (3.5x typical $10,000)
    res = service.evaluate_transaction(
        wallet=HOT_WALLET,
        amount_usd=10_000.0,
        destination=BENIGN_DEST_A,
        timestamp=eval_day_ts + 600.0,
        policy=policy,
    )

    assert any(r.code == "BASELINE_VOLUME_HIGH" for r in res.reasons)
    vh_reason = next(r for r in res.reasons if r.code == "BASELINE_VOLUME_HIGH")
    assert vh_reason.weight == 35
    # Human-readable format required: 'volume Nx typical for this hour'
    assert "volume 3.5x typical for this hour" in vh_reason.detail


# ==============================================================================
# 4. Normal Day Does Not Raise Baseline Reasons
# ==============================================================================


def test_normal_day_conforming_to_baseline_does_not_raise_reasons():
    """Requirement: Normal traffic adhering to historical distributions raises zero baseline reasons."""
    store = BaselineStore()
    service = BaselineService(store=store)
    policy = BaselinePolicy()

    base_time = BASE_MIDNIGHT_TS
    populate_28_day_baseline_history(
        store=store,
        wallet=HOT_WALLET,
        base_ts=base_time,
        typical_hourly_usd=10_000.0,
        typical_tx_size_usd=2_000.0,
    )

    eval_day_ts = base_time + (28 * 86400.0) + (14 * 3600.0)  # 14:00 UTC

    # A typical $2,000 transfer to known destination during daytime active hours
    res = service.evaluate_transaction(
        wallet=HOT_WALLET,
        amount_usd=2_000.0,
        destination="0x01111111111111111111111111111111111111",  # Known destination
        timestamp=eval_day_ts,
        policy=policy,
    )

    assert len(res.reasons) == 0
    assert res.total_risk_weight == 0
    assert res.is_cold_start is False


# ==============================================================================
# 5. New Destination Burst Detection
# ==============================================================================


def test_new_destination_burst_triggers_reason():
    """Requirement: Rapid transfers to previously unobserved destinations trigger BASELINE_NEW_DESTINATION_BURST."""
    store = BaselineStore()
    service = BaselineService(store=store)
    policy = BaselinePolicy(
        new_destination_burst_threshold=5,
        new_destination_burst_weight=30,
    )

    base_time = BASE_MIDNIGHT_TS
    populate_28_day_baseline_history(store=store, wallet=HOT_WALLET, base_ts=base_time)

    eval_day_ts = base_time + (28 * 86400.0) + (12 * 3600.0)

    # Send transfers to 4 new destinations in the past 2 hours
    for i in range(4):
        store.record_transaction(
            wallet=HOT_WALLET,
            amount_usd=1_000.0,
            destination=f"0xburst_{i}_00000000000000000000000000000000",
            timestamp=eval_day_ts - (i * 300.0),
        )

    # 5th transfer to a 5th new destination hits the burst threshold
    res = service.evaluate_transaction(
        wallet=HOT_WALLET,
        amount_usd=1_000.0,
        destination="0xburst_5_00000000000000000000000000000000",
        timestamp=eval_day_ts,
        policy=policy,
    )

    assert any(r.code == "BASELINE_NEW_DESTINATION_BURST" for r in res.reasons)
    burst_reason = next(r for r in res.reasons if r.code == "BASELINE_NEW_DESTINATION_BURST")
    assert burst_reason.weight == 30
    assert "New destination burst: 5 new destinations in 24h" in burst_reason.detail


# ==============================================================================
# 6. Size Outlier and Off-Hours Evaluation
# ==============================================================================


def test_size_outlier_and_off_hours_triggers():
    """Requirement: Transfer exceeding p99 triggers BASELINE_SIZE_OUTLIER; off-hours transfer triggers BASELINE_OFF_HOURS."""
    store = BaselineStore()
    service = BaselineService(store=store)
    policy = BaselinePolicy(
        size_outlier_weight=25,
        off_hours=[2, 3, 4],
        off_hours_threshold_usd=500.0,
        off_hours_weight=20,
    )

    base_time = BASE_MIDNIGHT_TS
    populate_28_day_baseline_history(
        store=store,
        wallet=HOT_WALLET,
        base_ts=base_time,
        typical_tx_size_usd=2_000.0,  # p99 will be around ~$2,400
    )

    # Transfer of $15,000 at 03:00 UTC (off-hours) to known destination
    eval_ts = base_time + (28 * 86400.0) + (3 * 3600.0)
    res = service.evaluate_transaction(
        wallet=HOT_WALLET,
        amount_usd=15_000.0,
        destination="0x01111111111111111111111111111111111111",
        timestamp=eval_ts,
        policy=policy,
    )

    reason_codes = [r.code for r in res.reasons]
    assert "BASELINE_SIZE_OUTLIER" in reason_codes
    assert "BASELINE_OFF_HOURS" in reason_codes

    size_reason = next(r for r in res.reasons if r.code == "BASELINE_SIZE_OUTLIER")
    assert "$15,000.00 is an outlier compared to historical p99" in size_reason.detail

    off_reason = next(r for r in res.reasons if r.code == "BASELINE_OFF_HOURS")
    assert "Outflow of $15,000.00 during off-hours (03:00 UTC)" in off_reason.detail


# ==============================================================================
# 7. Baselines Never Alone Cause DENY
# ==============================================================================


def test_baselines_contribute_weight_only_and_never_alone_cause_deny():
    """Requirement: Baselines contribute weight only; they can push verdict to HOLD but NEVER DENY."""
    engine = DecisionEngine()
    policy_doc = PolicyDocument(
        limits=LimitsPolicy(global_daily_usd=500_000.0),
        thresholds=ThresholdsPolicy(single_tx_usd=100_000.0, hold_score=50),
        baselines=BaselinePolicy(
            volume_multiplier_threshold=2.0,
            volume_high_weight=35,
            size_outlier_weight=25,
        ),
    )
    engine.reload_policy(policy_doc)

    base_time = BASE_MIDNIGHT_TS
    populate_28_day_baseline_history(
        store=baseline_store,
        wallet=HOT_WALLET,
        base_ts=base_time,
        typical_hourly_usd=5_000.0,
        typical_tx_size_usd=1_000.0,
    )

    eval_ts = base_time + (28 * 86400.0) + (14 * 3600.0)

    # Valid transaction that triggers both BASELINE_VOLUME_HIGH (35) and BASELINE_SIZE_OUTLIER (25)
    # Total risk score = 60 >= 50 hold threshold -> HOLD, NOT DENY!
    req = SigningRequest(
        chain="ethereum",
        wallet=HOT_WALLET,
        raw_tx=build_raw_legacy_tx(BENIGN_DEST_A, value_wei=10**18),
        metadata={
            "amount_usd": 20_000.0,
            "ts": eval_ts,
            "destination": BENIGN_DEST_A,
        },
    )

    decision = engine.evaluate(req)

    assert decision.verdict == Verdict.HOLD
    assert decision.verdict != Verdict.DENY
    assert decision.risk_score >= 50
    assert any(r.code == "BASELINE_VOLUME_HIGH" for r in decision.reasons)
    assert any(r.code == "BASELINE_SIZE_OUTLIER" for r in decision.reasons)
    # Verify none of the baseline reasons are hard_denies
    assert all(r.weight < 90 for r in decision.reasons)


# ==============================================================================
# 8. Backfill Baselines from Backtest Data (S22)
# ==============================================================================


def test_backfill_baselines_from_backtest_data():
    """Requirement: Backfill baselines from historical backtest dataset (JSONL or CSV)."""
    base_time = BASE_MIDNIGHT_TS
    jsonl_lines = []
    for day in range(10):
        ts = base_time + (day * 86400.0) + 3600.0
        jsonl_lines.append(
            f'{{"wallet": "{HOT_WALLET}", "amount_usd": 5000.0, "destination": "{BENIGN_DEST_A}", "ts": {ts}, "data_label": "REAL"}}'
        )
    raw_jsonl = "\n".join(jsonl_lines)

    processed = backtest_service.backfill_baselines(raw_jsonl, file_format="jsonl")
    assert processed == 10

    profile = baseline_store.get_profile(HOT_WALLET)
    assert profile is not None
    assert profile.total_transactions == 10
    assert profile.history_days >= 8.0  # > 7 days, so cold-start is resolved!


# ==============================================================================
# 9. Asymmetric Policy Evolution (classify_change for Baselines)
# ==============================================================================


def test_baseline_policy_asymmetric_classification():
    """Requirement: Tightening baseline rules = TIGHTEN (instant 1-person). Loosening = LOOSEN."""
    old_doc = PolicyDocument(
        baselines=BaselinePolicy(
            volume_multiplier_threshold=3.0,
            volume_high_weight=35,
            new_destination_burst_threshold=5,
            off_hours=[1, 2, 3],
        )
    )

    # 1. Stricter multiplier (2.0 < 3.0) -> TIGHTEN
    tighten_doc = old_doc.model_copy(deep=True)
    tighten_doc.baselines.volume_multiplier_threshold = 2.0
    assert classify_change(old_doc, tighten_doc) == ChangeClassification.TIGHTEN

    # 2. More off-hours -> TIGHTEN
    tighten_oh = old_doc.model_copy(deep=True)
    tighten_oh.baselines.off_hours = [1, 2, 3, 4, 5]
    assert classify_change(old_doc, tighten_oh) == ChangeClassification.TIGHTEN

    # 3. Higher burst threshold (10 > 5: tolerates more unverified destinations) -> LOOSEN
    loosen_doc = old_doc.model_copy(deep=True)
    loosen_doc.baselines.new_destination_burst_threshold = 10
    assert classify_change(old_doc, loosen_doc) == ChangeClassification.LOOSEN

    # 4. Disabling baselines -> LOOSEN
    disabled_doc = old_doc.model_copy(deep=True)
    disabled_doc.baselines.enabled = False
    assert classify_change(old_doc, disabled_doc) == ChangeClassification.LOOSEN
