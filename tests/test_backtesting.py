"""Comprehensive test suite for Backtesting & Historical Replay (Milestone S22 / F8).

Verifies:
1. Deterministic replay over identical inputs.
2. Production Redis keys remain untouched during isolated backtests.
3. Looser draft policy permits higher synthetic loss allowed.
4. JSONL and CSV parsing with REAL vs SYNTHETIC labeling.
5. Scenario pattern injection across all 5 scenario types.
6. Integration with S20 policy management (hash matching hook).
7. REST API endpoints POST /v1/backtests and GET /v1/backtests/{id}.
"""

from fastapi.testclient import TestClient

from services.bitguard.backtest.injector import scenario_injector
from services.bitguard.backtest.models import BacktestImportRequest
from services.bitguard.backtest.service import backtest_service
from services.bitguard.limits.store import ScopeBuilder, limit_store
from services.bitguard.main import app
from services.bitguard.models import Role
from services.bitguard.policy.crypto import compute_content_hash
from services.bitguard.policy.models import (
    ChangeClassification,
    LimitsPolicy,
    PolicyDocument,
    PolicyStatus,
    PolicyVersion,
    ThresholdsPolicy,
)
from services.bitguard.policy.service import policy_service
from services.bitguard.policy.store import policy_store
from services.bitguard.rbac import SEEDED_USERS

client = TestClient(app)

SAMPLE_JSONL = """
{"ts": 1730299400.0, "wallet": "0xBinanceHotETH1", "chain": "ethereum", "asset": "ETH", "amount": 1000.0, "destination": "0xCustomerA"}
{"ts": 1730299410.0, "wallet": "0xBinanceHotETH1", "chain": "ethereum", "asset": "ETH", "amount": 2500.0, "destination": "0xCustomerB"}
{"ts": 1730299420.0, "wallet": "0xBinanceHotETH1", "chain": "ethereum", "asset": "ETH", "amount": 5000.0, "destination": "0xCustomerC", "data_label": "REAL"}
{"ts": 1730299430.0, "wallet": "0xBinanceHotETH1", "chain": "ethereum", "asset": "ETH", "amount": 45000.0, "destination": "0xAttackerSynthetic", "data_label": "SYNTHETIC"}
""".strip()

SAMPLE_CSV = """
ts,wallet,chain,asset,amount,destination,intent_id,data_label
1730299400.0,0xBinanceHotETH1,ethereum,ETH,1500.0,0xCustomer1,intent-001,REAL
1730299415.0,0xBinanceHotETH1,ethereum,ETH,3200.0,0xCustomer2,intent-002,REAL
1730299430.0,0xBinanceHotETH1,ethereum,ETH,8000.0,0xCustomer3,,REAL
1730299445.0,0xBinanceHotETH1,ethereum,ETH,90000.0,0xAttacker1,,SYNTHETIC
""".strip()


def _create_test_policy(version: str, single_tx: float = 50_000.0, hold_score: int = 50, per_wallet_limit: float = 100_000.0) -> PolicyVersion:
    doc = PolicyDocument(
        version=version,
        limits=LimitsPolicy(
            global_daily_usd=5_000_000.0,
            wallet_daily_usd={"0xbinancehoteth1": per_wallet_limit},
        ),
        thresholds=ThresholdsPolicy(
            single_tx_usd=single_tx,
            hold_score=hold_score,
        ),
    )
    chash = compute_content_hash(doc)
    pv = PolicyVersion(
        id=f"pv-{version.replace('.', '-')}",
        version=version,
        author="secops@bitguard.local",
        content=doc,
        content_hash=chash,
        status=PolicyStatus.DRAFT,
        change_type=ChangeClassification.TIGHTEN,
    )
    policy_store.save(pv)
    return pv


def test_jsonl_and_csv_parsing():
    """Verify historical requests are correctly parsed from JSONL and CSV with REAL vs SYNTHETIC labels."""
    # JSONL
    reqs_jsonl = backtest_service.parse_historical_events(SAMPLE_JSONL, file_format="jsonl")
    assert len(reqs_jsonl) == 4
    assert reqs_jsonl[0].metadata["data_label"] == "REAL"
    assert reqs_jsonl[0].metadata["amount_usd"] == 1000.0
    assert reqs_jsonl[3].metadata["data_label"] == "SYNTHETIC"
    assert reqs_jsonl[3].metadata["amount_usd"] == 45000.0

    # CSV
    reqs_csv = backtest_service.parse_historical_events(SAMPLE_CSV, file_format="csv")
    assert len(reqs_csv) == 4
    assert reqs_csv[0].metadata["data_label"] == "REAL"
    assert reqs_csv[0].metadata["amount_usd"] == 1500.0
    assert reqs_csv[0].intent_id == "intent-001"
    assert reqs_csv[3].metadata["data_label"] == "SYNTHETIC"
    assert reqs_csv[3].metadata["amount_usd"] == 90000.0


def test_scenario_pattern_injection():
    """Verify that all 5 scenario patterns load and overlay properly as SYNTHETIC events."""
    patterns = scenario_injector.list_available_scenarios()
    pattern_ids = {p.id for p in patterns}
    expected_scenarios = {
        "split_under_limit",
        "rapid_velocity",
        "new_destination_burst",
        "unapproved_delegation_flag",
        "unmatched_intent_burst",
    }
    assert expected_scenarios.issubset(pattern_ids), f"Missing scenario patterns: {expected_scenarios - pattern_ids}"

    real_reqs = backtest_service.parse_historical_events(SAMPLE_JSONL, file_format="jsonl")[:2]
    overlaid = scenario_injector.overlay(real_reqs, scenario_ids=["split_under_limit", "unapproved_delegation_flag"])

    # Must contain both real events and generated synthetic events
    assert len(overlaid) > 2
    synthetic_count = sum(1 for e in overlaid if e.metadata.get("data_label") == "SYNTHETIC")
    assert synthetic_count >= 8

    # Verify chronological ordering
    timestamps = [float(e.metadata["ts"]) for e in overlaid]
    assert timestamps == sorted(timestamps)


def test_replay_is_deterministic():
    """Verify running the exact same backtest twice produces identical reports and decisions."""
    pv = _create_test_policy("v1.5.0", single_tx=50_000.0, hold_score=50)

    req = BacktestImportRequest(
        draft_policy_id=pv.id,
        data=SAMPLE_JSONL,
        format="jsonl",
        scenarios=["split_under_limit"],
    )

    report_1 = backtest_service.create_and_run_backtest(req)
    report_2 = backtest_service.create_and_run_backtest(req)

    assert report_1.total_events == report_2.total_events
    assert report_1.allowed_count == report_2.allowed_count
    assert report_1.held_count == report_2.held_count
    assert report_1.denied_count == report_2.denied_count
    assert report_1.estimated_false_positives == report_2.estimated_false_positives
    assert report_1.synthetic_loss_prevented_usd == report_2.synthetic_loss_prevented_usd
    assert report_1.synthetic_loss_allowed_usd == report_2.synthetic_loss_allowed_usd

    # Compare step by step verdicts
    for s1, s2 in zip(report_1.steps, report_2.steps, strict=True):
        assert s1.protected_decision.verdict == s2.protected_decision.verdict
        assert s1.amount_usd == s2.amount_usd


def test_replay_leaves_production_redis_keys_untouched():
    """Verify that isolated replay runs do not alter or create production Redis keys."""
    r = limit_store._redis
    assert r is not None

    # Pre-populate a production key
    prod_test_key = ScopeBuilder.wallet_scope("0xpreexistingprodwallet")
    r.set(prod_test_key, "active_prod_state")

    # Record production Redis keys
    prod_pattern = "limit:scope:*"
    initial_prod_keys = set(r.keys(prod_pattern))
    assert prod_test_key in initial_prod_keys

    pv = _create_test_policy("v1.6.0", single_tx=40_000.0, hold_score=50)
    req = BacktestImportRequest(
        draft_policy_id=pv.id,
        data=SAMPLE_CSV,
        format="csv",
        scenarios=["rapid_velocity", "split_under_limit"],
    )

    report = backtest_service.create_and_run_backtest(req)
    assert report.total_events > 0

    # Production keys must be completely unchanged
    current_prod_keys = set(r.keys(prod_pattern))
    assert current_prod_keys == initial_prod_keys

    # No leftover backtest keys should remain
    backtest_keys = list(r.keys(f"backtest:{report.id}:*"))
    assert len(backtest_keys) == 0


def test_looser_draft_allows_more_synthetic_loss():
    """A draft policy that is looser than current shows more synthetic loss allowed."""
    # Strict Policy: low threshold ($20k), strict hold score (40)
    strict_pv = _create_test_policy("v-strict", single_tx=20_000.0, hold_score=40, per_wallet_limit=30_000.0)

    # Looser Policy: very high threshold ($200k), relaxed hold score (90), large wallet limit ($500k)
    loose_pv = _create_test_policy("v-loose", single_tx=200_000.0, hold_score=90, per_wallet_limit=500_000.0)

    # Attack scenario: split_under_limit ($49,000 per tx)
    req_strict = BacktestImportRequest(
        draft_policy_id=strict_pv.id,
        data=SAMPLE_JSONL,
        format="jsonl",
        scenarios=["split_under_limit"],
    )
    req_loose = BacktestImportRequest(
        draft_policy_id=loose_pv.id,
        data=SAMPLE_JSONL,
        format="jsonl",
        scenarios=["split_under_limit"],
    )

    report_strict = backtest_service.create_and_run_backtest(req_strict)
    report_loose = backtest_service.create_and_run_backtest(req_loose)

    # Under strict policy: $49,000 transfers exceed $20k single-tx limit and $30k wallet limit -> held
    # Under loose policy: $49,000 transfers are under $200k limit and within $500k wallet limit -> allowed
    assert report_loose.synthetic_loss_allowed_usd > report_strict.synthetic_loss_allowed_usd
    assert report_strict.synthetic_loss_prevented_usd > report_loose.synthetic_loss_prevented_usd


def test_s20_loosening_hook_requires_matching_backtest_report():
    """Verifies S20 policy approval and activation strictly enforce matching backtest report hash."""
    secops_user = SEEDED_USERS[Role.SECOPS]
    approver1_user = SEEDED_USERS[Role.APPROVER]

    base_pv = policy_service.get_or_create_baseline()
    base_doc = base_pv.content

    # Create loosening draft
    loosen_doc = base_doc.model_copy(deep=True)
    loosen_doc.version = "v3.0.0"
    loosen_doc.limits.global_daily_usd = 8_000_000.0
    loosen_doc.thresholds.single_tx_usd = 250_000.0

    loosen_hash = compute_content_hash(loosen_doc)
    loosen_pv = PolicyVersion(
        id="pv-v3-0-0",
        version="v3.0.0",
        author=secops_user.email,
        content=loosen_doc,
        content_hash=loosen_hash,
        status=PolicyStatus.PENDING,
        change_type=ChangeClassification.LOOSEN,
    )
    policy_store.save(loosen_pv)

    # 1. Run backtest to generate valid report for this draft policy
    btr_req = BacktestImportRequest(
        draft_policy_id=loosen_pv.id,
        data=SAMPLE_JSONL,
        format="jsonl",
        scenarios=["split_under_limit"],
    )
    valid_report = backtest_service.create_and_run_backtest(btr_req)
    assert valid_report.draft_policy_hash == loosen_hash

    # 2. Attach a report with MISMATCHED draft policy hash
    mismatched_report = valid_report.model_copy(deep=True)
    mismatched_report.id = "btr-mismatched"
    mismatched_report.draft_policy_hash = "0xdeadbeefbad00000000000000000000000000000000000000000000000000000"
    backtest_service.save_report(mismatched_report)

    loosen_pv.backtest_report_id = "btr-mismatched"
    policy_store.save(loosen_pv)

    # Attempt to approve with mismatched report -> Rejected
    from services.bitguard.approvals.webauthn import (
        approver_registry,
        create_test_webauthn_assertion,
    )
    priv_appr1 = approver_registry.dev_private_keys["usr-approver-01"]
    assertion1 = create_test_webauthn_assertion(
        private_key=priv_appr1,
        tx_digest=loosen_pv.content_hash,
        sign_count=1,
    )
    import pytest
    with pytest.raises(ValueError, match="draft policy hash.*does not match"):
        policy_service.approve_policy(loosen_pv.id, approver_user=approver1_user, assertion=assertion1)

    # 3. Attach the valid matching report -> Approvals succeed
    loosen_pv.backtest_report_id = valid_report.id
    policy_store.save(loosen_pv)

    approved_pv = policy_service.approve_policy(loosen_pv.id, approver_user=approver1_user, assertion=assertion1)
    assert len(approved_pv.approvals) == 1


def test_backtest_rest_api_endpoints():
    """Verifies POST /v1/backtests and GET /v1/backtests/{id} HTTP endpoints."""
    pv = _create_test_policy("v1.7.0", single_tx=30_000.0, hold_score=50)

    # POST /v1/backtests
    payload = {
        "draft_policy_id": pv.id,
        "data": SAMPLE_JSONL,
        "format": "jsonl",
        "scenarios": ["split_under_limit"],
    }
    res = client.post("/v1/backtests", json=payload)
    assert res.status_code == 200, res.text
    data = res.json()

    report_id = data["id"]
    assert report_id.startswith("btr-")
    assert data["draft_policy_id"] == pv.id
    assert data["total_events"] > 0
    assert "holds_per_day" in data
    assert "estimated_false_positives" in data
    assert "synthetic_loss_prevented_usd" in data
    assert "policy_diff" in data

    # GET /v1/backtests/{id}
    res_get = client.get(f"/v1/backtests/{report_id}")
    assert res_get.status_code == 200
    get_data = res_get.json()
    assert get_data["id"] == report_id
    assert get_data["draft_policy_id"] == pv.id

    # Non-existent report -> 404
    res_404 = client.get("/v1/backtests/btr-non-existent-999")
    assert res_404.status_code == 404
