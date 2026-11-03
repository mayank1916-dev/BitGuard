"""Comprehensive test suite for BitGuard Integration Lab (Milestone S23 / F19).

Verifies:
1. Mainnet chain ID refusal (Invariant #9: Environment & Safety Boundary).
2. Declarative YAML scenario schema validation for all 11 scenarios.
3. Full integration lab suite execution with 100% pass rate.
4. Correctness of lab/results/latest.json output with explicit SYNTHETIC provenance.
5. Time-to-contain measurement on watcher delegation detection (Scenario 5).
6. CLI entrypoint behavior and exit codes (safety exit code 2 on mainnet attempt).
"""

import pytest

from lab.runner.config import LATEST_JSON_FILE, LATEST_SUMMARY_FILE, SCENARIOS_DIR
from lab.runner.executor import LabScenarioExecutor
from lab.runner.main import main
from lab.runner.models import LabReport, ScenarioDefinition
from lab.runner.safety import (
    MainnetForbiddenError,
    assert_non_mainnet,
)


def test_mainnet_chain_ids_strictly_refused():
    """Requirement: Never connect to mainnet; refuse to start if chain id is a known mainnet id."""
    # 1. Numeric known mainnets
    for chain_id in [1, 10, 56, 137, 8453, 42161, 43114]:
        with pytest.raises(MainnetForbiddenError) as exc_info:
            assert_non_mainnet(chain_id)
        assert "SAFETY VIOLATION" in str(exc_info.value)
        assert str(chain_id) in str(exc_info.value)

    # 2. String mainnet identifiers
    for chain_name in ["mainnet", "homestead", "ethereum-mainnet", "polygon-mainnet"]:
        with pytest.raises(MainnetForbiddenError) as exc_info:
            assert_non_mainnet(chain_name)
        assert "SAFETY VIOLATION" in str(exc_info.value)

    # 3. Testnets and local chains must pass without error
    assert_non_mainnet(31337, "anvil-local")
    assert_non_mainnet(11155111, "sepolia")
    assert_non_mainnet(17000, "holesky")


def test_all_11_scenarios_valid_yaml_declarations():
    """Requirement: All scenario files describe patterns as data (pure declarative YAML)."""
    executor = LabScenarioExecutor()
    scenarios = executor.load_scenarios(SCENARIOS_DIR)

    assert len(scenarios) == 11, f"Expected 11 scenarios, loaded {len(scenarios)}"

    expected_ids = [
        "scenario_01_normal_withdrawal",
        "scenario_02_over_limit_hold_then_quorum_release",
        "scenario_03_hold_expires_to_deny",
        "scenario_04_delegation_attempt_denied",
        "scenario_05_watcher_detects_unapproved_delegation_and_breaker_trips",
        "scenario_06_split_under_limit_triggers_velocity_or_baseline_reason",
        "scenario_07_redis_outage_fails_closed",
        "scenario_08_direct_signer_call_refused",
        "scenario_09_token_replay_refused",
        "scenario_10_unmatched_intent_denied",
        "scenario_11_lockdown_then_two_person_unlock",
    ]

    loaded_ids = [s.id for s in scenarios]
    assert loaded_ids == expected_ids

    for sc in scenarios:
        assert isinstance(sc, ScenarioDefinition)
        assert sc.target_chain_id == 31337
        assert sc.pattern_data, f"Scenario {sc.id} missing pattern_data"
        assert sc.assertions, f"Scenario {sc.id} missing assertions"


def test_full_lab_suite_execution_and_report_generation():
    """Requirement: Runner executes all 11 scenarios, producing latest.json and summary."""
    executor = LabScenarioExecutor()
    report = executor.execute_all(SCENARIOS_DIR)

    assert isinstance(report, LabReport)
    assert report.total_scenarios == 11
    assert report.passed == 11
    assert report.failed == 0
    assert report.pass_rate_pct == 100.0
    assert report.data_label == "SYNTHETIC"

    # Wording invariants verification
    assert "target p99 under 15 ms, measured" in report.target_performance_claim.lower()
    assert "reduces and contains" in report.containment_claim.lower()
    assert "production-ready architecture; pilot after audit and shadow-mode validation" in report.containment_claim.lower()

    # Verify latest.json and latest_summary.txt were persisted to disk
    assert LATEST_JSON_FILE.exists()
    assert LATEST_SUMMARY_FILE.exists()

    content = LATEST_SUMMARY_FILE.read_text(encoding="utf-8")
    assert "Scenarios Executed: 11 | Passed: 11 | Failed: 0 | Pass Rate: 100.0%" in content
    assert "Safety Gate: PASSED" in content


def test_time_to_contain_recorded_on_watcher_detection():
    """Requirement 5: Watcher detects unapproved delegation and breaker trips (time-to-contain recorded)."""
    executor = LabScenarioExecutor()
    scenarios = executor.load_scenarios(SCENARIOS_DIR)
    sc5 = next(s for s in scenarios if s.id == "scenario_05_watcher_detects_unapproved_delegation_and_breaker_trips")

    result = executor.execute_scenario(sc5)
    assert result.status == "PASS"
    assert result.time_to_contain_ms is not None
    assert result.time_to_contain_ms > 0.0
    assert result.time_to_contain_ms <= 5000.0
    assert result.actual_outcome == "BREAKER_TRIPPED"


def test_lab_cli_mainnet_rejection_exit_code(monkeypatch):
    """Verifies CLI entrypoint exits with code 2 on attempt to run against mainnet."""
    monkeypatch.setattr("sys.argv", ["lab-runner", "--chain-id", "1"])
    exit_code = main()
    assert exit_code == 2


def test_lab_cli_successful_run(monkeypatch):
    """Verifies CLI entrypoint exits with code 0 when all scenarios pass."""
    monkeypatch.setattr("sys.argv", ["lab-runner", "--chain-id", "31337"])
    exit_code = main()
    assert exit_code == 0
