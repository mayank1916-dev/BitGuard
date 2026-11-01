import pytest
from fastapi.testclient import TestClient

from backend.app.core.radar import RadarScanner, find_max_consecutive_nonces
from backend.app.core.replay import run_sensitivity_matrix
from backend.app.main import app


def test_find_max_consecutive_nonces():
    """Verify consecutive nonce detector with in-order and sorted streaks."""
    assert find_max_consecutive_nonces([]) == 0
    assert find_max_consecutive_nonces([1]) == 1
    assert find_max_consecutive_nonces([1, 2, 3, 4, 5]) == 5
    assert find_max_consecutive_nonces([1, 5, 2, 4, 3]) == 5  # sorted streak
    assert find_max_consecutive_nonces([1, 10, 20, 30]) == 1


def test_radar_consecutive_nonces_heuristic():
    """Verify that >= 5 consecutive nonces in authorizationList adds +40 risk."""
    scanner = RadarScanner()
    mock_tx = {
        "type": "0x4",
        "hash": "0xmocktx001",
        "from": "0xVictimHotWallet",
        "to": "0xSweeperContract",
        "authorizationList": [
            {"address": "0xSweeperContract", "nonce": hex(i)}
            for i in range(10, 18)  # 8 consecutive nonces
        ],
    }

    finding = scanner.evaluate_type4_tx(mock_tx, block_number=123456, timestamp=1730300000)
    assert finding is not None
    assert finding.has_consecutive_nonces is True
    assert finding.max_consecutive_nonces == 8
    assert "consecutive_nonces_spray" in finding.patterns
    assert finding.risk_score >= 60
    assert finding.is_suspicious is True


def test_radar_high_volume_heuristic():
    """Verify that >= 20 authorizations in authorizationList adds +20 risk."""
    scanner = RadarScanner()
    # 22 authorizations with random scattered nonces
    mock_tx = {
        "type": "0x04",
        "hash": "0xmocktx002",
        "from": "0xWalletA",
        "to": "0xContractB",
        "authorizationList": [
            {"address": f"0xDelegate{i % 4}", "nonce": i * 10}
            for i in range(22)
        ],
    }

    finding = scanner.evaluate_type4_tx(mock_tx, block_number=123457, timestamp=1730300010)
    assert finding is not None
    assert finding.auth_count == 22
    assert "high_volume_authorizations" in finding.patterns
    assert finding.has_consecutive_nonces is False


def test_radar_single_delegate_concentration_heuristic():
    """Verify that multiple authorizations targeting 1 delegate adds +20 risk."""
    scanner = RadarScanner()
    mock_tx = {
        "type": 4,
        "hash": "0xmocktx003",
        "from": "0xWalletA",
        "to": "0xTargetDelegate",
        "authorizationList": [
            {"address": "0xTargetDelegate", "nonce": 2},
            {"address": "0xTargetDelegate", "nonce": 15},
            {"address": "0xTargetDelegate", "nonce": 88},
        ],
    }

    finding = scanner.evaluate_type4_tx(mock_tx, block_number=123458, timestamp=1730300020)
    assert finding is not None
    assert finding.unique_delegates_count == 1
    assert "single_delegate_concentration" in finding.patterns


def test_radar_benign_single_auth_low_risk():
    """Verify that a single routine smart account upgrade remains low risk."""
    scanner = RadarScanner()
    mock_tx = {
        "type": "0x4",
        "hash": "0xmocktx004",
        "from": "0xStandardUser",
        "to": "0xSafeModule",
        "authorizationList": [
            {"address": "0xSafeModule", "nonce": 0}
        ],
    }

    finding = scanner.evaluate_type4_tx(mock_tx, block_number=123459, timestamp=1730300030)
    assert finding is not None
    assert finding.auth_count == 1
    assert finding.risk_score <= 15
    assert finding.is_suspicious is False
    assert len(finding.patterns) == 0


def test_radar_offline_cached_fallback():
    """Verify offline fallback seamlessly serves pre-recorded cached findings."""
    scanner = RadarScanner()
    result = scanner.scan_recent_blocks(n_blocks=5, force_cached=True)

    assert result.source == "cached_sample"
    assert result.findings_count > 0
    assert any(f.has_consecutive_nonces for f in result.findings)
    assert any(f.risk_score == 100 for f in result.findings)
    assert result.suspicious_count > 0


def test_radar_api_endpoint():
    """Verify GET /api/radar endpoint returns structured findings."""
    client = TestClient(app)
    res = client.get("/api/radar?force_cached=true")
    assert res.status_code == 200
    data = res.json()
    assert data["source"] == "cached_sample"
    assert "findings" in data
    assert len(data["findings"]) > 0
    assert data["findings"][0]["auth_count"] >= 1


def test_policy_sensitivity_matrix_and_api():
    """Verify sensitivity matrix calculation and POST /api/policy/sensitivity endpoint."""
    client = TestClient(app)
    req_body = {
        "multipliers": [0.5, 1.0, 2.0],
        "base_limits": {
            "single_tx_usd": 50000.0,
            "wallet_limit_usd": 100000.0,
            "global_limit_usd": 500000.0,
            "new_recipient_usd": 10000.0,
        },
    }
    res = client.post("/api/policy/sensitivity", json=req_body)
    assert res.status_code == 200
    body = res.json()
    assert "matrix" in body
    assert len(body["matrix"]) == 3

    p1 = body["matrix"][0]
    assert p1["limit_multiplier"] == 0.5
    assert p1["single_tx_usd"] == 25000.0
    assert p1["loss_prevented_usd"] > 4_300_000_000.0
    assert p1["loss_mitigated_pct"] >= 99.0
