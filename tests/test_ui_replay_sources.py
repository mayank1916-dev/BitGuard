"""Tests for Incident Replay Source Selector and S22 Backtest Integration (Milestone U3).

Tests compliance with:
- Three replay sources: 'Built-in scenario', 'Imported log', 'Recorded live traffic'.
- 'Imported log' streaming through the real decision engine.
- 'Recorded live traffic' replaying stored decisions.
- Simulation clock displaying event count in demo mode and real UTC time in live mode.
- Tagging cards with SYNTHETIC or REAL.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from services.bitguard.main import app

client = TestClient(app)


def test_list_backtests_endpoint():
    """GET /v1/backtests returns available backtest datasets."""
    resp = client.get("/v1/backtests")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 3

    ids = [b["id"] for b in data]
    assert "binance-exploit-2026" in ids
    assert "multichain-velocity-spike" in ids
    assert "unauthorized-delegation-7702" in ids


def test_get_backtest_events_endpoint():
    """GET /v1/backtests/{id}/events returns raw signing request events."""
    resp = client.get("/v1/backtests/binance-exploit-2026/events")
    assert resp.status_code == 200
    events = resp.json()
    assert isinstance(events, list)
    assert len(events) > 0
    assert "id" in events[0]
    assert "amount_usd" in events[0]


def test_run_backtest_through_real_engine():
    """POST /v1/backtests/{id}/run streams events through real engine producing real decisions."""
    resp = client.post("/v1/backtests/binance-exploit-2026/run")
    assert resp.status_code == 200
    data = resp.json()

    assert data["backtest_id"] == "binance-exploit-2026"
    assert data["total_events"] > 0
    assert "steps" in data
    assert len(data["steps"]) == data["total_events"]

    first_step = data["steps"][0]
    assert first_step["unprotected_action"] == "allow"
    assert "protected_decision" in first_step
    assert first_step["protected_decision"]["verdict"] in ["ALLOW", "HOLD", "DENY"]
    assert first_step["data_label"] in ["REAL", "SYNTHETIC"]

    assert "summary" in data
    assert data["summary"]["loss_prevented_usd"] >= 0.0


def test_legacy_api_backtests_endpoints():
    """Parity routes /api/backtests and /api/backtests/{id}/run work correctly."""
    resp_list = client.get("/api/backtests")
    assert resp_list.status_code == 200
    assert len(resp_list.json()) >= 3

    resp_run = client.post("/api/backtests/binance-exploit-2026/run")
    assert resp_run.status_code == 200
    assert resp_run.json()["total_events"] > 0


def test_api_client_source_helpers_exported():
    """Both web/api.js and frontend/src/api.ts export backtest and recorded traffic helpers."""
    web_api_path = Path("web/api.js")
    ts_api_path = Path("frontend/src/api.ts")

    assert web_api_path.exists()
    assert ts_api_path.exists()

    web_code = web_api_path.read_text(encoding="utf-8")
    ts_code = ts_api_path.read_text(encoding="utf-8")

    for symbol in ["listBacktests", "runBacktest", "getRecordedDecisions"]:
        assert symbol in web_code, f"web/api.js must export {symbol}"
        assert symbol in ts_code, f"frontend/src/api.ts must export {symbol}"


def test_replay_view_has_source_selector_and_clock_modes():
    """ReplayView contains the 3 required options, clock formatting, and SYNTHETIC/REAL tags."""
    replay_view_path = Path("frontend/src/pages/ReplayView.tsx")
    code = replay_view_path.read_text(encoding="utf-8")

    # Options in source select control
    assert "Built-in scenario" in code
    assert "Imported log" in code
    assert "Recorded live traffic" in code

    # Clock formatting logic (event count in demo mode vs real UTC time in live mode)
    assert "Event " in code
    assert "UTC" in code

    # Card tagging
    assert "SYNTHETIC" in code
    assert "REAL" in code
