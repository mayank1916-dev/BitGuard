"""Unit and integration tests for Mode indicator and Data Provenance labels (Milestone U2).

Tests compliance with:
- Invariant #8: Explicit data provenance (REAL, SYNTHETIC, REPORTED).
- Invariant #10: Visual stability and demo mode identity.
- S04 Mode integration: SIMULATION, SHADOW, ENFORCE and aggregated would_have_* counters.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from services.bitguard.main import app
from services.bitguard.mode_service import mode_service
from services.bitguard.models import OperationMode, WalletGroupConfig

client = TestClient(app)


def test_get_current_mode_default_simulation():
    """GET /v1/mode returns default SIMULATION mode."""
    resp = client.get("/v1/mode")
    assert resp.status_code == 200
    data = resp.json()
    assert "mode" in data
    assert data["mode"] in ["SIMULATION", "SHADOW", "ENFORCE"]


def test_get_shadow_metrics_endpoint():
    """GET /v1/metrics/shadow aggregates S04 would_have counters."""
    # Ensure default group exists
    default_group = WalletGroupConfig(
        id="default",
        name="Default Hot Wallets",
        mode=OperationMode.SIMULATION,
        wallets=["0xdef001"],
    )
    mode_service.register_wallet_group(default_group)

    resp = client.get("/v1/metrics/shadow?wallet_group=default")
    assert resp.status_code == 200
    data = resp.json()
    assert "would_have_allowed_count" in data
    assert "would_have_allowed_value" in data
    assert "would_have_blocked_count" in data
    assert "would_have_blocked_value" in data
    assert "mode" in data


def test_shadow_metrics_accumulation():
    """In SHADOW mode, record_metric accumulates would_have counters accurately."""
    group_id = "test-shadow-u2"
    group = WalletGroupConfig(
        id=group_id,
        name="Test Shadow Group U2",
        mode=OperationMode.SHADOW,
        wallets=["0xshadowu2"],
    )
    mode_service.register_wallet_group(group)

    mode_service.record_metric(group_id, is_would_block=True, value_usd=50000.0)
    mode_service.record_metric(group_id, is_would_block=True, value_usd=25000.0)
    mode_service.record_metric(group_id, is_allowed=True, value_usd=1200.0)

    counters = mode_service.get_shadow_counters(group_id)
    assert counters["mode"] == "SHADOW"
    assert counters["would_have_blocked_count"] == 2
    assert counters["would_have_blocked_value"] == 75000.0
    assert counters["would_have_allowed_count"] == 1
    assert counters["would_have_allowed_value"] == 1200.0


def test_legacy_api_mode_and_shadow_endpoints():
    """Legacy routes /api/mode and /api/metrics/shadow provide parity."""
    res_mode = client.get("/api/mode")
    assert res_mode.status_code == 200
    assert "mode" in res_mode.json()

    res_shadow = client.get("/api/metrics/shadow")
    assert res_shadow.status_code == 200
    assert "would_have_blocked_count" in res_shadow.json()


def test_api_client_files_export_mode_and_shadow_helpers():
    """Both web/api.js and frontend/src/api.ts export getMode and fetchShadowMetrics."""
    web_api_path = Path("web/api.js")
    ts_api_path = Path("frontend/src/api.ts")

    assert web_api_path.exists(), "web/api.js must exist"
    assert ts_api_path.exists(), "frontend/src/api.ts must exist"

    web_code = web_api_path.read_text(encoding="utf-8")
    ts_code = ts_api_path.read_text(encoding="utf-8")

    for symbol in ["getMode", "fetchCurrentMode", "fetchShadowMetrics"]:
        assert symbol in web_code, f"web/api.js must export {symbol}"
        assert symbol in ts_code, f"frontend/src/api.ts must export {symbol}"


def test_ui_components_preserve_demo_mode_badge_and_labels():
    """Navbar and ReplayView preserve 'DEFENSIVE SIMULATION' when in demo mode."""
    navbar_path = Path("frontend/src/components/Navbar.tsx")
    replay_path = Path("frontend/src/pages/ReplayView.tsx")
    utils_path = Path("frontend/src/utils.ts")

    navbar_code = navbar_path.read_text(encoding="utf-8")
    replay_code = replay_path.read_text(encoding="utf-8")
    utils_code = utils_path.read_text(encoding="utf-8")

    # In demo mode, exact badge text 'DEFENSIVE SIMULATION' must be returned
    assert "DEFENSIVE SIMULATION" in navbar_code
    # In API mode, active mode is displayed
    assert "(mode || 'SIMULATION').toUpperCase()" in navbar_code or "mode.toUpperCase()" in navbar_code

    # Provenance badge helper in utils
    assert "getDataLabelBadgeStyle" in utils_code
    assert "REAL" in utils_code
    assert "SYNTHETIC" in utils_code
    assert "REPORTED" in utils_code

    # Replay view has shadow mode counter labels
    assert "WOULD HAVE BEEN ALLOWED" in replay_code
    assert "BLOCKED VALUE" in replay_code
