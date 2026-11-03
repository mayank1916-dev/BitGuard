"""Comprehensive test suite for Task U7 - 7702 Radar & 'My addresses' panel.

Invariants and Requirements:
- Keep existing public scan.
- Add 'My addresses' panel with:
  - Watched addresses with delegation state ('none', 'allowed delegate', 'UNAPPROVED')
  - Delegate address and code hash if any
  - Last block checked
  - Provider agreement status ('all agree' / 'disagree')
  - Recent alerts with detection latency
- SecOps can add or remove addresses; Operator is read-only (403 on add/remove).
- Data from watcher API; demo mode provides sample data.
- Strict visual stability and provenance labels (AGENTS.md Invariant #8, #10).
"""

from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from services.bitguard.main import app
from services.bitguard.models import Role, WatcherAlert
from services.bitguard.rbac import SEEDED_USERS, create_access_token
from services.bitguard.watcher.store import watched_address_store
from services.bitguard.watcher.worker import delegation_watcher

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_watcher_store() -> Generator[None, None, None]:
    """Ensures a clean watcher store and alerts list for every test."""
    watched_address_store.clear()
    watched_address_store._seed_default_addresses()
    delegation_watcher.recent_alerts.clear()
    delegation_watcher.last_scanned_block = 21000500
    yield
    watched_address_store.clear()
    watched_address_store._seed_default_addresses()
    delegation_watcher.recent_alerts.clear()


def get_token_for_role(role: Role) -> str:
    user = SEEDED_USERS[role]
    return create_access_token(user)


def test_get_watched_addresses_operator_read() -> None:
    """Operator can view watched addresses with delegation states and consensus."""
    token = get_token_for_role(Role.OPERATOR)
    res = client.get("/v1/watched-addresses", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 3

    # Check structure of seeded items
    for item in data:
        assert "id" in item
        assert "address" in item
        assert "delegation_state" in item
        assert item["delegation_state"] in ["none", "allowed delegate", "UNAPPROVED"]
        assert "provider_agreement" in item
        assert item["provider_agreement"] in ["all agree", "disagree"]
        assert "last_scanned_block" in item
        assert "recent_alerts" in item


def test_secops_can_create_and_delete_watched_address() -> None:
    """SecOps can register and delete a monitored hot wallet address."""
    secops_token = get_token_for_role(Role.SECOPS)
    new_addr = "0x5555555555555555555555555555555555555555"

    create_res = client.post(
        "/v1/watched-addresses",
        json={
            "address": new_addr,
            "label": "SecOps Treasury Sub-Account",
            "chain": "ethereum-mainnet",
            "allowed_delegates": [],
            "notify_on_delegation": True,
        },
        headers={"Authorization": f"Bearer {secops_token}"},
    )
    assert create_res.status_code == 201
    created_id = create_res.json()["id"]

    # Verify presence in list
    list_res = client.get("/v1/watched-addresses", headers={"Authorization": f"Bearer {secops_token}"})
    assert list_res.status_code == 200
    items = list_res.json()
    assert any(x["id"] == created_id for x in items)

    # Delete as SecOps
    del_res = client.delete(
        f"/v1/watched-addresses/{created_id}",
        headers={"Authorization": f"Bearer {secops_token}"},
    )
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "deleted"

    # Verify removed
    get_res = client.get(
        f"/v1/watched-addresses/{created_id}",
        headers={"Authorization": f"Bearer {secops_token}"},
    )
    assert get_res.status_code == 404


def test_operator_forbidden_from_create_and_delete() -> None:
    """Operator role is read-only and cannot add or remove monitored addresses."""
    operator_token = get_token_for_role(Role.OPERATOR)

    # Attempt create
    create_res = client.post(
        "/v1/watched-addresses",
        json={
            "address": "0x4444444444444444444444444444444444444444",
            "label": "Unauthorized Add",
            "chain": "ethereum-sepolia",
        },
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert create_res.status_code == 403

    # Attempt delete on first seeded item
    secops_token = get_token_for_role(Role.SECOPS)
    list_res = client.get("/v1/watched-addresses", headers={"Authorization": f"Bearer {secops_token}"})
    first_id = list_res.json()[0]["id"]

    del_res = client.delete(
        f"/v1/watched-addresses/{first_id}",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert del_res.status_code == 403


def test_unapproved_delegation_alert_enriches_address() -> None:
    """When an unapproved delegation is detected, delegation_state is UNAPPROVED with delegate info and latency."""
    token = get_token_for_role(Role.SECOPS)
    list_res = client.get("/v1/watched-addresses", headers={"Authorization": f"Bearer {token}"})
    target_addr = list_res.json()[0]["address"]

    # Inject simulated CRITICAL alert
    test_alert = WatcherAlert(
        id="alert-test-unapproved-01",
        chain="ethereum",
        alert_code="UNAPPROVED_7702_DELEGATION",
        severity="CRITICAL",
        address=target_addr,
        block_number=21000505,
        block_timestamp=1700000000.0,
        details={
            "delegate": "0xbad0000000000000000000000000000000000bad",
            "delegate_code_hash": "0x" + "aa" * 32,
            "message": "Unapproved 7702 delegation detected",
        },
        latency_blocks=1,
        latency_seconds=0.0125,
    )
    delegation_watcher.recent_alerts.append(test_alert)

    # Query enriched addresses
    updated_res = client.get("/v1/watched-addresses", headers={"Authorization": f"Bearer {token}"})
    assert updated_res.status_code == 200
    matched = next(x for x in updated_res.json() if x["address"].lower() == target_addr.lower())

    assert matched["delegation_state"] == "UNAPPROVED"
    assert matched["delegate_address"] == "0xbad0000000000000000000000000000000000bad"
    assert matched["delegate_code_hash"] == "0x" + "aa" * 32
    assert len(matched["recent_alerts"]) >= 1
    assert matched["recent_alerts"][0]["latency_seconds"] == 0.0125
    assert matched["recent_alerts"][0]["latency_blocks"] == 1


def test_provider_disagreement_alert_sets_status() -> None:
    """Provider divergence sets provider_agreement to 'disagree'."""
    token = get_token_for_role(Role.SECOPS)
    list_res = client.get("/v1/watched-addresses", headers={"Authorization": f"Bearer {token}"})
    target_addr = list_res.json()[1]["address"]

    # Inject provider disagreement alert
    test_alert = WatcherAlert(
        id="alert-test-disagreement-01",
        chain="ethereum",
        alert_code="PROVIDER_DISAGREEMENT",
        severity="MEDIUM",
        address=target_addr,
        block_number=21000508,
        block_timestamp=1700000000.0,
        details={"message": "RPC nodes disagreed on code hash"},
        latency_blocks=1,
        latency_seconds=0.0084,
    )
    delegation_watcher.recent_alerts.append(test_alert)

    updated_res = client.get("/v1/watched-addresses", headers={"Authorization": f"Bearer {token}"})
    assert updated_res.status_code == 200
    matched = next(x for x in updated_res.json() if x["address"].lower() == target_addr.lower())

    assert matched["provider_agreement"] == "disagree"


def test_watcher_alerts_endpoint() -> None:
    """GET /v1/watcher/alerts returns recent alerts list."""
    token = get_token_for_role(Role.OPERATOR)
    test_alert = WatcherAlert(
        id="alert-test-nonce-01",
        chain="ethereum",
        alert_code="UNEXPECTED_NONCE_JUMP",
        severity="CRITICAL",
        address="0x1234567890123456789012345678901234567890",
        block_number=21000510,
        block_timestamp=1700000000.0,
        details={"message": "Nonce jump detected"},
        latency_blocks=1,
        latency_seconds=0.015,
    )
    delegation_watcher.recent_alerts.append(test_alert)

    res = client.get("/v1/watcher/alerts", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    alerts = res.json()
    assert len(alerts) >= 1
    assert any(a["alert_code"] == "UNEXPECTED_NONCE_JUMP" for a in alerts)


def test_ui_radar_source_code_invariants() -> None:
    """Verifies UI components, API methods, and visual stability constraints for Task U7."""
    root_dir = Path(__file__).resolve().parent.parent

    # 1. Frontend RadarView.tsx
    radar_file = root_dir / "frontend" / "src" / "pages" / "RadarView.tsx"
    assert radar_file.exists(), "frontend/src/pages/RadarView.tsx must exist"
    radar_content = radar_file.read_text(encoding="utf-8")

    # Invariant: Sub-nav toggle between 'My addresses' and 'Public Block Scanner'
    assert "My Addresses" in radar_content
    assert "Public Block Scanner" in radar_content
    assert "my_addresses" in radar_content

    # Invariant: Delegation state badges
    assert "allowed delegate" in radar_content
    assert "UNAPPROVED" in radar_content
    assert "none" in radar_content

    # Invariant: Provider agreement status
    assert "all agree" in radar_content
    assert "disagree" in radar_content

    # Invariant: Latency display
    assert "latency_seconds" in radar_content or "ms" in radar_content

    # Invariant: SecOps controls (Add / Remove)
    assert "Add Monitored Address" in radar_content or "Add Address" in radar_content
    assert "createWatchedAddress" in radar_content
    assert "deleteWatchedAddress" in radar_content
    assert "canManageAddresses" in radar_content

    # Invariant: Strict wording ("reduces and contains")
    assert "reduces and contains" in radar_content

    # 2. Frontend API client (frontend/src/api.ts)
    api_ts = root_dir / "frontend" / "src" / "api.ts"
    api_ts_content = api_ts.read_text(encoding="utf-8")
    assert "fetchWatchedAddresses" in api_ts_content
    assert "createWatchedAddress" in api_ts_content
    assert "deleteWatchedAddress" in api_ts_content
    assert "fetchWatcherAlerts" in api_ts_content

    # 3. Web API client (web/api.js)
    web_api = root_dir / "web" / "api.js"
    web_api_content = web_api.read_text(encoding="utf-8")
    assert "fetchWatchedAddresses" in web_api_content
    assert "createWatchedAddress" in web_api_content
    assert "deleteWatchedAddress" in web_api_content
    assert "fetchWatcherAlerts" in web_api_content
