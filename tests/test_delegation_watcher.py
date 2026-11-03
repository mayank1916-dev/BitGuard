"""Comprehensive unit and integration tests for Delegation Watcher (Milestone S17 / F6).

Invariants & Requirements:
- WatchedAddress CRUD: SecOps can create/update/delete; Operator can view; Operator cannot create (403).
- Multi-provider eth_getCode consensus: disagreement => alert PROVIDER_DISAGREEMENT and suspicious.
- EIP-7702 delegation check: code starting with 0xef0100 and length 23 bytes extracts delegate;
  unallowlisted code hash => severity CRITICAL.
- Type-4 block transactions scan naming a watched address => alert.
- Unexpected nonce jump versus BitGuard signed count => CRITICAL alert and breaker trips to HOLD.
- On CRITICAL: trips breaker to HOLD, emits stream event, appends audit entry, measures latency.
- Clean address => no alert.
- Benign allowlisted delegate => no alert.
- Measure and log detection latency in blocks and seconds.
"""


import pytest
from fastapi.testclient import TestClient

from services.bitguard.audit_service import audit_service
from services.bitguard.engine.breaker_store import breaker_store
from services.bitguard.main import app
from services.bitguard.models import (
    BreakerStateEnum,
    CreateWatchedAddressRequest,
    Role,
)
from services.bitguard.rbac import ALL_TEST_USERS, SEEDED_USERS, create_access_token
from services.bitguard.rpc.client import MockRpcClient
from services.bitguard.rules.delegation import compute_code_hash
from services.bitguard.watcher.provider_pool import provider_pool
from services.bitguard.watcher.store import watched_address_store
from services.bitguard.watcher.worker import delegation_watcher

client = TestClient(app)

# Benign test addresses and bytecode (test contracts only, no attack code)
WATCHED_HOT_WALLET = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
BENIGN_DELEGATE_ADDR = "0x1111111111111111111111111111111111111111"
BENIGN_DELEGATE_BYTECODE = "0x602a60005260206000f3"  # Returns 42

UNAPPROVED_DELEGATE_ADDR = "0x9999999999999999999999999999999999999999"
UNAPPROVED_DELEGATE_BYTECODE = "0x600160005260206000f3"

# Construct canonical EIP-7702 delegation bytecode: 0xef0100 + 20 bytes delegate address
BENIGN_7702_DESIGNATOR = "0xef0100" + BENIGN_DELEGATE_ADDR[2:].lower()
UNAPPROVED_7702_DESIGNATOR = "0xef0100" + UNAPPROVED_DELEGATE_ADDR[2:].lower()


@pytest.fixture(autouse=True)
def setup_watcher_test_environment():
    """Sets up isolated in-memory stores and mock RPC providers for each test."""
    watched_address_store.clear()
    breaker_store.reset()

    # Create two mock RPC providers for multi-provider consensus testing
    mock_rpc_1 = MockRpcClient()
    mock_rpc_2 = MockRpcClient()

    # Pre-deploy test contracts
    mock_rpc_1.set_contract(BENIGN_DELEGATE_ADDR, BENIGN_DELEGATE_BYTECODE)
    mock_rpc_2.set_contract(BENIGN_DELEGATE_ADDR, BENIGN_DELEGATE_BYTECODE)

    mock_rpc_1.set_contract(UNAPPROVED_DELEGATE_ADDR, UNAPPROVED_DELEGATE_BYTECODE)
    mock_rpc_2.set_contract(UNAPPROVED_DELEGATE_ADDR, UNAPPROVED_DELEGATE_BYTECODE)

    # Configure provider pool with both providers
    provider_pool.providers = [
        ("node_primary", mock_rpc_1),
        ("node_secondary", mock_rpc_2),
    ]

    yield

    watched_address_store.clear()
    breaker_store.reset()


def get_auth_header(role: Role = Role.SECOPS, user_id: str | None = None) -> dict[str, str]:
    """Helper generating Bearer Authorization header for test users."""
    user = ALL_TEST_USERS.get(user_id) if user_id else SEEDED_USERS[role]
    assert user is not None
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


# =========================================================================
# TEST 1: Clean Address => No Alert
# =========================================================================


def test_clean_address_generates_no_alert():
    """A monitored hot wallet with clean bytecode (empty/EOA 0x) generates no alerts."""
    benign_code_hash = compute_code_hash(BENIGN_DELEGATE_BYTECODE)
    watched_address_store.create(
        CreateWatchedAddressRequest(
            address=WATCHED_HOT_WALLET,
            chain="ethereum",
            label="Primary Hot Wallet",
            allowed_delegates=[benign_code_hash],
        )
    )

    alerts = delegation_watcher.scan_block(block_number=100)
    assert len(alerts) == 0
    assert breaker_store.get_state() == BreakerStateEnum.NORMAL


# =========================================================================
# TEST 2: Benign Allowlisted Delegate => No Alert
# =========================================================================


def test_allowlisted_delegate_generates_no_alert():
    """An address set to an allowlisted EIP-7702 delegate contract generates no alert."""
    benign_code_hash = compute_code_hash(BENIGN_DELEGATE_BYTECODE)
    watched_address_store.create(
        CreateWatchedAddressRequest(
            address=WATCHED_HOT_WALLET,
            chain="ethereum",
            label="Primary Hot Wallet",
            allowed_delegates=[benign_code_hash],
        )
    )

    # Simulate 7702 delegation on both nodes to benign delegate
    for _, client_rpc in provider_pool.providers:
        assert isinstance(client_rpc, MockRpcClient)
        client_rpc.set_contract(WATCHED_HOT_WALLET, BENIGN_7702_DESIGNATOR)

    alerts = delegation_watcher.scan_block(block_number=101)
    assert len(alerts) == 0
    assert breaker_store.get_state() == BreakerStateEnum.NORMAL


# =========================================================================
# TEST 3: Non-Allowlisted Delegate => CRITICAL Alert & Breaker Trips to HOLD
# =========================================================================


def test_unallowlisted_delegate_triggers_critical_and_trips_breaker():
    """An address delegated to an unallowlisted contract triggers CRITICAL alert and trips breaker."""
    benign_code_hash = compute_code_hash(BENIGN_DELEGATE_BYTECODE)
    watched_address_store.create(
        CreateWatchedAddressRequest(
            address=WATCHED_HOT_WALLET,
            chain="ethereum",
            label="Primary Hot Wallet",
            allowed_delegates=[benign_code_hash],  # UNAPPROVED_DELEGATE is not in allowlist
        )
    )

    # Set 7702 delegation on both nodes pointing to the unapproved contract
    for _, client_rpc in provider_pool.providers:
        assert isinstance(client_rpc, MockRpcClient)
        client_rpc.set_contract(WATCHED_HOT_WALLET, UNAPPROVED_7702_DESIGNATOR)

    alerts = delegation_watcher.scan_block(block_number=102)

    # Verify CRITICAL alert
    assert len(alerts) == 1
    crit_alert = alerts[0]
    assert crit_alert.alert_code == "UNAUTHORIZED_DELEGATION"
    assert crit_alert.severity == "CRITICAL"
    assert crit_alert.address.lower() == WATCHED_HOT_WALLET.lower()
    assert crit_alert.breaker_tripped is True

    # Invariant #6: Circuit breaker tripped to HOLD immediately
    assert breaker_store.get_state() == BreakerStateEnum.HOLD

    # Invariant #7: Tamper-evident audit entry appended
    recent_audit = audit_service.get_entries()[-5:]
    audit_event_types = [e.event_type for e in recent_audit]
    assert any("WATCHER_CRITICAL" in evt for evt in audit_event_types)

    # Latency measurement verified
    assert crit_alert.latency_blocks >= 0
    assert crit_alert.latency_seconds >= 0.0


# =========================================================================
# TEST 4: Provider Disagreement => Alert & Treated as Suspicious
# =========================================================================


def test_provider_disagreement_triggers_alert():
    """When RPC providers return conflicting bytecode for the same address, an alert is raised."""
    watched_address_store.create(
        CreateWatchedAddressRequest(
            address=WATCHED_HOT_WALLET,
            chain="ethereum",
            label="Primary Hot Wallet",
            allowed_delegates=[],
        )
    )

    # Provider 1 sees empty EOA (0x)
    assert isinstance(provider_pool.providers[0][1], MockRpcClient)
    provider_pool.providers[0][1].set_contract(WATCHED_HOT_WALLET, "0x")

    # Provider 2 sees unexpected contract code (conflict / split brain / eclipse attack)
    assert isinstance(provider_pool.providers[1][1], MockRpcClient)
    provider_pool.providers[1][1].set_contract(WATCHED_HOT_WALLET, "0x6080604052")

    alerts = delegation_watcher.scan_block(block_number=103)

    disagree_alerts = [a for a in alerts if a.alert_code == "PROVIDER_DISAGREEMENT"]
    assert len(disagree_alerts) == 1
    alert = disagree_alerts[0]
    assert alert.severity == "HIGH"
    assert "node_primary" in alert.details["provider_results"]
    assert "node_secondary" in alert.details["provider_results"]


# =========================================================================
# TEST 5: Type-4 Block Transactions Scan Naming Watched Address
# =========================================================================


def test_type4_block_transaction_with_unapproved_delegate_triggers_critical():
    """A block containing a Type 4 transaction authorizing an unapproved delegate is detected."""
    watched_address_store.create(
        CreateWatchedAddressRequest(
            address=WATCHED_HOT_WALLET,
            chain="ethereum",
            label="Primary Hot Wallet",
            allowed_delegates=[BENIGN_DELEGATE_ADDR],
        )
    )

    # Add a block containing a type-4 transaction naming WATCHED_HOT_WALLET
    mock_primary = provider_pool.providers[0][1]
    assert isinstance(mock_primary, MockRpcClient)

    mock_primary.add_block(
        number=104,
        timestamp=1730001000.0,
        transactions=[
            {
                "hash": "0xtxhash7702-unauth",
                "type": "0x04",
                "from": "0xattacker11111111111111111111111111111111",
                "authorizationList": [
                    {
                        "chainId": "0x1",
                        "address": UNAPPROVED_DELEGATE_ADDR,
                        "nonce": "0x1",
                        "authority": WATCHED_HOT_WALLET,
                    }
                ],
            }
        ],
    )

    alerts = delegation_watcher.scan_block(block_number=104)
    type4_alerts = [a for a in alerts if a.alert_code == "UNAUTHORIZED_TYPE4_AUTHORIZATION"]
    assert len(type4_alerts) == 1
    assert type4_alerts[0].severity == "CRITICAL"
    assert breaker_store.get_state() == BreakerStateEnum.HOLD


# =========================================================================
# TEST 6: Unexpected Nonce Jump Detection
# =========================================================================


def test_unexpected_nonce_jump_triggers_critical():
    """An unexpected advance in on-chain transaction count triggers CRITICAL alert and trips breaker."""
    watched = watched_address_store.create(
        CreateWatchedAddressRequest(
            address=WATCHED_HOT_WALLET,
            chain="ethereum",
            label="Primary Hot Wallet",
            initial_nonce=5,
        )
    )
    # BitGuard has recorded 2 signed transactions (expected max nonce = 5 + 2 = 7)
    watched.signed_count = 2

    # Simulate that on-chain nonce jumped to 10 (3 unauthorized transactions occurred off-band)
    mock_primary = provider_pool.providers[0][1]
    assert isinstance(mock_primary, MockRpcClient)
    mock_primary.set_nonce(WATCHED_HOT_WALLET, 10)

    alerts = delegation_watcher.scan_block(block_number=105)
    nonce_alerts = [a for a in alerts if a.alert_code == "UNEXPECTED_NONCE_JUMP"]
    assert len(nonce_alerts) == 1
    alert = nonce_alerts[0]
    assert alert.severity == "CRITICAL"
    assert alert.details["on_chain_nonce"] == 10
    assert alert.details["expected_max_nonce"] == 7
    assert alert.details["jump_size"] == 3
    assert breaker_store.get_state() == BreakerStateEnum.HOLD


# =========================================================================
# TEST 7: WatchedAddress CRUD and RBAC Access Control
# =========================================================================


def test_watched_address_crud_and_rbac():
    """SecOps can create/update/delete; Operator can view; Operator cannot create."""
    secops_headers = get_auth_header(Role.SECOPS)
    operator_headers = get_auth_header(Role.OPERATOR)

    # 1. SecOps creates watched address -> 201 Created
    create_payload = {
        "address": "0x5555555555555555555555555555555555555555",
        "chain": "ethereum",
        "label": "Cold Reserve Staging",
        "allowed_delegates": ["0x1111111111111111111111111111111111111111"],
        "initial_nonce": 0,
    }
    resp_create = client.post("/v1/watched-addresses", json=create_payload, headers=secops_headers)
    assert resp_create.status_code == 201
    created_id = resp_create.json()["id"]

    # 2. Operator can view watched addresses -> 200 OK
    resp_list = client.get("/v1/watched-addresses", headers=operator_headers)
    assert resp_list.status_code == 200
    addresses = [a["address"].lower() for a in resp_list.json()]
    assert "0x5555555555555555555555555555555555555555" in addresses

    # 3. Operator attempts to create watched address -> 403 Forbidden
    resp_unauth = client.post(
        "/v1/watched-addresses",
        json={
            "address": "0x6666666666666666666666666666666666666666",
            "chain": "ethereum",
            "label": "Unauthorized Test",
        },
        headers=operator_headers,
    )
    assert resp_unauth.status_code == 403

    # 4. SecOps updates configuration -> 200 OK
    resp_update = client.put(
        f"/v1/watched-addresses/{created_id}",
        json={"label": "Updated Cold Staging"},
        headers=secops_headers,
    )
    assert resp_update.status_code == 200
    assert resp_update.json()["label"] == "Updated Cold Staging"

    # 5. SecOps deletes watched address -> 200 OK
    resp_delete = client.delete(f"/v1/watched-addresses/{created_id}", headers=secops_headers)
    assert resp_delete.status_code == 200
    assert resp_delete.json()["status"] == "deleted"


# =========================================================================
# TEST 8: Live Breaker State Endpoint Reflects Breaker Trips
# =========================================================================


def test_breaker_endpoint_reflects_trip_to_hold():
    """GET /v1/breaker reflects HOLD state when tripped by watcher."""
    headers = get_auth_header(Role.VIEWER)

    # Initial state is NORMAL
    resp1 = client.get("/v1/breaker", headers=headers)
    assert resp1.status_code == 200
    assert resp1.json()["state"] == "NORMAL"

    # Trip breaker
    breaker_store.set_state(BreakerStateEnum.HOLD, reason="Test trip")

    # Breaker endpoint reflects HOLD
    resp2 = client.get("/v1/breaker", headers=headers)
    assert resp2.status_code == 200
    assert resp2.json()["state"] == "HOLD"
    assert "HOLD" in resp2.json()["reason"]
