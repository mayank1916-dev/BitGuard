"""Tests for EIP-7702 delegation guard policy, proxy rejection, and RPC resolution (Milestone S09)."""

import pytest
from fastapi.testclient import TestClient

from services.bitguard.main import app
from services.bitguard.mode_service import mode_service
from services.bitguard.models import AuthorizationItem, DecodedTx, FeeDetail
from services.bitguard.rpc.client import MockRpcClient
from services.bitguard.rules.delegation import (
    EIP1967_IMPLEMENTATION_SLOT,
    DelegationPolicy,
    check_delegations,
    compute_code_hash,
    has_delegatecall_opcode,
)

client = TestClient(app)

# Benign test bytecode samples (test contracts only, no attack code)
# 1. Simple benign delegate: returns 42 (PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN)
BENIGN_SIMPLE_CODE = "0x602a60005260206000f3"

# 2. Proxy delegate with DELEGATECALL opcode (0xF4)
BENIGN_PROXY_DELEGATECALL_CODE = (
    "0x36600080376000803660007311111111111111111111111111111111111111115af43d6000803e80602057fd5bf3"
)

# 3. Proxy implementation pointer storage value (32 bytes)
MOCK_IMPLEMENTATION_ADDRESS = "0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

OWNED_CUSTODY_WALLET = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
SIMPLE_DELEGATE_ADDR = "0x1111111111111111111111111111111111111111"
PROXY_DELEGATE_ADDR = "0x2222222222222222222222222222222222222222"
UNAPPROVED_DELEGATE_ADDR = "0x3333333333333333333333333333333333333333"


@pytest.fixture
def mock_rpc():
    """Provides an isolated MockRpcClient populated with test contracts."""
    rpc = MockRpcClient()
    # Deploy simple benign contract
    rpc.set_contract(SIMPLE_DELEGATE_ADDR, BENIGN_SIMPLE_CODE)
    # Deploy proxy contract with DELEGATECALL
    rpc.set_contract(PROXY_DELEGATE_ADDR, BENIGN_PROXY_DELEGATECALL_CODE)
    # Deploy unapproved contract
    rpc.set_contract(UNAPPROVED_DELEGATE_ADDR, "0x600160005260206000f3")
    return rpc


@pytest.fixture
def delegation_policy():
    """Provides a baseline DelegationPolicy with owned custody addresses."""
    policy = DelegationPolicy(
        owned_addresses={OWNED_CUSTODY_WALLET},
        delegate_allowlist={},
    )
    # Allowlist simple benign contract by code hash
    simple_hash = compute_code_hash(BENIGN_SIMPLE_CODE)
    policy.add_allowed_delegate(
        code_hash=simple_hash,
        name="BenignSimpleDelegate",
        reviewed_proxy_ok=False,
    )
    return policy


def test_evm_opcode_parser_detects_delegatecall():
    """Verify EVM opcode inspector detects DELEGATECALL and skips PUSH operand data."""
    # 1. Bytecode with DELEGATECALL (0xF4)
    proxy_bytes = bytes.fromhex(BENIGN_PROXY_DELEGATECALL_CODE[2:])
    assert has_delegatecall_opcode(proxy_bytes)

    # 2. Bytecode without DELEGATECALL
    simple_bytes = bytes.fromhex(BENIGN_SIMPLE_CODE[2:])
    assert not has_delegatecall_opcode(simple_bytes)

    # 3. Bytecode with PUSH1 0xF4 (immediate data 0xF4, not an executable opcode)
    # PUSH1 0xF4 PUSH1 0x00 MSTORE RETURN -> 60f460005260206000f3
    push_f4_data = bytes.fromhex("60f460005260206000f3")
    assert not has_delegatecall_opcode(push_f4_data), "Operand byte 0xF4 inside PUSH1 must not be flagged"


def test_allowed_simple_delegate_passes_and_emits_alert(mock_rpc, delegation_policy):
    """Rule 1 & 4: Allowed delegate code hash passes and emits a high-severity alert for owned address."""
    tx = DecodedTx(
        chain="ethereum",
        from_address=OWNED_CUSTODY_WALLET,
        to_address=OWNED_CUSTODY_WALLET,
        asset="ETH",
        amount="0",
        calls=[],
        authorizations=[
            AuthorizationItem(
                chain_id=1,
                address=SIMPLE_DELEGATE_ADDR,
                nonce=0,
                authority=OWNED_CUSTODY_WALLET,
            )
        ],
        fee=FeeDetail(),
        digest="0x1234",
    )

    result = check_delegations(tx, delegation_policy, mock_rpc)
    assert result.passed
    assert result.is_alert
    assert result.alert_severity == "HIGH"
    assert "owned custody address" in (result.alert_message or "")


def test_unapproved_delegate_denied(mock_rpc, delegation_policy):
    """Rule 1: Delegate whose code hash is not in allowlist is denied with DELEGATION_OWNED_ADDRESS."""
    tx = DecodedTx(
        chain="ethereum",
        from_address=OWNED_CUSTODY_WALLET,
        to_address=OWNED_CUSTODY_WALLET,
        asset="ETH",
        amount="0",
        calls=[],
        authorizations=[
            AuthorizationItem(
                chain_id=1,
                address=UNAPPROVED_DELEGATE_ADDR,
                nonce=0,
                authority=OWNED_CUSTODY_WALLET,
            )
        ],
        fee=FeeDetail(),
        digest="0x1234",
    )

    result = check_delegations(tx, delegation_policy, mock_rpc)
    assert not result.passed
    assert result.code == "DELEGATION_OWNED_ADDRESS"
    assert "not in delegate_allowlist" in (result.detail or "")


def test_proxy_delegatecall_rejected_unless_reviewed_proxy_ok(mock_rpc, delegation_policy):
    """Rule 3: Delegate with DELEGATECALL is rejected unless explicitly marked reviewed_proxy_ok."""
    proxy_hash = compute_code_hash(BENIGN_PROXY_DELEGATECALL_CODE)

    # Allowlist the proxy code hash, but with reviewed_proxy_ok = False
    delegation_policy.add_allowed_delegate(
        code_hash=proxy_hash,
        name="BenignProxyUnreviewed",
        reviewed_proxy_ok=False,
    )

    tx = DecodedTx(
        chain="ethereum",
        from_address=OWNED_CUSTODY_WALLET,
        to_address=OWNED_CUSTODY_WALLET,
        asset="ETH",
        amount="0",
        calls=[],
        authorizations=[
            AuthorizationItem(
                chain_id=1,
                address=PROXY_DELEGATE_ADDR,
                nonce=0,
                authority=OWNED_CUSTODY_WALLET,
            )
        ],
        fee=FeeDetail(),
        digest="0x1234",
    )

    # Case A: reviewed_proxy_ok = False -> DENIED
    res_deny = check_delegations(tx, delegation_policy, mock_rpc)
    assert not res_deny.passed
    assert res_deny.code == "DELEGATION_UPGRADEABLE_PROXY"
    assert "DELEGATECALL" in (res_deny.detail or "")

    # Case B: reviewed_proxy_ok = True -> ALLOWED
    delegation_policy.add_allowed_delegate(
        code_hash=proxy_hash,
        name="BenignProxyReviewed",
        reviewed_proxy_ok=True,
    )
    res_allow = check_delegations(tx, delegation_policy, mock_rpc)
    assert res_allow.passed


def test_proxy_eip1967_slot_rejected(mock_rpc, delegation_policy):
    """Rule 3: Delegate with non-zero EIP-1967 implementation slot is rejected."""
    # Deploy contract with simple code, but with non-zero EIP-1967 slot
    slot_proxy_addr = "0x4444444444444444444444444444444444444444"
    mock_rpc.set_contract(
        slot_proxy_addr,
        BENIGN_SIMPLE_CODE,
        storage={EIP1967_IMPLEMENTATION_SLOT: MOCK_IMPLEMENTATION_ADDRESS},
    )

    tx = DecodedTx(
        chain="ethereum",
        from_address=OWNED_CUSTODY_WALLET,
        to_address=OWNED_CUSTODY_WALLET,
        asset="ETH",
        amount="0",
        calls=[],
        authorizations=[
            AuthorizationItem(
                chain_id=1,
                address=slot_proxy_addr,
                nonce=0,
                authority=OWNED_CUSTODY_WALLET,
            )
        ],
        fee=FeeDetail(),
        digest="0x1234",
    )

    res = check_delegations(tx, delegation_policy, mock_rpc)
    assert not res.passed
    assert res.code == "DELEGATION_UPGRADEABLE_PROXY"
    assert "EIP-1967 implementation slot" in (res.detail or "")


def test_rpc_failure_fails_closed(mock_rpc, delegation_policy):
    """Rule 5: RPC failure while querying contract bytecode fails closed with DELEGATION_RPC_FAILURE."""
    mock_rpc.set_fail_rpc(True, "Node connection timeout")

    tx = DecodedTx(
        chain="ethereum",
        from_address=OWNED_CUSTODY_WALLET,
        to_address=OWNED_CUSTODY_WALLET,
        asset="ETH",
        amount="0",
        calls=[],
        authorizations=[
            AuthorizationItem(
                chain_id=1,
                address=SIMPLE_DELEGATE_ADDR,
                nonce=0,
                authority=OWNED_CUSTODY_WALLET,
            )
        ],
        fee=FeeDetail(),
        digest="0x1234",
    )

    res = check_delegations(tx, delegation_policy, mock_rpc)
    assert not res.passed
    assert res.code == "DELEGATION_RPC_FAILURE"
    assert "RPC error" in (res.detail or "")


def test_unowned_authority_delegation_passes_unrestricted(mock_rpc, delegation_policy):
    """Delegations by unowned external authorities are not restricted by internal custody allowlist."""
    external_wallet = "0x9999999999999999999999999999999999999999"
    tx = DecodedTx(
        chain="ethereum",
        from_address=external_wallet,
        to_address=external_wallet,
        asset="ETH",
        amount="0",
        calls=[],
        authorizations=[
            AuthorizationItem(
                chain_id=1,
                address=UNAPPROVED_DELEGATE_ADDR,
                nonce=0,
                authority=external_wallet,
            )
        ],
        fee=FeeDetail(),
        digest="0x1234",
    )

    res = check_delegations(tx, delegation_policy, mock_rpc)
    assert res.passed
    assert not res.is_alert


def test_mode_service_delegation_guard_pipeline_integration(mock_rpc, delegation_policy):
    """Verify full evaluate pipeline rejects disallowed delegation and allows approved delegate."""
    mode_service.set_rpc_client(mock_rpc)
    mode_service.set_delegation_policy(delegation_policy)

    # 1. Unapproved delegate request
    disallowed_payload = {
        "id": "req-del-deny",
        "raw_tx": "0x04f870",  # Mock Type-4 tx envelope
        "chain": "ethereum",
        "wallet": OWNED_CUSTODY_WALLET,
        "metadata": {
            "require_delegation_check": True,
            "decoded_tx": {
                "chain": "ethereum",
                "from": OWNED_CUSTODY_WALLET,
                "to": OWNED_CUSTODY_WALLET,
                "asset": "ETH",
                "amount": "0",
                "calls": [],
                "authorizations": [
                    {
                        "chain_id": 1,
                        "address": UNAPPROVED_DELEGATE_ADDR,
                        "nonce": 0,
                        "authority": OWNED_CUSTODY_WALLET,
                    }
                ],
                "fee": {},
                "digest": "0x5678",
            },
        },
    }

    res_deny = client.post("/v1/evaluate", json=disallowed_payload)
    assert res_deny.status_code == 200
    data_deny = res_deny.json()
    assert data_deny["verdict"] == "DENY"
    assert data_deny["reasons"][0]["code"] == "DELEGATION_OWNED_ADDRESS"

    # 2. Approved delegate request
    allowed_payload = {
        "id": "req-del-allow",
        "raw_tx": "0x04f870",
        "chain": "ethereum",
        "wallet": OWNED_CUSTODY_WALLET,
        "metadata": {
            "require_delegation_check": True,
            "decoded_tx": {
                "chain": "ethereum",
                "from": OWNED_CUSTODY_WALLET,
                "to": OWNED_CUSTODY_WALLET,
                "asset": "ETH",
                "amount": "0",
                "calls": [],
                "authorizations": [
                    {
                        "chain_id": 1,
                        "address": SIMPLE_DELEGATE_ADDR,
                        "nonce": 0,
                        "authority": OWNED_CUSTODY_WALLET,
                    }
                ],
                "fee": {},
                "digest": "0x5678",
            },
        },
    }

    res_allow = client.post("/v1/evaluate", json=allowed_payload)
    assert res_allow.status_code == 200
    data_allow = res_allow.json()
    assert data_allow["verdict"] == "ALLOW"
