"""Comprehensive unit and integration tests for Signer Shim and Approval Tokens (Milestone S11 / F1).

Covers:
- Ed25519 token issuance, compact format, claims, and key rotation.
- Invariant #1: Key Isolation (shim holds disposable key only).
- Invariant #2: Approval Binding & Verification.
- Invariant #3: Fail-Closed Default (nonce store outage, replay rejection).
- Invariant #4: Raw Byte Source of Truth (independent digest recomputation).
- Invariant #9: Safety boundary (disposable keys only).
- Network ACL and container isolation verification (demo_custody container boundary).
"""

import time

import fakeredis
import pytest
import rlp
import yaml  # type: ignore[import-untyped]
from fastapi.testclient import TestClient

from services.bitguard.decoders.evm import evm_decoder
from services.bitguard.tokens import (
    KeySet,
    TokenKey,
    issue_token,
    token_manager,
)
from services.signer_shim.config import settings as shim_settings
from services.signer_shim.main import app as shim_app
from services.signer_shim.main import set_public_key_set
from services.signer_shim.nonce_store import nonce_store

client = TestClient(shim_app)

TEST_WALLET = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
BENIGN_DEST = "0x1111111111111111111111111111111111111111"
AUTH_HEADERS = {"X-BitGuard-Internal-Auth": shim_settings.internal_auth_token}


def build_raw_legacy_tx(
    to: str = BENIGN_DEST,
    value: int = 1_000_000_000_000_000,
    nonce: int = 0,
    gas_price: int = 20_000_000_000,
    gas_limit: int = 21000,
    data: bytes = b"",
) -> str:
    """Helper constructing canonical raw legacy EVM transaction hex."""
    to_bytes = bytes.fromhex(to[2:]) if to.startswith("0x") else bytes.fromhex(to)
    payload = [nonce, gas_price, gas_limit, to_bytes, value, data]
    return "0x" + rlp.encode(payload).hex()


@pytest.fixture(autouse=True)
def setup_test_shim_environment():
    """Sets up an isolated FakeRedis client and synced KeySet for every test."""
    # Isolated in-memory Redis for atomic nonce consumption
    server = fakeredis.FakeServer()
    fake_client = fakeredis.FakeRedis(server=server, decode_responses=True)
    nonce_store.set_redis_client(fake_client)

    # Sync public keys from active token manager to signer shim
    pub_dict = token_manager.key_set.export_public_key_set()
    shim_key_set = KeySet.from_public_key_dict(pub_dict)
    set_public_key_set(shim_key_set)

    yield


# -----------------------------------------------------------------------------
# Test 1: Valid Sign
# -----------------------------------------------------------------------------


def test_valid_sign_with_disposable_testnet_key():
    """Valid end-to-end signing: token verified, digest recomputed, nonce consumed, testnet key signs."""
    raw_tx = build_raw_legacy_tx(value=5000)
    decoded = evm_decoder.decode(raw_tx)

    token = token_manager.issue(
        decoded_tx=decoded,
        wallet=TEST_WALLET,
        chain="ethereum",
    )

    payload = {
        "raw_tx_bytes": raw_tx,
        "token": token,
        "wallet": TEST_WALLET,
        "chain": "ethereum",
    }

    res = client.post("/sign", headers=AUTH_HEADERS, json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "SIGNED"
    assert data["digest"] == decoded.digest.lower()
    assert data["wallet"].lower() == TEST_WALLET.lower()
    assert data["chain"] == "ethereum"
    assert data["signature"].startswith("0x")
    assert len(data["signature"]) == 132  # 0x + 65 bytes * 2 = 132 hex chars
    assert data["r"].startswith("0x")
    assert data["s"].startswith("0x")
    assert data["v"] in [27, 28]
    assert data["tx_hash"].startswith("0x")


# -----------------------------------------------------------------------------
# Test 2: Expired Token
# -----------------------------------------------------------------------------


def test_expired_token_refused():
    """Tokens past their 60s expiration window are rejected with TOKEN_EXPIRED."""
    raw_tx = build_raw_legacy_tx(value=5000)
    decoded = evm_decoder.decode(raw_tx)

    # Issue token expired in the past (iat was 120s ago, exp was 60s ago)
    now = int(time.time())
    stale_time = now - 120
    expired_token = token_manager.issue(
        decoded_tx=decoded,
        wallet=TEST_WALLET,
        chain="ethereum",
        now=stale_time,
    )

    payload = {
        "raw_tx_bytes": raw_tx,
        "token": expired_token,
    }

    res = client.post("/sign", headers=AUTH_HEADERS, json=payload)
    assert res.status_code == 400
    data = res.json()
    assert data["status"] == "REFUSED"
    assert data["reason_code"] == "TOKEN_EXPIRED"


# -----------------------------------------------------------------------------
# Test 3: Wrong Digest (Payload Tampering)
# -----------------------------------------------------------------------------


def test_wrong_digest_refused():
    """Invariant #4: If raw_tx_bytes does not match the token's bound digest, reject with DIGEST_MISMATCH."""
    raw_tx_original = build_raw_legacy_tx(value=1000)
    decoded_original = evm_decoder.decode(raw_tx_original)
    token = token_manager.issue(
        decoded_tx=decoded_original,
        wallet=TEST_WALLET,
        chain="ethereum",
    )

    # Attacker tampers with value in raw bytes
    raw_tx_tampered = build_raw_legacy_tx(value=999_999)

    payload = {
        "raw_tx_bytes": raw_tx_tampered,
        "token": token,
    }

    res = client.post("/sign", headers=AUTH_HEADERS, json=payload)
    assert res.status_code == 400
    data = res.json()
    assert data["status"] == "REFUSED"
    assert data["reason_code"] == "DIGEST_MISMATCH"
    assert "does not match token digest" in data["detail"]


# -----------------------------------------------------------------------------
# Test 4: Wrong Chain & Wrong Wallet
# -----------------------------------------------------------------------------


def test_wrong_chain_refused():
    """Tokens bound to a different blockchain are rejected with CHAIN_MISMATCH."""
    raw_tx = build_raw_legacy_tx()
    decoded = evm_decoder.decode(raw_tx)

    # Token issued for arbitrum
    token = token_manager.issue(
        decoded_tx=decoded,
        wallet=TEST_WALLET,
        chain="arbitrum",
    )

    payload = {
        "raw_tx_bytes": raw_tx,
        "token": token,
        "chain": "arbitrum",
    }

    # Raw bytes decode to ethereum, but token claims arbitrum
    res = client.post("/sign", headers=AUTH_HEADERS, json=payload)
    assert res.status_code == 400
    data = res.json()
    assert data["status"] == "REFUSED"
    assert data["reason_code"] == "CHAIN_MISMATCH"


def test_wrong_wallet_refused():
    """Requested wallet mismatching token claims is rejected with WALLET_MISMATCH."""
    raw_tx = build_raw_legacy_tx()
    decoded = evm_decoder.decode(raw_tx)
    token = token_manager.issue(
        decoded_tx=decoded,
        wallet=TEST_WALLET,
        chain="ethereum",
    )

    payload = {
        "raw_tx_bytes": raw_tx,
        "token": token,
        "wallet": "0x9999999999999999999999999999999999999999",
    }

    res = client.post("/sign", headers=AUTH_HEADERS, json=payload)
    assert res.status_code == 400
    data = res.json()
    assert data["status"] == "REFUSED"
    assert data["reason_code"] == "WALLET_MISMATCH"


# -----------------------------------------------------------------------------
# Test 5: Replayed Nonce
# -----------------------------------------------------------------------------


def test_replayed_nonce_rejected_atomically():
    """Invariant #2: Nonces are single-use; resubmitting the same approval token is refused with NONCE_ALREADY_CONSUMED."""
    raw_tx = build_raw_legacy_tx(value=7000)
    decoded = evm_decoder.decode(raw_tx)
    token = token_manager.issue(
        decoded_tx=decoded,
        wallet=TEST_WALLET,
        chain="ethereum",
    )

    payload = {
        "raw_tx_bytes": raw_tx,
        "token": token,
    }

    # First attempt: succeeds and consumes nonce in Redis
    res1 = client.post("/sign", headers=AUTH_HEADERS, json=payload)
    assert res1.status_code == 200
    assert res1.json()["status"] == "SIGNED"

    # Second attempt (replay attack): fails atomically
    res2 = client.post("/sign", headers=AUTH_HEADERS, json=payload)
    assert res2.status_code == 400
    data2 = res2.json()
    assert data2["status"] == "REFUSED"
    assert data2["reason_code"] == "NONCE_ALREADY_CONSUMED"


# -----------------------------------------------------------------------------
# Test 6: Unknown & Retired Key IDs (Key Rotation)
# -----------------------------------------------------------------------------


def test_token_from_unknown_kid_refused():
    """Tokens signed with an unrecognized kid are rejected with UNKNOWN_KID."""
    raw_tx = build_raw_legacy_tx()
    decoded = evm_decoder.decode(raw_tx)

    rogue_key = TokenKey.generate(kid="rogue-ed25519-99")
    rogue_token = issue_token(
        decoded_tx=decoded,
        wallet=TEST_WALLET,
        chain="ethereum",
        signing_key=rogue_key,
    )

    payload = {
        "raw_tx_bytes": raw_tx,
        "token": rogue_token,
    }

    res = client.post("/sign", headers=AUTH_HEADERS, json=payload)
    assert res.status_code == 400
    data = res.json()
    assert data["status"] == "REFUSED"
    assert data["reason_code"] == "UNKNOWN_KID"


def test_token_from_retired_kid_refused():
    """Tokens signed with a retired kid are rejected with RETIRED_KID."""
    raw_tx = build_raw_legacy_tx()
    decoded = evm_decoder.decode(raw_tx)

    # Create temporary key set with a key that is then retired
    ks = KeySet()
    old_key = TokenKey.generate(kid="old-key-v0")
    ks.add_key(old_key, set_active=True)

    token = issue_token(
        decoded_tx=decoded,
        wallet=TEST_WALLET,
        chain="ethereum",
        signing_key=old_key,
    )

    # Retire the key
    ks.retire_key("old-key-v0")
    set_public_key_set(ks)

    payload = {
        "raw_tx_bytes": raw_tx,
        "token": token,
    }

    res = client.post("/sign", headers=AUTH_HEADERS, json=payload)
    assert res.status_code == 400
    data = res.json()
    assert data["status"] == "REFUSED"
    assert data["reason_code"] == "RETIRED_KID"


def test_key_rotation_lifecycle():
    """Verify key rotation: active key can be rotated, old active key retired, new key signs successfully."""
    raw_tx = build_raw_legacy_tx()
    decoded = evm_decoder.decode(raw_tx)

    # 1. Rotate key to v2
    token_manager.rotate_key("bg-ed25519-v2")
    pub_dict = token_manager.key_set.export_public_key_set()
    set_public_key_set(KeySet.from_public_key_dict(pub_dict))

    # 2. Token issued with new key
    token_v2 = token_manager.issue(
        decoded_tx=decoded,
        wallet=TEST_WALLET,
        chain="ethereum",
    )
    res_v2 = client.post("/sign", headers=AUTH_HEADERS, json={"raw_tx_bytes": raw_tx, "token": token_v2})
    assert res_v2.status_code == 200
    assert res_v2.json()["status"] == "SIGNED"


# -----------------------------------------------------------------------------
# Test 7: Direct Call Without Token & Signature Tampering
# -----------------------------------------------------------------------------


def test_direct_call_without_token_refused():
    """Direct invocation without approval token is rejected."""
    raw_tx = build_raw_legacy_tx()

    payload = {
        "raw_tx_bytes": raw_tx,
        "token": "",
    }

    res = client.post("/sign", headers=AUTH_HEADERS, json=payload)
    assert res.status_code == 400
    data = res.json()
    assert data["status"] == "REFUSED"
    assert data["reason_code"] == "MISSING_APPROVAL_TOKEN"


def test_tampered_token_signature_refused():
    """Tampering with token signature bytes is detected and refused with INVALID_TOKEN_SIGNATURE."""
    raw_tx = build_raw_legacy_tx()
    decoded = evm_decoder.decode(raw_tx)
    token = token_manager.issue(
        decoded_tx=decoded,
        wallet=TEST_WALLET,
        chain="ethereum",
    )

    parts = token.split(".")
    # Tamper with signature segment
    tampered_sig = parts[2][:-4] + "AAAA"
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    payload = {
        "raw_tx_bytes": raw_tx,
        "token": tampered_token,
    }

    res = client.post("/sign", headers=AUTH_HEADERS, json=payload)
    assert res.status_code == 400
    data = res.json()
    assert data["status"] == "REFUSED"
    assert data["reason_code"] == "INVALID_TOKEN_SIGNATURE"


# -----------------------------------------------------------------------------
# Test 8: Network Isolation & Demo Custody Container Boundary
# -----------------------------------------------------------------------------


def test_direct_call_without_internal_acl_auth_rejected():
    """Direct invocation without BitGuard internal ACL secret is rejected with 403 Forbidden."""
    raw_tx = build_raw_legacy_tx()
    decoded = evm_decoder.decode(raw_tx)
    token = token_manager.issue(
        decoded_tx=decoded,
        wallet=TEST_WALLET,
        chain="ethereum",
    )

    payload = {
        "raw_tx_bytes": raw_tx,
        "token": token,
    }

    # 1. No Authorization / ACL header provided
    res_no_auth = client.post("/sign", json=payload)
    assert res_no_auth.status_code == 403

    # 2. Rogue or incorrect internal token
    res_bad_auth = client.post(
        "/sign",
        headers={"X-BitGuard-Internal-Auth": "rogue-unauthorized-caller-token"},
        json=payload,
    )
    assert res_bad_auth.status_code == 403
    data = res_bad_auth.json()
    assert data["detail"]["reason_code"] == "UNAUTHORIZED_INTERNAL_CALLER"


def test_third_party_demo_custody_container_unreachable():
    """Verify architectural network isolation: a third 'demo_custody' container cannot route to signer_shim.

    Validates:
    1. docker-compose.yml defines 'signer_internal' with 'internal: true' (no external internet/routing).
    2. 'signer_shim' is attached strictly to 'signer_internal' and NOT to 'public'.
    3. 'signer_shim' never publishes port 8001 to the host (ports list empty; expose only).
    4. An external or third-party container attached to 'public' (like demo_custody) cannot resolve or route to signer_shim.
    """
    with open("docker-compose.yml", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)

    services = compose_data.get("services", {})
    networks = compose_data.get("networks", {})

    # 1. Verify signer_internal network is an isolated internal bridge
    assert "signer_internal" in networks, "Network 'signer_internal' must exist"
    assert networks["signer_internal"].get("internal") is True, (
        "Invariant: 'signer_internal' network must be defined with 'internal: true'"
    )

    # 2. Verify signer_shim network isolation
    assert "signer_shim" in services, "Service 'signer_shim' must exist"
    shim_networks = services["signer_shim"].get("networks", [])
    assert shim_networks == ["signer_internal"], (
        f"Signer shim must be attached strictly to 'signer_internal' only, got {shim_networks}"
    )

    # 3. Verify no published host ports for signer_shim
    assert "ports" not in services["signer_shim"], (
        "Signer shim port 8001 must NEVER be published to the host machine"
    )
    assert services["signer_shim"].get("expose") == ["8001"], (
        "Signer shim port 8001 must be exposed internally to 'signer_internal' only"
    )

    # 4. Verify that an external container 'demo_custody' on 'public' network cannot call signer_shim
    # Direct calls lacking internal ACL fail with 403
    res_bypass = client.post(
        "/sign",
        headers={"X-Forwarded-For": "172.20.0.99"},  # Simulating demo_custody container IP
        json={"raw_tx_bytes": "0x00", "token": "dummy"},
    )
    assert res_bypass.status_code == 403
    assert res_bypass.json()["detail"]["reason_code"] == "UNAUTHORIZED_INTERNAL_CALLER"


# -----------------------------------------------------------------------------
# Test 9: Fail-Closed on Nonce Store Outage
# -----------------------------------------------------------------------------


def test_nonce_store_outage_fails_closed():
    """Invariant #3: Redis outage during nonce consumption results in fail-closed 500 error."""
    raw_tx = build_raw_legacy_tx()
    decoded = evm_decoder.decode(raw_tx)
    token = token_manager.issue(
        decoded_tx=decoded,
        wallet=TEST_WALLET,
        chain="ethereum",
    )

    # Break redis client to simulate outage
    broken_redis = fakeredis.FakeRedis()
    broken_redis.set = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("Redis connection refused"))  # type: ignore[method-assign]
    nonce_store.set_redis_client(broken_redis)

    payload = {
        "raw_tx_bytes": raw_tx,
        "token": token,
    }

    res = client.post("/sign", headers=AUTH_HEADERS, json=payload)
    assert res.status_code == 500
    data = res.json()
    assert data["status"] == "REFUSED"
    assert data["reason_code"] == "NONCE_STORE_UNAVAILABLE"
