"""Comprehensive unit, fuzz, and integration tests for Bitcoin PSBT Chain Decoder (Milestone S34).

Covers:
- Invariant #1: Key Isolation (shim holds disposable testnet key only).
- Invariant #2: Approval Binding & Verification (one-time token bound to sighash digest, chain, wallet).
- Invariant #3: Fail-Closed Default (malformed, corrupt, or invalid PSBTs raise DecodeError).
- Invariant #4: Raw Byte Source of Truth (strictly decode from raw PSBT bytes, ignore caller metadata).
- At least 20 test vectors including malformed vectors.
- Hypothesis property-based fuzz tests.
- End-to-end integration test with Signer Shim using disposable testnet key.
"""

import base64
import time

import fakeredis
import hypothesis.strategies as st
import pytest
from embit import ec, psbt, script, transaction
from embit.networks import NETWORKS
from fastapi.testclient import TestClient
from hypothesis import given, settings

from services.bitguard.decoders.base import DecodeError
from services.bitguard.decoders.psbt import psbt_decoder
from services.bitguard.engine.pipeline import decision_engine
from services.bitguard.ledger.intent_check import check_intent
from services.bitguard.ledger.mock import mock_ledger_connector
from services.bitguard.ledger.models import IntentStatus, WithdrawalIntent
from services.bitguard.models import DecodedTx, SigningRequest
from services.bitguard.policy.models import PolicyDocument
from services.bitguard.tokens import KeySet, token_manager
from services.signer_shim.config import settings as shim_settings
from services.signer_shim.heartbeat import heartbeat_tracker
from services.signer_shim.main import app as shim_app
from services.signer_shim.main import set_public_key_set
from services.signer_shim.nonce_store import nonce_store

shim_client = TestClient(shim_app)
AUTH_HEADERS = {"X-BitGuard-Internal-Auth": shim_settings.internal_auth_token}


# -----------------------------------------------------------------------------
# Fixtures and Helpers
# -----------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Provides isolated FakeRedis and synced keys for tests."""
    server = fakeredis.FakeServer()
    fake_client = fakeredis.FakeRedis(server=server, decode_responses=True)
    nonce_store.set_redis_client(fake_client)

    pub_dict = token_manager.key_set.export_public_key_set()
    shim_key_set = KeySet.from_public_key_dict(pub_dict)
    set_public_key_set(shim_key_set)

    heartbeat_tracker.last_heartbeat_time = time.time()
    mock_ledger_connector.reset()
    yield


def build_test_psbt(
    input_amounts: list[int],
    output_amounts: list[int],
    change_indices: list[int] | None = None,
    legacy: bool = False,
    taproot: bool = False,
) -> tuple[str, str, list[str]]:
    """Builds a test PSBT and returns (base64_psbt, sender_address, recipient_addresses)."""
    tx = transaction.Transaction()
    tx.version = 2
    tx.vin = [
        transaction.TransactionInput(bytes([i + 1] * 32), 0)
        for i in range(len(input_amounts))
    ]

    recipient_scripts: list[script.Script] = []
    recipient_addrs: list[str] = []

    for j, _ in enumerate(output_amounts):
        if taproot:
            s = script.Script(b"\x51\x20" + bytes([(j + 10) % 256] * 32))
        elif legacy:
            s = script.Script(b"\x76\xa9\x14" + bytes([(j + 10) % 256] * 20) + b"\x88\xac")
        else:
            s = script.Script(b"\x00\x14" + bytes([(j + 10) % 256] * 20))
        recipient_scripts.append(s)
        recipient_addrs.append(s.address(NETWORKS["main"]))

    tx.vout = [
        transaction.TransactionOutput(output_amounts[j], recipient_scripts[j])
        for j in range(len(output_amounts))
    ]

    p = psbt.PSBT(tx)

    sender_addrs: list[str] = []
    for i, in_amt in enumerate(input_amounts):
        if legacy:
            prev_tx = transaction.Transaction()
            prev_tx.vin = [transaction.TransactionInput(bytes([9] * 32), 0)]
            prev_script = script.Script(b"\x76\xa9\x14" + bytes([(i + 1) * 3 % 256] * 20) + b"\x88\xac")
            prev_tx.vout = [transaction.TransactionOutput(in_amt, prev_script)]
            p.inputs[i].non_witness_utxo = prev_tx
            sender_addrs.append(prev_script.address(NETWORKS["main"]))
        elif taproot:
            prev_script = script.Script(b"\x51\x20" + bytes([(i + 1) * 3 % 256] * 32))
            p.inputs[i].witness_utxo = transaction.TransactionOutput(in_amt, prev_script)
            sender_addrs.append(prev_script.address(NETWORKS["main"]))
        else:
            prev_script = script.Script(b"\x00\x14" + bytes([(i + 1) * 3 % 256] * 20))
            p.inputs[i].witness_utxo = transaction.TransactionOutput(in_amt, prev_script)
            sender_addrs.append(prev_script.address(NETWORKS["main"]))

    # Add BIP32 derivation path to change outputs if requested
    if change_indices:
        for ch_idx in change_indices:
            pk = ec.PrivateKey(bytes([(ch_idx + 1) * 7 % 256] * 32)).sec()
            pub = ec.PublicKey.parse(pk)
            # m / 84' / 0' / 0' / 1 / ch_idx (change index = 1)
            p.outputs[ch_idx].bip32_derivations[pub] = psbt.DerivationPath(
                b"1234",
                [2147483732, 2147483648, 2147483648, 1, ch_idx],
            )

    return p.to_base64(), sender_addrs[0], recipient_addrs


# -----------------------------------------------------------------------------
# Test Vectors 1-10: Valid PSBT Transactions & Features
# -----------------------------------------------------------------------------


def test_vector_01_valid_segwit_with_change():
    """Vector 1: Valid SegWit P2WPKH with 1 external recipient and 1 BIP32 change output."""
    b64, sender, recipients = build_test_psbt(
        input_amounts=[100_000],
        output_amounts=[75_000, 20_000],
        change_indices=[1],
    )
    decoded = psbt_decoder.decode(b64)

    assert decoded.chain == "bitcoin"
    assert decoded.asset == "BTC"
    assert decoded.from_address == sender
    assert decoded.to_address == recipients[0]
    assert decoded.amount == "75000"  # Excludes change!
    assert decoded.fee.fee_satoshis == 5_000
    assert decoded.digest.startswith("0x")
    assert len(decoded.digest) == 66  # 32 bytes hex + 0x

    # Verify calls
    assert len(decoded.calls) == 4  # 2 outputs + 1 input + 1 fee
    assert decoded.calls[0].flag is None
    assert decoded.calls[0].recipient == recipients[0]
    assert decoded.calls[0].amount == "75000"
    assert decoded.calls[1].flag == "CHANGE"
    assert decoded.calls[1].amount == "20000"
    assert decoded.calls[2].call_type == "INPUT"
    assert decoded.calls[3].call_type == "FEE"
    assert decoded.calls[3].flag is None


def test_vector_02_valid_segwit_no_change():
    """Vector 2: Valid SegWit transaction with no change (entire amount minus fee sent)."""
    b64, sender, recipients = build_test_psbt(
        input_amounts=[50_000],
        output_amounts=[48_000],
    )
    decoded = psbt_decoder.decode(b64)

    assert decoded.amount == "48000"
    assert decoded.to_address == recipients[0]
    assert decoded.fee.fee_satoshis == 2_000
    assert decoded.calls[0].flag is None


def test_vector_03_valid_hex_encoded_psbt():
    """Vector 3: Valid PSBT passed as raw hex string."""
    b64, _, _ = build_test_psbt(
        input_amounts=[100_000],
        output_amounts=[90_000],
    )
    raw_bytes = base64.b64decode(b64)
    hex_str = "0x" + raw_bytes.hex()

    decoded = psbt_decoder.decode(hex_str)
    assert decoded.amount == "90000"
    assert decoded.fee.fee_satoshis == 10_000


def test_vector_04_valid_legacy_p2pkh_with_non_witness_utxo():
    """Vector 4: Valid legacy P2PKH transaction with non_witness_utxo."""
    b64, sender, recipients = build_test_psbt(
        input_amounts=[200_000],
        output_amounts=[180_000],
        legacy=True,
    )
    decoded = psbt_decoder.decode(b64)

    assert decoded.from_address == sender
    assert decoded.to_address == recipients[0]
    assert decoded.amount == "180000"
    assert decoded.fee.fee_satoshis == 20_000
    assert decoded.digest.startswith("0x")


def test_vector_05_valid_taproot_p2tr():
    """Vector 5: Valid Taproot P2TR transaction."""
    b64, sender, recipients = build_test_psbt(
        input_amounts=[150_000],
        output_amounts=[140_000],
        taproot=True,
    )
    decoded = psbt_decoder.decode(b64)

    assert decoded.amount == "140000"
    assert decoded.to_address == recipients[0]
    assert decoded.fee.fee_satoshis == 10_000
    assert decoded.to_address.startswith("bc1p")


def test_vector_06_valid_multi_input():
    """Vector 6: Multi-input PSBT (2 inputs from different addresses)."""
    b64, sender, recipients = build_test_psbt(
        input_amounts=[60_000, 70_000],
        output_amounts=[120_000],
    )
    decoded = psbt_decoder.decode(b64)

    assert decoded.amount == "120000"
    assert decoded.fee.fee_satoshis == 10_000
    # Both inputs are in calls with sighash in data
    input_calls = [c for c in decoded.calls if c.call_type == "INPUT"]
    assert len(input_calls) == 2
    assert input_calls[0].data.startswith("0x")
    assert input_calls[1].data.startswith("0x")


def test_vector_07_valid_multi_output_batch():
    """Vector 7: Multi-output batch payout (5 outputs)."""
    b64, sender, recipients = build_test_psbt(
        input_amounts=[500_000],
        output_amounts=[50_000, 60_000, 70_000, 80_000, 90_000],
    )
    decoded = psbt_decoder.decode(b64)

    assert decoded.amount == str(50_000 + 60_000 + 70_000 + 80_000 + 90_000)
    assert decoded.fee.fee_satoshis == 150_000
    out_calls = [c for c in decoded.calls if c.call_type == "OUTPUT"]
    assert len(out_calls) == 5


def test_vector_08_change_detection_via_owned_addresses():
    """Vector 8: Change output detection via policy.owned_addresses."""
    b64, _, recipients = build_test_psbt(
        input_amounts=[100_000],
        output_amounts=[60_000, 35_000],
    )
    # Configure recipient 1 as owned address in policy
    policy = PolicyDocument(owned_addresses=[recipients[1]])
    decoded = psbt_decoder.decode(b64, policy=policy)

    assert decoded.amount == "60000"
    assert decoded.calls[0].flag is None
    assert decoded.calls[1].flag == "CHANGE"


def test_vector_09_change_detection_via_input_address_match():
    """Vector 9: Change output detection via return to originating input address."""
    tx = transaction.Transaction()
    tx.vin = [transaction.TransactionInput(bytes([1] * 32), 0)]

    s_orig = script.Script(b"\x00\x14" + bytes([2] * 20))
    s_dest = script.Script(b"\x00\x14" + bytes([3] * 20))

    tx.vout = [
        transaction.TransactionOutput(40_000, s_dest),
        transaction.TransactionOutput(55_000, s_orig),  # Returns to originating sender
    ]
    p = psbt.PSBT(tx)
    p.inputs[0].witness_utxo = transaction.TransactionOutput(100_000, s_orig)

    decoded = psbt_decoder.decode(p.to_base64())
    assert decoded.amount == "40000"
    assert decoded.calls[0].flag is None
    assert decoded.calls[1].flag == "CHANGE"


def test_vector_10_fee_exceeds_policy():
    """Vector 10: Fee exceeds policy threshold and is flagged FEE_EXCEEDS_POLICY."""
    b64, _, _ = build_test_psbt(
        input_amounts=[2_500_000],
        output_amounts=[500_000],  # 2,000,000 fee exceeds 1,000,000 default max
    )
    decoded = psbt_decoder.decode(b64)

    assert decoded.fee.fee_satoshis == 2_000_000
    fee_call = [c for c in decoded.calls if c.call_type == "FEE"][0]
    assert fee_call.flag == "FEE_EXCEEDS_POLICY"


# -----------------------------------------------------------------------------
# Test Vectors 11-25: Malformed & Invalid Vectors (Fail-Closed Invariant #3)
# -----------------------------------------------------------------------------


def test_vector_11_malformed_empty_payload():
    """Vector 11: Empty string raises DecodeError."""
    with pytest.raises(DecodeError, match="empty or whitespace"):
        psbt_decoder.decode("")


def test_vector_12_malformed_none_payload():
    """Vector 12: None payload raises DecodeError."""
    with pytest.raises(DecodeError, match="cannot be None"):
        psbt_decoder.decode(None)  # type: ignore


def test_vector_13_malformed_invalid_magic_bytes():
    """Vector 13: Payload without 'psbt\\xff' magic raises DecodeError."""
    bad_bytes = b"badm\xff\x01\x00\x00"
    with pytest.raises(DecodeError, match="Invalid PSBT magic"):
        psbt_decoder.decode(bad_bytes)


def test_vector_14_malformed_truncated_header():
    """Vector 14: Payload less than 5 bytes raises DecodeError."""
    with pytest.raises(DecodeError, match="too short"):
        psbt_decoder.decode(b"psbt")


def test_vector_15_malformed_corrupt_base64():
    """Vector 15: Invalid base64 characters raise DecodeError."""
    with pytest.raises(DecodeError, match="Invalid base64"):
        psbt_decoder.decode("???NotBase64!!!")


def test_vector_16_malformed_corrupt_psbt_stream():
    """Vector 16: Valid magic bytes but truncated internal records raise DecodeError."""
    corrupt_stream = b"psbt\xff\x01\x00\x99"
    with pytest.raises(DecodeError, match="Failed parsing PSBT"):
        psbt_decoder.decode(corrupt_stream)


def test_vector_17_malformed_missing_utxo_info():
    """Vector 17: Input missing UTXO information raises DecodeError."""
    tx = transaction.Transaction()
    tx.vin = [transaction.TransactionInput(bytes([1] * 32), 0)]
    tx.vout = [transaction.TransactionOutput(50_000, script.Script(b"\x00\x14" + bytes([2] * 20)))]
    p = psbt.PSBT(tx)
    # Deliberately omit witness_utxo and non_witness_utxo

    with pytest.raises(DecodeError, match="missing previous UTXO information"):
        psbt_decoder.decode(p.to_base64())


def test_vector_18_malformed_negative_fee():
    """Vector 18: Total outputs exceed inputs (negative fee) raises DecodeError."""
    b64, _, _ = build_test_psbt(
        input_amounts=[50_000],
        output_amounts=[80_000],  # Outputs > inputs
    )
    with pytest.raises(DecodeError, match="Negative transaction fee"):
        psbt_decoder.decode(b64)


def test_vector_19_malformed_trailing_garbage():
    """Vector 19: Valid PSBT with trailing garbage appended raises DecodeError."""
    b64, _, _ = build_test_psbt(
        input_amounts=[100_000],
        output_amounts=[80_000],
    )
    raw = base64.b64decode(b64)
    with_garbage = raw + b"EXTRA_TRAILING_BYTES"
    with pytest.raises(DecodeError, match="Trailing garbage"):
        psbt_decoder.decode(with_garbage)


def test_vector_20_malformed_zero_inputs():
    """Vector 20: Transaction with zero inputs raises DecodeError."""
    tx = transaction.Transaction()
    tx.vin = []
    tx.vout = [transaction.TransactionOutput(50_000, script.Script(b"\x00\x14" + bytes([1] * 20)))]
    p = psbt.PSBT(tx)
    with pytest.raises(DecodeError):
        psbt_decoder.decode(p.to_base64())


def test_vector_21_malformed_zero_outputs():
    """Vector 21: Transaction with zero outputs raises DecodeError."""
    tx = transaction.Transaction()
    tx.vin = [transaction.TransactionInput(bytes([1] * 32), 0)]
    tx.vout = []
    p = psbt.PSBT(tx)
    p.inputs[0].witness_utxo = transaction.TransactionOutput(50_000, script.Script(b"\x00\x14" + bytes([1] * 20)))
    with pytest.raises(DecodeError, match="0 outputs"):
        psbt_decoder.decode(p.to_base64())


def test_vector_22_malformed_negative_or_overflow_output_value():
    """Vector 22: Output value exceeding 21 million BTC satoshis raises DecodeError."""
    tx = transaction.Transaction()
    tx.vin = [transaction.TransactionInput(bytes([1] * 32), 0)]
    tx.vout = [transaction.TransactionOutput(2_100_000_000_000_001, script.Script(b"\x00\x14" + bytes([1] * 20)))]
    p = psbt.PSBT(tx)
    p.inputs[0].witness_utxo = transaction.TransactionOutput(3_000_000_000_000_000, script.Script(b"\x00\x14" + bytes([1] * 20)))
    with pytest.raises(DecodeError, match="out of valid range"):
        psbt_decoder.decode(p.to_base64())


def test_vector_23_malformed_overflow_output_value():
    """Vector 23: Output value exceeding 21 million BTC raises DecodeError."""
    tx = transaction.Transaction()
    tx.vin = [transaction.TransactionInput(bytes([1] * 32), 0)]
    tx.vout = [transaction.TransactionOutput(3_000_000_000_000_000, script.Script(b"\x00\x14" + bytes([1] * 20)))]
    p = psbt.PSBT(tx)
    p.inputs[0].witness_utxo = transaction.TransactionOutput(4_000_000_000_000_000, script.Script(b"\x00\x14" + bytes([1] * 20)))
    with pytest.raises(DecodeError, match="out of valid range"):
        psbt_decoder.decode(p.to_base64())


def test_vector_24_malformed_non_witness_utxo_vout_out_of_bounds():
    """Vector 24: Non-witness UTXO previous tx doesn't contain matching vout index."""
    tx = transaction.Transaction()
    tx.vin = [transaction.TransactionInput(bytes([1] * 32), 5)]  # vout=5
    tx.vout = [transaction.TransactionOutput(10_000, script.Script(b"\x00\x14" + bytes([1] * 20)))]
    p = psbt.PSBT(tx)

    prev_tx = transaction.Transaction()
    prev_tx.vin = [transaction.TransactionInput(bytes([9] * 32), 0)]
    prev_tx.vout = [transaction.TransactionOutput(50_000, script.Script(b"\x00\x14" + bytes([1] * 20)))]  # len=1
    p.inputs[0].non_witness_utxo = prev_tx

    with pytest.raises(DecodeError, match="out of range"):
        psbt_decoder.decode(p.to_base64())


def test_vector_25_malformed_odd_length_hex():
    """Vector 25: Odd length or non-hex string raises DecodeError."""
    with pytest.raises(DecodeError, match="Invalid hex"):
        psbt_decoder.decode("0x70736274ff1")


# -----------------------------------------------------------------------------
# Hypothesis Property-Based Fuzz Testing
# -----------------------------------------------------------------------------


@given(st.binary(min_size=0, max_size=300))
@settings(max_examples=50, deadline=None)
def test_psbt_decoder_hypothesis_random_bytes_fuzz(fuzz_data: bytes):
    """Fuzz test: Arbitrary byte mutations must fail-closed with DecodeError, never crash."""
    try:
        res = psbt_decoder.decode(fuzz_data)
        assert isinstance(res, DecodedTx)
    except DecodeError:
        pass  # Expected fail-closed behavior


@given(st.integers(min_value=0, max_value=100), st.binary(min_size=1, max_size=10))
@settings(max_examples=30, deadline=None)
def test_psbt_decoder_hypothesis_mutated_valid_psbt_fuzz(offset: int, mutation: bytes):
    """Fuzz test: Mutated valid PSBT bytes must fail-closed with DecodeError or parse safely."""
    valid_b64, _, _ = build_test_psbt([100_000], [80_000])
    raw = bytearray(base64.b64decode(valid_b64))
    if offset < len(raw):
        raw[offset : offset + len(mutation)] = mutation[: min(len(mutation), len(raw) - offset)]

    try:
        res = psbt_decoder.decode(bytes(raw))
        assert isinstance(res, DecodedTx)
    except DecodeError:
        pass  # Expected fail-closed behavior


# -----------------------------------------------------------------------------
# Decision Pipeline & Intent Reconciliation Tests
# -----------------------------------------------------------------------------


def test_psbt_in_decision_pipeline():
    """Verifies that decision pipeline decodes PSBT, extracts wallet, and processes verdict."""
    b64, sender, recipients = build_test_psbt(
        input_amounts=[100_000],
        output_amounts=[80_000],
    )

    req = SigningRequest(
        raw_tx=b64,
        chain="bitcoin",
        wallet=sender,
        metadata={"amount_usd": 50.0},
    )

    decision = decision_engine.evaluate(req, is_dry_run=True)
    assert decision.decoded_tx is not None
    assert decision.decoded_tx.chain == "bitcoin"
    assert decision.decoded_tx.amount == "80000"
    assert decision.decoded_tx.to_address == recipients[0]


def test_psbt_intent_reconciliation():
    """Verifies custody withdrawal intent check matches Bitcoin PSBT amount and destination."""
    b64, sender, recipients = build_test_psbt(
        input_amounts=[100_000],
        output_amounts=[80_000],
    )
    decoded = psbt_decoder.decode(b64)

    # Register custody intent in mock ledger
    intent = WithdrawalIntent(
        id="intent-btc-01",
        account_id="acc-1",
        amount="80000",
        destination=recipients[0],
        chain="bitcoin",
        asset="BTC",
        status=IntentStatus.APPROVED.value,
    )
    mock_ledger_connector.register_intent(intent)

    req = SigningRequest(
        raw_tx=b64,
        chain="bitcoin",
        wallet=sender,
        intent_id=intent.id,
    )

    res = check_intent(req, decoded, ledger=mock_ledger_connector)
    assert res.passed is True
    assert res.intent is not None


# -----------------------------------------------------------------------------
# End-to-End Test with Signer Shim (Disposable Testnet Key)
# -----------------------------------------------------------------------------


def test_psbt_signer_shim_e2e_round_trip():
    """End-to-End: BitGuard issues approval token for PSBT, Signer Shim verifies and signs."""
    b64, sender, recipients = build_test_psbt(
        input_amounts=[100_000],
        output_amounts=[75_000, 20_000],
        change_indices=[1],
    )
    decoded = psbt_decoder.decode(b64)

    # Invariant #2: One-time token bound to PSBT digest, chain, wallet
    token_str = token_manager.issue(
        decoded_tx=decoded,
        wallet=sender,
        chain="bitcoin",
        ttl_seconds=60,
    )

    # Submit to Signer Shim /sign
    resp = shim_client.post(
        "/sign",
        json={
            "raw_tx_bytes": b64,
            "token": token_str,
            "wallet": sender,
            "chain": "bitcoin",
        },
        headers=AUTH_HEADERS,
    )

    assert resp.status_code == 200, f"Signing failed: {resp.text}"
    body = resp.json()
    assert body["status"] == "SIGNED"
    assert body["chain"] == "bitcoin"
    assert body["digest"].lower() == decoded.digest.lower()
    assert "signature" in body
    assert "r" in body
    assert "s" in body


def test_psbt_signer_shim_replay_rejected():
    """Replaying the same approval token on the Signer Shim is rejected (NONCE_ALREADY_CONSUMED)."""
    b64, sender, _ = build_test_psbt(
        input_amounts=[100_000],
        output_amounts=[90_000],
    )
    decoded = psbt_decoder.decode(b64)

    token_str = token_manager.issue(
        decoded_tx=decoded,
        wallet=sender,
        chain="bitcoin",
        ttl_seconds=60,
    )

    # First attempt: succeeds
    resp1 = shim_client.post(
        "/sign",
        json={
            "raw_tx_bytes": b64,
            "token": token_str,
            "wallet": sender,
            "chain": "bitcoin",
        },
        headers=AUTH_HEADERS,
    )
    assert resp1.status_code == 200

    # Second attempt: replayed token is refused
    resp2 = shim_client.post(
        "/sign",
        json={
            "raw_tx_bytes": b64,
            "token": token_str,
            "wallet": sender,
            "chain": "bitcoin",
        },
        headers=AUTH_HEADERS,
    )
    assert resp2.status_code == 400
    assert resp2.json()["reason_code"] == "NONCE_ALREADY_CONSUMED"


def test_psbt_signer_shim_digest_mismatch_refused():
    """Tampering with raw PSBT payload causes DIGEST_MISMATCH refusal."""
    b64_orig, sender, _ = build_test_psbt(
        input_amounts=[100_000],
        output_amounts=[90_000],
    )
    decoded = psbt_decoder.decode(b64_orig)

    # Issue token for original transaction
    token_str = token_manager.issue(
        decoded_tx=decoded,
        wallet=sender,
        chain="bitcoin",
        ttl_seconds=60,
    )

    # Alter payload: change output amount to 80,000 (different sighash)
    b64_altered, _, _ = build_test_psbt(
        input_amounts=[100_000],
        output_amounts=[80_000],
    )

    resp = shim_client.post(
        "/sign",
        json={
            "raw_tx_bytes": b64_altered,
            "token": token_str,
            "wallet": sender,
            "chain": "bitcoin",
        },
        headers=AUTH_HEADERS,
    )
    assert resp.status_code == 400
    assert resp.json()["reason_code"] == "DIGEST_MISMATCH"
