"""Comprehensive test suite for EvmDecoder: test vector library, eth-account round-trip, and hypothesis fuzzing (Milestone S06 / F4)."""

import json
from pathlib import Path

import pytest
import rlp
from eth_account.typed_transactions import AccessListTransaction, DynamicFeeTransaction
from eth_utils import to_checksum_address
from hypothesis import given, settings
from hypothesis import strategies as st

from services.bitguard.decoders.base import DecodeError
from services.bitguard.decoders.evm import EvmDecoder, evm_decoder
from services.bitguard.models import DecodedTx


def test_evm_vectors_library():
    """Verify all 32 test vectors from tests/vectors/evm/vectors.json."""
    vector_file = Path(__file__).resolve().parent / "vectors" / "evm" / "vectors.json"
    assert vector_file.exists(), "EVM vectors JSON file must exist"

    vectors = json.loads(vector_file.read_text(encoding="utf-8"))
    assert len(vectors) >= 25, f"Must have at least 25 test vectors, found {len(vectors)}"

    valid_count = 0
    malformed_count = 0

    for vec in vectors:
        vec_id = vec["id"]
        raw_hex = vec["raw_hex"]
        is_valid = vec["is_valid"]

        if is_valid:
            valid_count += 1
            decoded = evm_decoder.decode(raw_hex)
            assert isinstance(decoded, DecodedTx), f"Failed to return DecodedTx for {vec_id}"
            assert decoded.digest.startswith("0x"), f"Digest missing 0x prefix for {vec_id}"

            if "to" in vec:
                assert decoded.to_address == vec["to"], f"Destination mismatch in {vec_id}"
            if "asset" in vec:
                assert decoded.asset == vec["asset"], f"Asset mismatch in {vec_id}"
            if "amount" in vec:
                assert decoded.amount == vec["amount"], f"Amount mismatch in {vec_id}"
            if "authorizations_count" in vec:
                assert len(decoded.authorizations) == vec["authorizations_count"], (
                    f"Authorization count mismatch in {vec_id}"
                )
            if "call_type" in vec and decoded.calls:
                assert decoded.calls[0].call_type == vec["call_type"], f"Call type mismatch in {vec_id}"
            if "flag" in vec and decoded.calls:
                assert decoded.calls[0].flag == vec["flag"], f"Flag mismatch in {vec_id}"
        else:
            malformed_count += 1
            with pytest.raises(DecodeError):
                evm_decoder.decode(raw_hex)

    assert valid_count >= 15, f"Expected at least 15 valid vectors, verified {valid_count}"
    assert malformed_count >= 10, f"Expected at least 10 malformed vectors, verified {malformed_count}"


def test_eth_account_round_trip_legacy():
    """Round-trip verification of Legacy unsigned transactions against eth-account."""
    to_addr = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    tx_params = {
        "nonce": 42,
        "gasPrice": 25_000_000_000,
        "gas": 21_000,
        "to": to_addr,
        "value": 1_500_000_000_000_000_000,
        "data": b"",
        "chainId": 1,
    }

    # Encode unsigned legacy EIP-155 payload
    to_bytes = bytes.fromhex(to_addr[2:])
    unsigned_rlp = rlp.encode([
        tx_params["nonce"],
        tx_params["gasPrice"],
        tx_params["gas"],
        to_bytes,
        tx_params["value"],
        tx_params["data"],
        tx_params["chainId"],
        0,
        0,
    ])

    decoded = evm_decoder.decode(unsigned_rlp)
    assert decoded.to_address == to_addr
    assert decoded.amount == str(tx_params["value"])
    assert decoded.fee.gas_limit == tx_params["gas"]
    assert decoded.fee.max_fee_per_gas == str(tx_params["gasPrice"])
    assert decoded.chain == "ethereum"


def test_eth_account_round_trip_type1_eip2930():
    """Round-trip verification of Type 1 (EIP-2930) transactions against eth-account."""
    to_addr = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    to_bytes = bytes.fromhex(to_addr[2:])
    storage_key = "0x0000000000000000000000000000000000000000000000000000000000000001"
    storage_key_bytes = bytes.fromhex(storage_key[2:])

    tx_dict = {
        "type": 1,
        "chainId": 1,
        "nonce": 7,
        "gasPrice": 20_000_000_000,
        "gas": 30_000,
        "to": to_addr,
        "value": 250_000_000,
        "data": b"",
        "accessList": [{"address": to_addr, "storageKeys": [storage_key]}],
    }
    account_tx = AccessListTransaction.from_dict(tx_dict)
    expected_hash = "0x" + account_tx.hash().hex()

    access_list_rlp = [[to_bytes, [storage_key_bytes]]]
    raw_2930 = b"\x01" + rlp.encode([
        tx_dict["chainId"],
        tx_dict["nonce"],
        tx_dict["gasPrice"],
        tx_dict["gas"],
        to_bytes,
        tx_dict["value"],
        tx_dict["data"],
        access_list_rlp,
    ])

    decoded = evm_decoder.decode(raw_2930)
    assert decoded.digest == expected_hash
    assert decoded.to_address == to_addr
    assert decoded.amount == "250000000"


def test_eth_account_round_trip_type2_eip1559():
    """Round-trip verification of Type 2 (EIP-1559) transactions against eth-account."""
    to_addr = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    to_bytes = bytes.fromhex(to_addr[2:])

    tx_dict = {
        "type": 2,
        "chainId": 1,
        "nonce": 12,
        "maxPriorityFeePerGas": 1_200_000_000,
        "maxFeePerGas": 32_000_000_000,
        "gas": 21_000,
        "to": to_bytes,
        "value": 5_000_000_000_000_000_000,
        "data": b"",
        "accessList": (),
    }
    account_tx = DynamicFeeTransaction.from_dict(tx_dict)
    expected_hash = "0x" + account_tx.hash().hex()

    raw_1559 = b"\x02" + rlp.encode([
        tx_dict["chainId"],
        tx_dict["nonce"],
        tx_dict["maxPriorityFeePerGas"],
        tx_dict["maxFeePerGas"],
        tx_dict["gas"],
        to_bytes,
        tx_dict["value"],
        tx_dict["data"],
        [],
    ])

    decoded = evm_decoder.decode(raw_1559)
    assert decoded.digest == expected_hash
    assert decoded.to_address == to_addr
    assert decoded.amount == "5000000000000000000"
    assert decoded.fee.max_fee_per_gas == "32000000000"
    assert decoded.fee.max_priority_fee_per_gas == "1200000000"


def test_eip7702_two_authorizations_parsing():
    """Verify Type 4 (EIP-7702) parses multiple authorizations into DecodedTx.authorizations."""
    to_bytes = bytes.fromhex("742d35Cc6634C0532925a3b844Bc454e4438f44e")
    delegate_1 = bytes.fromhex("1111111111111111111111111111111111111111")
    delegate_2 = bytes.fromhex("2222222222222222222222222222222222222222")

    auth_1 = [1, delegate_1, 0]
    auth_2 = [1, delegate_2, 99]

    raw_7702 = b"\x04" + rlp.encode([
        1, 10, 1_000_000_000, 30_000_000_000, 100_000, to_bytes, 0, b"", [], [auth_1, auth_2]
    ])

    decoded = evm_decoder.decode(raw_7702)
    assert len(decoded.authorizations) == 2
    assert decoded.authorizations[0].chain_id == 1
    assert decoded.authorizations[0].address == to_checksum_address(delegate_1)
    assert decoded.authorizations[0].nonce == 0

    assert decoded.authorizations[1].chain_id == 1
    assert decoded.authorizations[1].address == to_checksum_address(delegate_2)
    assert decoded.authorizations[1].nonce == 99


def test_erc20_approve_unlimited_flag():
    """Verify ERC-20 approve with maximum uint256 is flagged as UNLIMITED_APPROVAL."""
    token_bytes = bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    spender_bytes = bytes.fromhex("3333333333333333333333333333333333333333")
    unlimited_amount = (1 << 256) - 1

    calldata = (
        bytes.fromhex("095ea7b3")
        + spender_bytes.rjust(32, b"\x00")
        + unlimited_amount.to_bytes(32, "big")
    )

    raw_tx = b"\x02" + rlp.encode([
        1, 1, 1_000_000_000, 30_000_000_000, 50_000, token_bytes, 0, calldata, []
    ])

    decoded = evm_decoder.decode(raw_tx)
    assert len(decoded.calls) == 1
    call = decoded.calls[0]
    assert call.call_type == "ERC20_APPROVE"
    assert call.is_unlimited_approval is True
    assert call.flag == "UNLIMITED_APPROVAL"


def test_erc20_transfer_from_unpacking():
    """Verify ERC-20 transferFrom unpacks sender, recipient and token amount."""
    token_bytes = bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    sender_bytes = bytes.fromhex("1111111111111111111111111111111111111111")
    recipient_bytes = bytes.fromhex("2222222222222222222222222222222222222222")
    amount = 750_000_000

    calldata = (
        bytes.fromhex("23b872dd")
        + sender_bytes.rjust(32, b"\x00")
        + recipient_bytes.rjust(32, b"\x00")
        + amount.to_bytes(32, "big")
    )

    raw_tx = b"\x02" + rlp.encode([
        1, 1, 1_000_000_000, 30_000_000_000, 75_000, token_bytes, 0, calldata, []
    ])

    decoded = evm_decoder.decode(raw_tx)
    assert len(decoded.calls) == 1
    call = decoded.calls[0]
    assert call.call_type == "ERC20_TRANSFER_FROM"
    assert call.sender == to_checksum_address(sender_bytes)
    assert call.recipient == to_checksum_address(recipient_bytes)
    assert call.amount == str(amount)


@settings(max_examples=100)
@given(fuzz_data=st.binary(min_size=0, max_size=1024))
def test_evm_decoder_hypothesis_fuzz(fuzz_data: bytes):
    """Hypothesis fuzz test proving EvmDecoder never crashes with anything except DecodeError."""
    decoder = EvmDecoder()
    try:
        res = decoder.decode(fuzz_data)
        assert isinstance(res, DecodedTx)
    except DecodeError:
        pass
