"""Generates comprehensive test vectors for EVM transaction decoding (Milestone S06 / F4)."""

import json
from pathlib import Path

import rlp
from eth_utils import to_checksum_address


def make_erc20_transfer_data(recipient: str, amount: int) -> bytes:
    selector = bytes.fromhex("a9059cbb")
    clean_recip = bytes.fromhex(recipient[2:] if recipient.startswith("0x") else recipient)
    recip_padded = clean_recip.rjust(32, b"\x00")
    amount_padded = amount.to_bytes(32, "big")
    return selector + recip_padded + amount_padded


def make_erc20_approve_data(spender: str, amount: int) -> bytes:
    selector = bytes.fromhex("095ea7b3")
    clean_spender = bytes.fromhex(spender[2:] if spender.startswith("0x") else spender)
    spender_padded = clean_spender.rjust(32, b"\x00")
    amount_padded = amount.to_bytes(32, "big")
    return selector + spender_padded + amount_padded


def make_erc20_transfer_from_data(sender: str, recipient: str, amount: int) -> bytes:
    selector = bytes.fromhex("23b872dd")
    clean_sender = bytes.fromhex(sender[2:] if sender.startswith("0x") else sender)
    clean_recip = bytes.fromhex(recipient[2:] if recipient.startswith("0x") else recipient)
    sender_padded = clean_sender.rjust(32, b"\x00")
    recip_padded = clean_recip.rjust(32, b"\x00")
    amount_padded = amount.to_bytes(32, "big")
    return selector + sender_padded + recip_padded + amount_padded


def generate_all_vectors() -> list[dict]:
    vectors = []
    to_addr_hex = "742d35Cc6634C0532925a3b844Bc454e4438f44e"
    to_bytes = bytes.fromhex(to_addr_hex)
    token_addr_hex = "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    token_bytes = bytes.fromhex(token_addr_hex)
    recip_hex = "1111111111111111111111111111111111111111"
    spender_hex = "2222222222222222222222222222222222222222"
    sender_hex = "3333333333333333333333333333333333333333"

    # --- VALID VECTORS ---

    # 1. Legacy EIP-155 Native Transfer
    raw_01 = rlp.encode([1, 20_000_000_000, 21_000, to_bytes, 1_000_000_000_000_000_000, b"", 1, 0, 0])
    vectors.append({
        "id": "legacy_eip155_native_transfer",
        "raw_hex": "0x" + raw_01.hex(),
        "is_valid": True,
        "type": "legacy",
        "to": to_checksum_address(to_bytes),
        "asset": "ETH",
        "amount": "1000000000000000000",
        "call_type": "NATIVE_TRANSFER",
    })

    # 2. Legacy Pre-155 Native Transfer (6 items)
    raw_02 = rlp.encode([2, 25_000_000_000, 21_000, to_bytes, 500_000_000_000_000_000, b""])
    vectors.append({
        "id": "legacy_pre155_native_transfer",
        "raw_hex": "0x" + raw_02.hex(),
        "is_valid": True,
        "type": "legacy",
        "to": to_checksum_address(to_bytes),
        "asset": "ETH",
        "amount": "500000000000000000",
        "call_type": "NATIVE_TRANSFER",
    })

    # 3. Legacy ERC-20 Transfer
    data_transfer = make_erc20_transfer_data(recip_hex, 1000 * 10**6)
    raw_03 = rlp.encode([3, 20_000_000_000, 65_000, token_bytes, 0, data_transfer, 1, 0, 0])
    vectors.append({
        "id": "legacy_erc20_transfer",
        "raw_hex": "0x" + raw_03.hex(),
        "is_valid": True,
        "type": "legacy",
        "to": to_checksum_address(token_bytes),
        "asset": to_checksum_address(token_bytes),
        "amount": str(1000 * 10**6),
        "call_type": "ERC20_TRANSFER",
    })

    # 4. Legacy ERC-20 Approve (standard)
    data_approve = make_erc20_approve_data(spender_hex, 500 * 10**6)
    raw_04 = rlp.encode([4, 20_000_000_000, 45_000, token_bytes, 0, data_approve, 1, 0, 0])
    vectors.append({
        "id": "legacy_erc20_approve",
        "raw_hex": "0x" + raw_04.hex(),
        "is_valid": True,
        "type": "legacy",
        "to": to_checksum_address(token_bytes),
        "asset": to_checksum_address(token_bytes),
        "amount": str(500 * 10**6),
        "call_type": "ERC20_APPROVE",
        "is_unlimited": False,
    })

    # 5. Legacy ERC-20 Approve Unlimited (2^256 - 1)
    unlimited_val = (1 << 256) - 1
    data_approve_unlim = make_erc20_approve_data(spender_hex, unlimited_val)
    raw_05 = rlp.encode([5, 20_000_000_000, 45_000, token_bytes, 0, data_approve_unlim, 1, 0, 0])
    vectors.append({
        "id": "legacy_erc20_approve_unlimited",
        "raw_hex": "0x" + raw_05.hex(),
        "is_valid": True,
        "type": "legacy",
        "to": to_checksum_address(token_bytes),
        "asset": to_checksum_address(token_bytes),
        "amount": str(unlimited_val),
        "call_type": "ERC20_APPROVE",
        "is_unlimited": True,
        "flag": "UNLIMITED_APPROVAL",
    })

    # 6. Legacy ERC-20 TransferFrom
    data_tf = make_erc20_transfer_from_data(sender_hex, recip_hex, 250 * 10**6)
    raw_06 = rlp.encode([6, 20_000_000_000, 75_000, token_bytes, 0, data_tf, 1, 0, 0])
    vectors.append({
        "id": "legacy_erc20_transfer_from",
        "raw_hex": "0x" + raw_06.hex(),
        "is_valid": True,
        "type": "legacy",
        "to": to_checksum_address(token_bytes),
        "asset": to_checksum_address(token_bytes),
        "amount": str(250 * 10**6),
        "call_type": "ERC20_TRANSFER_FROM",
    })

    # 7. Legacy Contract Creation (to = b"")
    init_code = bytes.fromhex("6080604052348015600f57600080fd5b50")
    raw_07 = rlp.encode([7, 20_000_000_000, 150_000, b"", 0, init_code, 1, 0, 0])
    vectors.append({
        "id": "legacy_contract_creation",
        "raw_hex": "0x" + raw_07.hex(),
        "is_valid": True,
        "type": "legacy",
        "to": None,
        "asset": "ETH",
        "amount": "0",
        "call_type": "RAW_CALL",
    })

    # 8. Legacy Unknown Function Selector
    unknown_data = bytes.fromhex("deadbeef0000000000000000000000001234567890123456789012345678901234567890")
    raw_08 = rlp.encode([8, 20_000_000_000, 50_000, to_bytes, 0, unknown_data, 1, 0, 0])
    vectors.append({
        "id": "legacy_unknown_selector",
        "raw_hex": "0x" + raw_08.hex(),
        "is_valid": True,
        "type": "legacy",
        "to": to_checksum_address(to_bytes),
        "asset": "ETH",
        "amount": "0",
        "call_type": "RAW_CALL",
        "flag": "UNKNOWN_SELECTOR",
    })

    # 9. Type 1 (EIP-2930) Native Transfer
    raw_09 = b"\x01" + rlp.encode([1, 9, 20_000_000_000, 21_000, to_bytes, 2_000_000_000_000_000_000, b"", []])
    vectors.append({
        "id": "eip2930_native_transfer",
        "raw_hex": "0x" + raw_09.hex(),
        "is_valid": True,
        "type": "0x01",
        "to": to_checksum_address(to_bytes),
        "asset": "ETH",
        "amount": "2000000000000000000",
        "call_type": "NATIVE_TRANSFER",
    })

    # 10. Type 1 (EIP-2930) ERC-20 Transfer
    raw_10 = b"\x01" + rlp.encode([1, 10, 20_000_000_000, 65_000, token_bytes, 0, data_transfer, []])
    vectors.append({
        "id": "eip2930_erc20_transfer",
        "raw_hex": "0x" + raw_10.hex(),
        "is_valid": True,
        "type": "0x01",
        "to": to_checksum_address(token_bytes),
        "asset": to_checksum_address(token_bytes),
        "amount": str(1000 * 10**6),
        "call_type": "ERC20_TRANSFER",
    })

    # 11. Type 1 (EIP-2930) With Access List
    storage_key = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
    access_list = [[to_bytes, [storage_key]]]
    raw_11 = b"\x01" + rlp.encode([1, 11, 20_000_000_000, 30_000, to_bytes, 100, b"", access_list])
    vectors.append({
        "id": "eip2930_with_access_list",
        "raw_hex": "0x" + raw_11.hex(),
        "is_valid": True,
        "type": "0x01",
        "to": to_checksum_address(to_bytes),
        "asset": "ETH",
        "amount": "100",
    })

    # 12. Type 2 (EIP-1559) Native Transfer
    raw_12 = b"\x02" + rlp.encode([1, 12, 1_000_000_000, 30_000_000_000, 21_000, to_bytes, 10**18, b"", []])
    vectors.append({
        "id": "eip1559_native_transfer",
        "raw_hex": "0x" + raw_12.hex(),
        "is_valid": True,
        "type": "0x02",
        "to": to_checksum_address(to_bytes),
        "asset": "ETH",
        "amount": str(10**18),
        "call_type": "NATIVE_TRANSFER",
    })

    # 13. Type 2 (EIP-1559) ERC-20 Transfer
    raw_13 = b"\x02" + rlp.encode([1, 13, 1_500_000_000, 35_000_000_000, 65_000, token_bytes, 0, data_transfer, []])
    vectors.append({
        "id": "eip1559_erc20_transfer",
        "raw_hex": "0x" + raw_13.hex(),
        "is_valid": True,
        "type": "0x02",
        "to": to_checksum_address(token_bytes),
        "asset": to_checksum_address(token_bytes),
        "amount": str(1000 * 10**6),
        "call_type": "ERC20_TRANSFER",
    })

    # 14. Type 2 (EIP-1559) ERC-20 Approve (Standard)
    raw_14 = b"\x02" + rlp.encode([1, 14, 1_000_000_000, 30_000_000_000, 45_000, token_bytes, 0, data_approve, []])
    vectors.append({
        "id": "eip1559_erc20_approve",
        "raw_hex": "0x" + raw_14.hex(),
        "is_valid": True,
        "type": "0x02",
        "to": to_checksum_address(token_bytes),
        "asset": to_checksum_address(token_bytes),
        "amount": str(500 * 10**6),
        "call_type": "ERC20_APPROVE",
        "is_unlimited": False,
    })

    # 15. Type 2 (EIP-1559) ERC-20 Approve Unlimited
    raw_15 = b"\x02" + rlp.encode([1, 15, 1_000_000_000, 30_000_000_000, 45_000, token_bytes, 0, data_approve_unlim, []])
    vectors.append({
        "id": "eip1559_erc20_approve_unlimited",
        "raw_hex": "0x" + raw_15.hex(),
        "is_valid": True,
        "type": "0x02",
        "to": to_checksum_address(token_bytes),
        "asset": to_checksum_address(token_bytes),
        "amount": str(unlimited_val),
        "call_type": "ERC20_APPROVE",
        "is_unlimited": True,
        "flag": "UNLIMITED_APPROVAL",
    })

    # 16. Type 2 (EIP-1559) ERC-20 TransferFrom
    raw_16 = b"\x02" + rlp.encode([1, 16, 1_000_000_000, 30_000_000_000, 75_000, token_bytes, 0, data_tf, []])
    vectors.append({
        "id": "eip1559_erc20_transfer_from",
        "raw_hex": "0x" + raw_16.hex(),
        "is_valid": True,
        "type": "0x02",
        "to": to_checksum_address(token_bytes),
        "asset": to_checksum_address(token_bytes),
        "amount": str(250 * 10**6),
        "call_type": "ERC20_TRANSFER_FROM",
    })

    # 17. Type 2 (EIP-1559) With Access List
    raw_17 = b"\x02" + rlp.encode([1, 17, 1_000_000_000, 30_000_000_000, 30_000, to_bytes, 100, b"", access_list])
    vectors.append({
        "id": "eip1559_with_access_list",
        "raw_hex": "0x" + raw_17.hex(),
        "is_valid": True,
        "type": "0x02",
        "to": to_checksum_address(to_bytes),
        "asset": "ETH",
        "amount": "100",
    })

    # 18. Type 4 (EIP-7702) Single Authorization
    auth_single = [1, bytes.fromhex(recip_hex), 0]
    raw_18 = b"\x04" + rlp.encode([1, 18, 1_000_000_000, 30_000_000_000, 50_000, to_bytes, 0, b"", [], [auth_single]])
    vectors.append({
        "id": "eip7702_single_authorization",
        "raw_hex": "0x" + raw_18.hex(),
        "is_valid": True,
        "type": "0x04",
        "authorizations_count": 1,
        "auth_0_address": to_checksum_address(bytes.fromhex(recip_hex)),
        "auth_0_nonce": 0,
    })

    # 19. Type 4 (EIP-7702) Two Authorizations
    auth_1 = [1, bytes.fromhex(recip_hex), 0]
    auth_2 = [1, bytes.fromhex(spender_hex), 5]
    raw_19 = b"\x04" + rlp.encode([1, 19, 1_000_000_000, 30_000_000_000, 60_000, to_bytes, 0, b"", [], [auth_1, auth_2]])
    vectors.append({
        "id": "eip7702_two_authorizations",
        "raw_hex": "0x" + raw_19.hex(),
        "is_valid": True,
        "type": "0x04",
        "authorizations_count": 2,
        "auth_0_address": to_checksum_address(bytes.fromhex(recip_hex)),
        "auth_0_nonce": 0,
        "auth_1_address": to_checksum_address(bytes.fromhex(spender_hex)),
        "auth_1_nonce": 5,
    })

    # 20. Type 4 (EIP-7702) With ERC-20 Transfer
    raw_20 = b"\x04" + rlp.encode([1, 20, 1_000_000_000, 30_000_000_000, 90_000, token_bytes, 0, data_transfer, [], [auth_1, auth_2]])
    vectors.append({
        "id": "eip7702_with_erc20_transfer",
        "raw_hex": "0x" + raw_20.hex(),
        "is_valid": True,
        "type": "0x04",
        "to": to_checksum_address(token_bytes),
        "asset": to_checksum_address(token_bytes),
        "amount": str(1000 * 10**6),
        "call_type": "ERC20_TRANSFER",
        "authorizations_count": 2,
    })

    # --- MALFORMED VECTORS (At least 10) ---

    # 21. Malformed Empty
    vectors.append({
        "id": "malformed_empty",
        "raw_hex": "0x",
        "is_valid": False,
        "expected_error": "Empty",
    })

    # 22. Malformed Non-Hex
    vectors.append({
        "id": "malformed_non_hex",
        "raw_hex": "0xnot_a_valid_hex_string_12345",
        "is_valid": False,
        "expected_error": "Invalid hexadecimal",
    })

    # 23. Malformed Unknown Type 0x03
    raw_bad_type = b"\x03" + rlp.encode([1, 1, 100, 21000, to_bytes, 0, b"", []])
    vectors.append({
        "id": "malformed_unknown_tx_type_03",
        "raw_hex": "0x" + raw_bad_type.hex(),
        "is_valid": False,
        "expected_error": "Unsupported or invalid transaction envelope prefix: 0x03",
    })

    # 24. Malformed Unknown Type 0x05
    raw_bad_type5 = b"\x05" + rlp.encode([1, 1, 100, 21000, to_bytes, 0, b"", []])
    vectors.append({
        "id": "malformed_unknown_tx_type_05",
        "raw_hex": "0x" + raw_bad_type5.hex(),
        "is_valid": False,
        "expected_error": "Unsupported or invalid transaction envelope prefix: 0x05",
    })

    # 25. Malformed Legacy Trailing Garbage
    vectors.append({
        "id": "malformed_legacy_trailing_garbage",
        "raw_hex": "0x" + raw_01.hex() + "deadbeef",
        "is_valid": False,
        "expected_error": "Trailing garbage",
    })

    # 26. Malformed 1559 Trailing Garbage
    vectors.append({
        "id": "malformed_1559_trailing_garbage",
        "raw_hex": "0x" + raw_12.hex() + "cafebabe1234",
        "is_valid": False,
        "expected_error": "Trailing garbage",
    })

    # 27. Malformed Truncated RLP
    # Cut in half
    vectors.append({
        "id": "malformed_truncated_rlp",
        "raw_hex": "0x" + raw_12[: len(raw_12) // 2].hex(),
        "is_valid": False,
        "expected_error": "RLP decoding failure",
    })

    # 28. Malformed Invalid Address Length (19 bytes instead of 20)
    bad_addr = bytes.fromhex("742d35Cc6634C0532925a3b844Bc454e4438f4")  # 19 bytes
    raw_bad_addr = b"\x02" + rlp.encode([1, 1, 1000, 3000, 21000, bad_addr, 0, b"", []])
    vectors.append({
        "id": "malformed_invalid_address_length",
        "raw_hex": "0x" + raw_bad_addr.hex(),
        "is_valid": False,
        "expected_error": "Invalid EVM address length",
    })

    # 29. Malformed ERC-20 Calldata Truncated (less than 68 bytes)
    truncated_erc20 = bytes.fromhex("a9059cbb11111111111111111111111111111111")
    raw_trunc_erc20 = b"\x02" + rlp.encode([1, 1, 1000, 3000, 21000, to_bytes, 0, truncated_erc20, []])
    vectors.append({
        "id": "malformed_erc20_truncated_calldata",
        "raw_hex": "0x" + raw_trunc_erc20.hex(),
        "is_valid": False,
        "expected_error": "ERC-20 transfer calldata must be exactly 68 bytes",
    })

    # 30. Malformed ERC-20 transferFrom Calldata Truncated (less than 100 bytes)
    truncated_tf = bytes.fromhex("23b872dd" + "00" * 32 + "11" * 32)  # only 68 bytes instead of 100
    raw_trunc_tf = b"\x02" + rlp.encode([1, 1, 1000, 3000, 21000, to_bytes, 0, truncated_tf, []])
    vectors.append({
        "id": "malformed_erc20_transfer_from_truncated",
        "raw_hex": "0x" + raw_trunc_tf.hex(),
        "is_valid": False,
        "expected_error": "ERC-20 transferFrom calldata must be exactly 100 bytes",
    })

    # 31. Malformed EIP-7702 Delegate Address Length (18 bytes instead of 20)
    bad_auth = [1, bytes.fromhex("111111111111111111111111111111111111"), 0]  # 18 bytes
    raw_bad_7702 = b"\x04" + rlp.encode([1, 1, 1000, 3000, 21000, to_bytes, 0, b"", [], [bad_auth]])
    vectors.append({
        "id": "malformed_7702_invalid_delegate_address",
        "raw_hex": "0x" + raw_bad_7702.hex(),
        "is_valid": False,
        "expected_error": "EIP-7702 delegate address in item #0 must be 20 bytes",
    })

    # 32. Malformed Non-Canonical Integer with Leading Zero Byte
    # rlp.encode(b"\x00\x05") produces an RLP string containing leading zero
    raw_leading_zero = b"\x02" + rlp.encode([1, b"\x00\x05", 1000, 3000, 21000, to_bytes, 0, b"", []])
    vectors.append({
        "id": "malformed_non_canonical_integer",
        "raw_hex": "0x" + raw_leading_zero.hex(),
        "is_valid": False,
        "expected_error": "Non-canonical integer encoding: leading zeroes present",
    })

    return vectors


if __name__ == "__main__":
    vecs = generate_all_vectors()
    out_path = Path(__file__).resolve().parent / "vectors.json"
    out_path.write_text(json.dumps(vecs, indent=2) + "\n", encoding="utf-8")
    print(f"Generated {len(vecs)} vectors to {out_path}")
