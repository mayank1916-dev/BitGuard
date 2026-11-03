"""Canonical EVM raw transaction decoder supporting legacy, EIP-2930, EIP-1559, and EIP-7702 (Milestone S06 / F4)."""

import logging
from typing import Any

import rlp
from eth_account import Account
from eth_utils import keccak, to_checksum_address

from services.bitguard.decoders.base import ChainDecoder, DecodeError
from services.bitguard.models import AuthorizationItem, CallItem, DecodedTx, FeeDetail

logger = logging.getLogger(__name__)

# Known chain names by chain_id
KNOWN_CHAINS: dict[int, str] = {
    1: "ethereum",
    5: "goerli",
    11155111: "sepolia",
    10: "optimism",
    42161: "arbitrum",
    8453: "base",
    137: "polygon",
    56: "bsc",
    31337: "anvil",
}

# Standard ERC-20 Function Selectors
SELECTOR_ERC20_TRANSFER = "0xa9059cbb"  # transfer(address,uint256)
SELECTOR_ERC20_APPROVE = "0x095ea7b3"  # approve(address,uint256)
SELECTOR_ERC20_TRANSFER_FROM = "0x23b872dd"  # transferFrom(address,address,uint256)

# Threshold for unlimited token approvals (>= 2^255 - 1)
UNLIMITED_APPROVAL_THRESHOLD = (1 << 255) - 1


def int_from_bytes(val: Any) -> int:
    """Parses integer from RLP item enforcing canonical encoding (no leading zero bytes)."""
    if isinstance(val, int):
        return val
    if isinstance(val, bytes):
        if len(val) > 1 and val[0] == 0:
            raise DecodeError("Non-canonical integer encoding: leading zeroes present")
        return int.from_bytes(val, "big")
    raise DecodeError(f"Expected bytes or integer for numeric field, got {type(val).__name__}")


def format_address(addr_bytes: bytes) -> str | None:
    """Validates 20-byte address length and returns EIP-55 checksum string, or None for empty contract creation."""
    if len(addr_bytes) == 0:
        return None
    if len(addr_bytes) != 20:
        raise DecodeError(f"Invalid EVM address length: expected 20 bytes, got {len(addr_bytes)}")
    return to_checksum_address(addr_bytes)


class EvmDecoder(ChainDecoder):
    """Decodes raw unsigned EVM transactions strictly from byte streams (Invariant #4)."""

    def decode(self, raw_bytes: bytes | str) -> DecodedTx:
        """Decodes raw transaction bytes into canonical DecodedTx structure.

        Supports:
        - Legacy transactions (pre-EIP-155 and EIP-155)
        - Type 0x01 (EIP-2930 Access List)
        - Type 0x02 (EIP-1559 Dynamic Fee)
        - Type 0x04 (EIP-7702 Set Code Transaction with authorization list)
        """
        # 1. Normalize input to bytes
        tx_bytes = self._normalize_bytes(raw_bytes)
        if len(tx_bytes) == 0:
            raise DecodeError("Empty raw transaction payload")

        first_byte = tx_bytes[0]

        # 2. Identify transaction envelope type (EIP-2718)
        if first_byte == 0x01:
            return self._decode_eip2930(tx_bytes)
        elif first_byte == 0x02:
            return self._decode_eip1559(tx_bytes)
        elif first_byte == 0x04:
            return self._decode_eip7702(tx_bytes)
        elif first_byte >= 0xC0:
            return self._decode_legacy(tx_bytes)
        else:
            raise DecodeError(
                f"Unsupported or invalid transaction envelope prefix: 0x{first_byte:02x}"
            )

    def _normalize_bytes(self, raw_bytes: bytes | str) -> bytes:
        """Converts hex strings or bytes into raw bytes."""
        if isinstance(raw_bytes, str):
            clean = raw_bytes.strip()
            if clean.startswith(("0x", "0X")):
                clean = clean[2:]
            if not clean:
                raise DecodeError("Empty hex string supplied")
            try:
                return bytes.fromhex(clean)
            except ValueError as exc:
                raise DecodeError(f"Invalid hexadecimal encoding: {exc}") from exc
        elif isinstance(raw_bytes, (bytes, bytearray)):
            return bytes(raw_bytes)
        raise DecodeError(f"Expected bytes or hex string, got {type(raw_bytes).__name__}")

    def _rlp_decode_canonical(self, rlp_payload: bytes) -> list[Any]:
        """Decodes RLP payload asserting no trailing garbage and canonical encoding."""
        try:
            items = rlp.decode(rlp_payload)
            if not isinstance(items, (list, tuple)):
                raise DecodeError(f"Expected RLP list for transaction payload, got {type(items).__name__}")

            re_encoded = rlp.encode(items)
            if re_encoded != rlp_payload:
                raise DecodeError("Trailing garbage or non-canonical RLP encoding detected")
            return list(items)
        except DecodeError:
            raise
        except Exception as exc:
            raise DecodeError(f"RLP decoding failure: {exc}") from exc

    def _decode_legacy(self, tx_bytes: bytes) -> DecodedTx:
        """Decodes legacy transactions (6 items pre-EIP-155 or 9 items EIP-155 / signed)."""
        items = self._rlp_decode_canonical(tx_bytes)
        if len(items) not in (6, 9):
            raise DecodeError(f"Legacy transaction must have 6 or 9 elements, got {len(items)}")

        nonce = int_from_bytes(items[0])
        gas_price = int_from_bytes(items[1])
        gas_limit = int_from_bytes(items[2])
        to_address = format_address(items[3])
        value = int_from_bytes(items[4])
        data = items[5] if isinstance(items[5], bytes) else bytes(items[5])

        chain_id = 1
        is_signed = False

        if len(items) == 9:
            v = int_from_bytes(items[6])
            r = int_from_bytes(items[7])
            s = int_from_bytes(items[8])

            if r == 0 and s == 0:
                # EIP-155 unsigned payload: v is chain_id
                chain_id = v if v > 0 else 1
                signing_payload = rlp.encode(
                    [nonce, gas_price, gas_limit, items[3], value, data, chain_id, 0, 0]
                )
            else:
                is_signed = True
                chain_id = (v - 35) // 2 if v >= 35 else 1
                signing_payload = rlp.encode(
                    [nonce, gas_price, gas_limit, items[3], value, data, chain_id, 0, 0]
                )
        else:
            signing_payload = rlp.encode([nonce, gas_price, gas_limit, items[3], value, data])

        digest = "0x" + keccak(signing_payload).hex()
        from_address = self._recover_signer(tx_bytes) if is_signed else "0x0000000000000000000000000000000000000000"

        calls, asset, amount = self._decode_calls(to_address, value, data)

        return DecodedTx(
            chain=KNOWN_CHAINS.get(chain_id, f"eip155:{chain_id}"),
            from_address=from_address,
            to_address=to_address,
            asset=asset,
            amount=str(amount),
            calls=calls,
            authorizations=[],
            fee=FeeDetail(
                gas_limit=gas_limit,
                max_fee_per_gas=str(gas_price),
                max_priority_fee_per_gas=str(gas_price),
            ),
            digest=digest,
        )

    def _decode_eip2930(self, tx_bytes: bytes) -> DecodedTx:
        """Decodes Type 0x01 (EIP-2930 Access List) transactions."""
        items = self._rlp_decode_canonical(tx_bytes[1:])
        if len(items) not in (8, 11):
            raise DecodeError(f"Type 1 transaction must contain 8 or 11 elements, got {len(items)}")

        chain_id = int_from_bytes(items[0])
        nonce = int_from_bytes(items[1])
        gas_price = int_from_bytes(items[2])
        gas_limit = int_from_bytes(items[3])
        to_address = format_address(items[4])
        value = int_from_bytes(items[5])
        data = items[6] if isinstance(items[6], bytes) else bytes(items[6])
        access_list = items[7]
        if not isinstance(access_list, (list, tuple)):
            raise DecodeError("Access list in Type 1 transaction must be an RLP list")

        signing_payload = b"\x01" + rlp.encode(
            [chain_id, nonce, gas_price, gas_limit, items[4], value, data, access_list]
        )
        digest = "0x" + keccak(signing_payload).hex()

        is_signed = len(items) == 11
        from_address = self._recover_signer(tx_bytes) if is_signed else "0x0000000000000000000000000000000000000000"

        calls, asset, amount = self._decode_calls(to_address, value, data)

        return DecodedTx(
            chain=KNOWN_CHAINS.get(chain_id, f"eip155:{chain_id}"),
            from_address=from_address,
            to_address=to_address,
            asset=asset,
            amount=str(amount),
            calls=calls,
            authorizations=[],
            fee=FeeDetail(
                gas_limit=gas_limit,
                max_fee_per_gas=str(gas_price),
                max_priority_fee_per_gas=str(gas_price),
            ),
            digest=digest,
        )

    def _decode_eip1559(self, tx_bytes: bytes) -> DecodedTx:
        """Decodes Type 0x02 (EIP-1559 Dynamic Fee) transactions."""
        items = self._rlp_decode_canonical(tx_bytes[1:])
        if len(items) not in (9, 12):
            raise DecodeError(f"Type 2 transaction must contain 9 or 12 elements, got {len(items)}")

        chain_id = int_from_bytes(items[0])
        nonce = int_from_bytes(items[1])
        max_priority_fee = int_from_bytes(items[2])
        max_fee = int_from_bytes(items[3])
        gas_limit = int_from_bytes(items[4])
        to_address = format_address(items[5])
        value = int_from_bytes(items[6])
        data = items[7] if isinstance(items[7], bytes) else bytes(items[7])
        access_list = items[8]
        if not isinstance(access_list, (list, tuple)):
            raise DecodeError("Access list in Type 2 transaction must be an RLP list")

        signing_payload = b"\x02" + rlp.encode(
            [chain_id, nonce, max_priority_fee, max_fee, gas_limit, items[5], value, data, access_list]
        )
        digest = "0x" + keccak(signing_payload).hex()

        is_signed = len(items) == 12
        from_address = self._recover_signer(tx_bytes) if is_signed else "0x0000000000000000000000000000000000000000"

        calls, asset, amount = self._decode_calls(to_address, value, data)

        return DecodedTx(
            chain=KNOWN_CHAINS.get(chain_id, f"eip155:{chain_id}"),
            from_address=from_address,
            to_address=to_address,
            asset=asset,
            amount=str(amount),
            calls=calls,
            authorizations=[],
            fee=FeeDetail(
                gas_limit=gas_limit,
                max_fee_per_gas=str(max_fee),
                max_priority_fee_per_gas=str(max_priority_fee),
            ),
            digest=digest,
        )

    def _decode_eip7702(self, tx_bytes: bytes) -> DecodedTx:
        """Decodes Type 0x04 (EIP-7702 Set Code) transactions parsing the authorization list."""
        items = self._rlp_decode_canonical(tx_bytes[1:])
        if len(items) not in (10, 13):
            raise DecodeError(f"Type 4 transaction must contain 10 or 13 elements, got {len(items)}")

        chain_id = int_from_bytes(items[0])
        nonce = int_from_bytes(items[1])
        max_priority_fee = int_from_bytes(items[2])
        max_fee = int_from_bytes(items[3])
        gas_limit = int_from_bytes(items[4])
        to_address = format_address(items[5])
        value = int_from_bytes(items[6])
        data = items[7] if isinstance(items[7], bytes) else bytes(items[7])
        access_list = items[8]
        raw_authorizations = items[9]

        if not isinstance(access_list, (list, tuple)):
            raise DecodeError("Access list in Type 4 transaction must be an RLP list")
        if not isinstance(raw_authorizations, (list, tuple)):
            raise DecodeError("EIP-7702 authorization list must be an RLP list")

        # Parse EIP-7702 authorization items
        authorizations: list[AuthorizationItem] = []
        for idx, auth in enumerate(raw_authorizations):
            if not isinstance(auth, (list, tuple)) or len(auth) < 3:
                raise DecodeError(
                    f"EIP-7702 authorization #{idx} must contain at least [chain_id, address, nonce]"
                )
            auth_chain_id = int_from_bytes(auth[0])
            auth_addr_bytes = auth[1]
            if len(auth_addr_bytes) != 20:
                raise DecodeError(
                    f"EIP-7702 delegate address in item #{idx} must be 20 bytes, got {len(auth_addr_bytes)}"
                )
            auth_address = to_checksum_address(auth_addr_bytes)
            auth_nonce = int_from_bytes(auth[2])

            authority: str | None = None
            if len(auth) >= 6:
                try:
                    y_parity = int_from_bytes(auth[3])
                    r = int_from_bytes(auth[4])
                    s = int_from_bytes(auth[5])
                    if r > 0 and s > 0:
                        v = y_parity if y_parity in [27, 28] else (27 + (y_parity % 2))
                        auth_digest = keccak(
                            b"\x05" + rlp.encode([auth_chain_id, auth_addr_bytes, auth_nonce])
                        )
                        authority = Account._recover_hash(auth_digest, vrs=(v, r, s))
                except Exception:
                    authority = None

            authorizations.append(
                AuthorizationItem(
                    chain_id=auth_chain_id,
                    address=auth_address,
                    nonce=auth_nonce,
                    authority=authority,
                )
            )

        signing_payload = b"\x04" + rlp.encode(
            [
                chain_id,
                nonce,
                max_priority_fee,
                max_fee,
                gas_limit,
                items[5],
                value,
                data,
                access_list,
                raw_authorizations,
            ]
        )
        digest = "0x" + keccak(signing_payload).hex()

        is_signed = len(items) == 13
        from_address = self._recover_signer(tx_bytes) if is_signed else "0x0000000000000000000000000000000000000000"

        calls, asset, amount = self._decode_calls(to_address, value, data)

        return DecodedTx(
            chain=KNOWN_CHAINS.get(chain_id, f"eip155:{chain_id}"),
            from_address=from_address,
            to_address=to_address,
            asset=asset,
            amount=str(amount),
            calls=calls,
            authorizations=authorizations,
            fee=FeeDetail(
                gas_limit=gas_limit,
                max_fee_per_gas=str(max_fee),
                max_priority_fee_per_gas=str(max_priority_fee),
            ),
            digest=digest,
        )

    def _decode_calls(
        self,
        to_address: str | None,
        value: int,
        data: bytes,
    ) -> tuple[list[CallItem], str, int]:
        """Decodes calldata into CallItem structures recognizing native transfers and ERC-20 calls."""
        dest = to_address or "0x0000000000000000000000000000000000000000"

        if len(data) == 0:
            # Native ETH transfer
            call = CallItem(
                to=dest,
                value=str(value),
                data="0x",
                selector=None,
                call_type="NATIVE_TRANSFER",
                recipient=to_address,
                amount=str(value),
                flag=None,
            )
            return [call], "ETH", value

        if len(data) < 4:
            # Calldata too short to form a selector -> RAW_CALL with UNKNOWN_SELECTOR
            call = CallItem(
                to=dest,
                value=str(value),
                data="0x" + data.hex(),
                selector="0x" + data.hex(),
                call_type="RAW_CALL",
                flag="UNKNOWN_SELECTOR",
            )
            return [call], "ETH", value

        selector = "0x" + data[:4].hex().lower()

        if selector == SELECTOR_ERC20_TRANSFER:
            # transfer(address recipient, uint256 amount)
            if len(data) != 68:
                raise DecodeError(
                    f"ERC-20 transfer calldata must be exactly 68 bytes, got {len(data)}"
                )
            recipient = to_checksum_address(data[16:36])
            token_amount = int.from_bytes(data[36:68], "big")
            call = CallItem(
                to=dest,
                value=str(value),
                data="0x" + data.hex(),
                selector=SELECTOR_ERC20_TRANSFER,
                call_type="ERC20_TRANSFER",
                recipient=recipient,
                amount=str(token_amount),
            )
            return [call], dest, token_amount

        elif selector == SELECTOR_ERC20_APPROVE:
            # approve(address spender, uint256 amount)
            if len(data) != 68:
                raise DecodeError(
                    f"ERC-20 approve calldata must be exactly 68 bytes, got {len(data)}"
                )
            spender = to_checksum_address(data[16:36])
            token_amount = int.from_bytes(data[36:68], "big")
            is_unlimited = token_amount >= UNLIMITED_APPROVAL_THRESHOLD
            flag = "UNLIMITED_APPROVAL" if is_unlimited else None
            call = CallItem(
                to=dest,
                value=str(value),
                data="0x" + data.hex(),
                selector=SELECTOR_ERC20_APPROVE,
                call_type="ERC20_APPROVE",
                recipient=spender,
                amount=str(token_amount),
                is_unlimited_approval=is_unlimited,
                flag=flag,
            )
            return [call], dest, token_amount

        elif selector == SELECTOR_ERC20_TRANSFER_FROM:
            # transferFrom(address sender, address recipient, uint256 amount)
            if len(data) != 100:
                raise DecodeError(
                    f"ERC-20 transferFrom calldata must be exactly 100 bytes, got {len(data)}"
                )
            sender = to_checksum_address(data[16:36])
            recipient = to_checksum_address(data[48:68])
            token_amount = int.from_bytes(data[68:100], "big")
            call = CallItem(
                to=dest,
                value=str(value),
                data="0x" + data.hex(),
                selector=SELECTOR_ERC20_TRANSFER_FROM,
                call_type="ERC20_TRANSFER_FROM",
                sender=sender,
                recipient=recipient,
                amount=str(token_amount),
            )
            return [call], dest, token_amount

        else:
            # Unknown selector -> RAW_CALL with UNKNOWN_SELECTOR flag
            call = CallItem(
                to=dest,
                value=str(value),
                data="0x" + data.hex(),
                selector=selector,
                call_type="RAW_CALL",
                flag="UNKNOWN_SELECTOR",
            )
            return [call], "ETH", value

    def _recover_signer(self, signed_bytes: bytes) -> str:
        """Recovers signing address from signed raw transaction bytes."""
        try:
            return Account.recover_transaction(signed_bytes)
        except Exception:
            return "0x0000000000000000000000000000000000000000"


# Singleton instance
evm_decoder = EvmDecoder()
