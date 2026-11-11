"""Bitcoin PSBT (BIP-174 / BIP-370) transaction decoder (Milestone S34).

Invariants:
- Invariant #3: Fail-Closed Default (unknown format, parse error, corrupt bytes => DecodeError).
- Invariant #4: Raw Byte Source of Truth (strictly decode from raw PSBT bytes, ignore caller metadata).
"""

import base64
import logging
from io import BytesIO
from typing import Any

from embit import psbt, script
from embit.networks import NETWORKS

from services.bitguard.decoders.base import ChainDecoder, DecodeError
from services.bitguard.models import CallItem, DecodedTx, FeeDetail

logger = logging.getLogger("bitguard.decoders.psbt")

MAX_SATOSHIS = 21_000_000 * 100_000_000  # 21 million BTC in satoshis


def _script_to_address(s: script.Script, net: dict[str, Any] = NETWORKS["main"]) -> str:
    """Safely converts a Script to a human-readable Bitcoin address with fallbacks."""
    try:
        return s.address(net)
    except Exception:
        try:
            return s.address(NETWORKS["test"])
        except Exception:
            # Fallback for non-standard, OP_RETURN, or bare scripts
            return f"script:{s.data.hex()}"


def _is_bip32_change_path(derivation_path: list[int]) -> bool:
    """Evaluates BIP-44/49/84/86 derivation path to check if change index is 1."""
    if len(derivation_path) >= 4:
        # Standard BIP44/49/84/86: m / purpose' / coin_type' / account' / change / index
        # index 3 (or second to last) is change
        if len(derivation_path) >= 5 and derivation_path[3] == 1:
            return True
        if derivation_path[-2] == 1:
            return True
    return False


class BtcPsbtDecoder(ChainDecoder):
    """Decodes Bitcoin Partially Signed Transactions (BIP-174 / BIP-370) strictly from raw bytes."""

    def __init__(
        self,
        network: str = "main",
        default_max_fee_sats: int = 1_000_000,
        default_max_sats_per_byte: float = 250.0,
        owned_addresses: set[str] | list[str] | None = None,
    ) -> None:
        self.network_name = network
        self.default_max_fee_sats = default_max_fee_sats
        self.default_max_sats_per_byte = default_max_sats_per_byte
        self.owned_addresses = {a.strip().lower() for a in (owned_addresses or [])}

    def _resolve_network(self, chain_id: str | None) -> dict[str, Any]:
        """Maps chain identifier string to embit network dictionary."""
        if not chain_id:
            return NETWORKS["main"]
        clean = chain_id.strip().lower()
        if "test" in clean or "regtest" in clean or "signet" in clean:
            return NETWORKS.get(clean, NETWORKS["test"])
        return NETWORKS["main"]

    def decode(
        self,
        raw_bytes: bytes | str,
        policy: Any = None,
        chain: str | None = None,
    ) -> DecodedTx:
        """Decodes raw PSBT bytes into canonical DecodedTx structure.

        Args:
            raw_bytes: Raw PSBT bytes, hex-encoded string, or base64-encoded string.
            policy: Optional PolicyDocument containing owned_addresses or fee limits.
            chain: Optional chain identifier (e.g. 'bitcoin', 'bitcoin_testnet').

        Returns:
            DecodedTx: Canonical decoded transaction representation.

        Raises:
            DecodeError: If bytes are invalid, unknown type, malformed, or contain trailing data.
        """
        # 1. Parse raw input bytes from base64, hex, or direct bytes
        if raw_bytes is None:
            raise DecodeError("Raw PSBT payload cannot be None")

        if isinstance(raw_bytes, str):
            clean_str = raw_bytes.strip()
            if not clean_str:
                raise DecodeError("Raw PSBT string payload cannot be empty or whitespace")

            # Check hex prefix or pure hex encoding
            if clean_str.startswith(("0x", "0X")):
                try:
                    payload_bytes = bytes.fromhex(clean_str[2:])
                except ValueError as exc:
                    raise DecodeError(f"Invalid hex encoding in PSBT payload: {exc}") from exc
            elif clean_str.lower().startswith("70736274ff"):
                try:
                    payload_bytes = bytes.fromhex(clean_str)
                except ValueError as exc:
                    raise DecodeError(f"Invalid hex encoding in PSBT payload: {exc}") from exc
            else:
                # Base64 decode
                try:
                    payload_bytes = base64.b64decode(clean_str, validate=True)
                except Exception as exc:
                    raise DecodeError(f"Invalid base64 encoding in PSBT payload: {exc}") from exc
        elif isinstance(raw_bytes, (bytes, bytearray)):
            payload_bytes = bytes(raw_bytes)
        else:
            raise DecodeError(f"Unsupported raw payload type: {type(raw_bytes)}")

        if len(payload_bytes) < 5:
            raise DecodeError(f"PSBT payload too short ({len(payload_bytes)} bytes)")

        # Invariant #3: Fail-closed on invalid PSBT magic bytes
        if not payload_bytes.startswith(b"psbt\xff"):
            raise DecodeError(
                f"Invalid PSBT magic bytes (expected b'psbt\\xff', got {payload_bytes[:5]!r})"
            )

        # 2. Parse PSBT stream and check for trailing garbage
        bio = BytesIO(payload_bytes)
        try:
            psbt_obj = psbt.PSBT.read_from(bio)
        except Exception as exc:
            raise DecodeError(f"Failed parsing PSBT data structure: {exc}") from exc

        rem = bio.read()
        if rem:
            raise DecodeError(f"Trailing garbage detected in PSBT payload: {len(rem)} extra bytes")

        tx = psbt_obj.tx
        if tx is None:
            raise DecodeError("PSBT contains no unsigned global transaction")

        if not tx.vin:
            raise DecodeError("PSBT unsigned transaction has 0 inputs")
        if not tx.vout:
            raise DecodeError("PSBT unsigned transaction has 0 outputs")

        if len(psbt_obj.inputs) != len(tx.vin):
            raise DecodeError(
                f"PSBT input count mismatch: {len(psbt_obj.inputs)} inputs metadata vs {len(tx.vin)} transaction vin"
            )
        if len(psbt_obj.outputs) != len(tx.vout):
            raise DecodeError(
                f"PSBT output count mismatch: {len(psbt_obj.outputs)} outputs metadata vs {len(tx.vout)} transaction vout"
            )

        net = self._resolve_network(chain or self.network_name)

        # 3. Decode Inputs strictly from raw PSBT bytes
        input_items: list[CallItem] = []
        input_addresses: list[str] = []
        total_input_sats = 0

        for i, in_meta in enumerate(psbt_obj.inputs):
            vin_item = tx.vin[i]
            # Determine previous UTXO (witness or non-witness)
            prev_script: script.Script | None = None
            in_value: int | None = None

            if in_meta.witness_utxo is not None:
                in_value = in_meta.witness_utxo.value
                prev_script = in_meta.witness_utxo.script_pubkey
            elif in_meta.non_witness_utxo is not None:
                prev_tx = in_meta.non_witness_utxo
                if vin_item.vout >= len(prev_tx.vout):
                    raise DecodeError(
                        f"Input {i} vout {vin_item.vout} out of range in non_witness_utxo (len {len(prev_tx.vout)})"
                    )
                prev_out = prev_tx.vout[vin_item.vout]
                in_value = prev_out.value
                prev_script = prev_out.script_pubkey

            if in_value is None or prev_script is None:
                raise DecodeError(
                    f"Input {i} missing previous UTXO information; cannot determine value, address, or compute sighash"
                )

            if in_value < 0 or in_value > MAX_SATOSHIS:
                raise DecodeError(
                    f"Input {i} value out of valid range: {in_value} satoshis"
                )

            total_input_sats += in_value
            in_address = _script_to_address(prev_script, net)
            input_addresses.append(in_address)

            # Compute input sighash (Invariant #2 & #4)
            try:
                sighash_bytes = psbt_obj.sighash(i)
            except Exception as exc:
                raise DecodeError(f"Failed to compute signing sighash for input {i}: {exc}") from exc

            if not isinstance(sighash_bytes, (bytes, bytearray)) or len(sighash_bytes) != 32:
                raise DecodeError(
                    f"Computed sighash for input {i} must be exactly 32 bytes, got {len(sighash_bytes) if sighash_bytes else 0}"
                )

            sighash_hex = f"0x{sighash_bytes.hex()}"
            txid_hex = vin_item.txid.hex()

            input_items.append(
                CallItem(
                    to=f"{txid_hex}:{vin_item.vout}",
                    value=str(in_value),
                    amount=str(in_value),
                    call_type="INPUT",
                    sender=in_address,
                    data=sighash_hex,
                )
            )

        # 4. Decode Outputs strictly from raw PSBT bytes
        # Build owned addresses set for change output identification
        all_owned_addresses = set(self.owned_addresses)
        if policy is not None:
            if hasattr(policy, "owned_addresses"):
                all_owned_addresses.update(a.strip().lower() for a in policy.owned_addresses)
            if hasattr(policy, "known_change_addresses"):
                all_owned_addresses.update(a.strip().lower() for a in policy.known_change_addresses)

        input_addrs_set = {a.lower() for a in input_addresses}

        output_items: list[CallItem] = []
        total_external_amount = 0
        first_external_recipient: str | None = None

        for j, out_meta in enumerate(psbt_obj.outputs):
            vout_item = tx.vout[j]
            out_value = vout_item.value

            if out_value < 0 or out_value > MAX_SATOSHIS:
                raise DecodeError(
                    f"Output {j} value out of valid range: {out_value} satoshis"
                )

            out_address = _script_to_address(vout_item.script_pubkey, net)

            # Check change output conditions
            is_change = False

            # Condition A: BIP32 derivation path change flag (path[3] == 1 or path[-2] == 1)
            if out_meta.bip32_derivations:
                for der in out_meta.bip32_derivations.values():
                    if hasattr(der, "derivation") and _is_bip32_change_path(der.derivation):
                        is_change = True
                        break

            if not is_change and out_meta.taproot_bip32_derivations:
                for _leaf_hashes, der in out_meta.taproot_bip32_derivations.values():
                    if hasattr(der, "derivation") and _is_bip32_change_path(der.derivation):
                        is_change = True
                        break

            # Condition B: Address is in configured owned / internal change addresses
            if not is_change and out_address.lower() in all_owned_addresses:
                is_change = True

            # Condition C: Output address matches an originating input address (when multiple outputs)
            if not is_change and len(tx.vout) > 1 and out_address.lower() in input_addrs_set:
                is_change = True

            if is_change:
                flag = "CHANGE"
            else:
                flag = None
                total_external_amount += out_value
                if first_external_recipient is None:
                    first_external_recipient = out_address

            output_items.append(
                CallItem(
                    to=out_address,
                    value=str(out_value),
                    amount=str(out_value),
                    call_type="OUTPUT",
                    recipient=out_address,
                    flag=flag,
                )
            )

        # Fallback if all outputs are change or consolidation
        if first_external_recipient is None:
            first_external_recipient = _script_to_address(tx.vout[0].script_pubkey, net)
            total_external_amount = sum(out.value for out in tx.vout)

        # 5. Fee and Rate Calculation
        total_output_sats = sum(out.value for out in tx.vout)
        fee_sats = total_input_sats - total_output_sats

        if fee_sats < 0:
            raise DecodeError(
                f"Negative transaction fee ({fee_sats} satoshis): inputs ({total_input_sats}) < outputs ({total_output_sats})"
            )

        # Approximate virtual size from serialized transaction
        tx_vsize = len(tx.serialize())
        sats_per_vbyte = fee_sats / max(tx_vsize, 1)

        # Evaluate fee policy bounds
        max_fee_sats = getattr(policy, "max_fee_sats", None) or self.default_max_fee_sats
        max_sats_per_byte = getattr(policy, "max_sats_per_byte", None) or self.default_max_sats_per_byte

        fee_outside_policy = (fee_sats > max_fee_sats) or (sats_per_vbyte > max_sats_per_byte)
        fee_flag = "FEE_EXCEEDS_POLICY" if fee_outside_policy else None

        fee_item = CallItem(
            to="NETWORK_FEE",
            value=str(fee_sats),
            amount=str(fee_sats),
            call_type="FEE",
            flag=fee_flag,
        )

        # 6. Primary signing digest
        # Invariant #2: Exact data that will be signed by the signer shim
        primary_digest = input_items[0].data or f"0x{psbt_obj.sighash(0).hex()}"

        # 7. Construct canonical DecodedTx
        # List outputs first, then inputs, then network fee
        all_calls = output_items + input_items + [fee_item]
        primary_from = input_addresses[0] if input_addresses else ""

        target_chain = (chain or "bitcoin").lower()

        return DecodedTx(
            chain=target_chain,
            from_address=primary_from,
            to_address=first_external_recipient,
            asset="BTC",
            amount=str(total_external_amount),
            calls=all_calls,
            authorizations=[],
            fee=FeeDetail(
                gas_limit=tx_vsize,
                fee_satoshis=fee_sats,
                sats_per_vbyte=round(sats_per_vbyte, 2),
            ),
            digest=primary_digest,
        )


# Singleton decoder instance
psbt_decoder = BtcPsbtDecoder()
