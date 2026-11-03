"""Bytecode, delegation, and transaction nonce inspectors for the BitGuard Watcher (Milestone S17 / F6).

Invariants:
- Invariant #3: Fail-Closed Default. Unknown or unreviewed delegate triggers CRITICAL alert.
- Invariant #4: Raw Byte Source of Truth. Compares code hashes of deployed bytecodes.
"""

import logging
from typing import Any

from eth_utils import to_checksum_address

from services.bitguard.models import WatchedAddress, WatcherAlert
from services.bitguard.rpc.base import RpcClient
from services.bitguard.rules.delegation import compute_code_hash

logger = logging.getLogger("bitguard.watcher.inspector")

# EIP-7702 prefix: 0xef0100 (3 bytes) followed by 20-byte address = 23 bytes total (46 hex digits without 0x)
EIP7702_PREFIX = "ef0100"
EIP7702_BYTE_LENGTH = 23
EIP7702_HEX_LENGTH = 46


def is_eip7702_delegation(code_hex: str) -> bool:
    """Checks whether the bytecode represents an EIP-7702 delegation designator."""
    clean = code_hex.removeprefix("0x").lower()
    return len(clean) == EIP7702_HEX_LENGTH and clean.startswith(EIP7702_PREFIX)


def extract_eip7702_delegate(code_hex: str) -> str:
    """Extracts checksummed 20-byte delegate address from an EIP-7702 bytecode designator."""
    clean = code_hex.removeprefix("0x").lower()
    if not (len(clean) == EIP7702_HEX_LENGTH and clean.startswith(EIP7702_PREFIX)):
        raise ValueError(f"Bytecode is not an EIP-7702 delegation designator: {code_hex}")
    address_bytes = bytes.fromhex(clean[6:46])
    return to_checksum_address(address_bytes)


class WatcherInspector:
    """Evaluates on-chain bytecode, 7702 delegations, and nonce velocity for watched addresses."""

    def inspect_address_code(
        self,
        watched: WatchedAddress,
        code_hex: str,
        rpc: RpcClient,
        block_number: int,
        block_timestamp: float,
    ) -> WatcherAlert | None:
        """Inspects retrieved bytecode for unauthorized EIP-7702 delegations or unexpected changes."""
        clean_code = code_hex.removeprefix("0x").lower()

        # 1. Clean address (EOA / empty code)
        if not clean_code or clean_code == "0x" or len(clean_code) == 0:
            if watched.expected_code_hash and watched.expected_code_hash != compute_code_hash("0x"):
                return WatcherAlert(
                    id=f"alert-code-cleared-{watched.id}-{block_number}",
                    alert_code="CODE_HASH_MISMATCH",
                    severity="CRITICAL",
                    address=watched.address,
                    chain=watched.chain,
                    block_number=block_number,
                    block_timestamp=block_timestamp,
                    details={
                        "expected_code_hash": watched.expected_code_hash,
                        "actual_code": "0x",
                        "message": "Bytecode was unexpectedly cleared or self-destructed",
                    },
                )
            return None

        # 2. Check for EIP-7702 Delegation Designator (0xef0100 + 20-byte address)
        if is_eip7702_delegation(code_hex):
            delegate_address = extract_eip7702_delegate(code_hex)
            logger.info("detected_eip7702_delegation: address=%s delegate=%s", watched.address, delegate_address)

            # Resolve delegate contract bytecode and hash
            try:
                delegate_code = rpc.get_code(delegate_address)
                delegate_code_hash = compute_code_hash(delegate_code)
            except Exception as exc:
                logger.error("failed_resolving_delegate_code for %s: %s", delegate_address, exc)
                return WatcherAlert(
                    id=f"alert-rpc-fail-{watched.id}-{block_number}",
                    alert_code="DELEGATION_RPC_FAILURE",
                    severity="CRITICAL",
                    address=watched.address,
                    chain=watched.chain,
                    block_number=block_number,
                    block_timestamp=block_timestamp,
                    details={"delegate": delegate_address, "error": str(exc)},
                )

            # Check allowlist (address or code hash)
            allowed_hashes_or_addrs = [d.lower() for d in watched.allowed_delegates]
            is_allowed = (
                delegate_address.lower() in allowed_hashes_or_addrs
                or delegate_code_hash.lower() in allowed_hashes_or_addrs
            )

            if not is_allowed:
                logger.warning(
                    "CRITICAL: Unauthorized EIP-7702 delegation detected on watched address %s -> delegate=%s (hash=%s)",
                    watched.address,
                    delegate_address,
                    delegate_code_hash,
                )
                return WatcherAlert(
                    id=f"alert-delegation-{watched.id}-{block_number}",
                    alert_code="UNAUTHORIZED_DELEGATION",
                    severity="CRITICAL",
                    address=watched.address,
                    chain=watched.chain,
                    block_number=block_number,
                    block_timestamp=block_timestamp,
                    details={
                        "delegate": delegate_address,
                        "delegate_code_hash": delegate_code_hash,
                        "allowed_delegates": watched.allowed_delegates,
                        "message": "Watched hot wallet delegated to unapproved contract (EIP-7702)",
                    },
                )
            return None

        # 3. Standard Smart Contract Bytecode check
        if watched.expected_code_hash:
            actual_hash = compute_code_hash(code_hex)
            if actual_hash.lower() != watched.expected_code_hash.lower():
                return WatcherAlert(
                    id=f"alert-hash-mismatch-{watched.id}-{block_number}",
                    alert_code="CODE_HASH_MISMATCH",
                    severity="CRITICAL",
                    address=watched.address,
                    chain=watched.chain,
                    block_number=block_number,
                    block_timestamp=block_timestamp,
                    details={
                        "expected_code_hash": watched.expected_code_hash,
                        "actual_code_hash": actual_hash,
                        "message": "Contract bytecode altered on-chain",
                    },
                )

        return None

    def inspect_block_transactions(
        self,
        block_data: dict[str, Any],
        watched_map: dict[str, WatchedAddress],
        rpc: RpcClient,
        block_number: int,
        block_timestamp: float,
    ) -> list[WatcherAlert]:
        """Scans transactions in the block for type-4 transactions or unexpected nonce jumps."""
        alerts: list[WatcherAlert] = []
        transactions = block_data.get("transactions", [])

        # 1. Scan transactions for Type 4 EIP-7702 Authorizations naming a watched address
        for tx in transactions:
            if not isinstance(tx, dict):
                continue
            tx_type = tx.get("type")
            if tx_type in (4, "0x4", "0x04"):
                auth_list = tx.get("authorizationList") or tx.get("authorizations") or []
                for auth in auth_list:
                    if not isinstance(auth, dict):
                        continue
                    authority = (
                        auth.get("authority")
                        or auth.get("address")
                        or auth.get("from")
                    )
                    if not authority:
                        continue
                    clean_authority = authority.lower()
                    if clean_authority in watched_map:
                        watched = watched_map[clean_authority]
                        delegate = auth.get("delegate") or auth.get("address")
                        # Verify delegate
                        allowed_list = [d.lower() for d in watched.allowed_delegates]
                        delegate_ok = delegate and delegate.lower() in allowed_list
                        if not delegate_ok:
                            alerts.append(
                                WatcherAlert(
                                    id=f"alert-type4-tx-{watched.id}-{block_number}",
                                    alert_code="UNAUTHORIZED_TYPE4_AUTHORIZATION",
                                    severity="CRITICAL",
                                    address=watched.address,
                                    chain=watched.chain,
                                    block_number=block_number,
                                    block_timestamp=block_timestamp,
                                    details={
                                        "tx_hash": tx.get("hash"),
                                        "delegate": delegate,
                                        "authority": authority,
                                        "message": "Type-4 transaction in block names watched address as authority with unapproved delegate",
                                    },
                                )
                            )

        # 2. Check for Unexpected Nonce Jumps
        for _addr_key, watched in watched_map.items():
            try:
                on_chain_nonce = rpc.get_transaction_count(watched.address, block=hex(block_number))
                expected_max = watched.last_known_nonce + watched.signed_count
                if on_chain_nonce > expected_max:
                    alerts.append(
                        WatcherAlert(
                            id=f"alert-nonce-jump-{watched.id}-{block_number}",
                            alert_code="UNEXPECTED_NONCE_JUMP",
                            severity="CRITICAL",
                            address=watched.address,
                            chain=watched.chain,
                            block_number=block_number,
                            block_timestamp=block_timestamp,
                            details={
                                "on_chain_nonce": on_chain_nonce,
                                "expected_max_nonce": expected_max,
                                "jump_size": on_chain_nonce - expected_max,
                                "message": f"Nonce jumped from expected {expected_max} to {on_chain_nonce} without BitGuard authorization",
                            },
                        )
                    )
            except Exception as exc:
                logger.warning("failed_querying_nonce_for_%s: %s", watched.address, exc)

        return alerts


inspector = WatcherInspector()
