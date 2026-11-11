"""Disposable Testnet Key Custody Backend for Signer Shim (Milestones S11 & S36).

Invariants:
- Invariant #1: Key Isolation: Only the signer shim holds a disposable TESTNET key.
- Invariant #9: Environment & Safety Boundary: Disposable keys only. No mainnet. No real funds.
"""

import logging
from typing import Any

from eth_account import Account
from eth_utils import keccak

from services.signer_shim.backends.base import SignerBackend
from services.signer_shim.config import settings

logger = logging.getLogger("signer_shim.backends.disposable")


class DisposableKeyBackend(SignerBackend):
    """Local disposable key custody using an ephemeral/testnet secp256k1 private key."""

    def __init__(self, private_key: str | None = None) -> None:
        key = private_key or settings.testnet_private_key
        clean_key = key.strip()
        if not clean_key.startswith("0x"):
            clean_key = f"0x{clean_key}"
        self._account = Account.from_key(clean_key)
        logger.info(
            "Initialized DisposableKeyBackend with testnet address: %s",
            self._account.address,
        )

    @property
    def backend_name(self) -> str:
        return "disposable"

    @property
    def address(self) -> str:
        return str(self._account.address)

    def sign_digest(self, digest_hex: str) -> dict[str, Any]:
        """Signs a 32-byte digest using the local disposable testnet key."""
        clean_digest = digest_hex.strip()
        if clean_digest.startswith("0x"):
            clean_digest = clean_digest[2:]

        digest_bytes = bytes.fromhex(clean_digest)
        if len(digest_bytes) != 32:
            raise ValueError(f"Signing digest must be exactly 32 bytes, got {len(digest_bytes)}")

        sig = Account._sign_hash(digest_bytes, self._account.key)

        r_hex = f"0x{sig.r:064x}"
        s_hex = f"0x{sig.s:064x}"
        v_int = int(sig.v)
        full_sig_hex = f"0x{sig.r:064x}{sig.s:064x}{sig.v:02x}"
        tx_hash_hex = "0x" + keccak(bytes.fromhex(full_sig_hex[2:])).hex()

        return {
            "r": r_hex,
            "s": s_hex,
            "v": v_int,
            "signature": full_sig_hex,
            "tx_hash": tx_hash_hex,
            "address": self._account.address,
        }

    def get_backend_info(self) -> dict[str, str]:
        return {
            "backend": "disposable",
            "address": self.address,
            "environment": settings.environment,
            "status": "ready",
        }
