"""Disposable testnet key custody and ECDSA transaction signing (Milestone S11).

Invariants:
- Invariant #1: Key Isolation: Only the signer shim holds a disposable TESTNET key.
  BitGuard never stores or uses signing keys.
- Invariant #9: Environment & Safety Boundary: Disposable keys only. No mainnet. No real funds.
"""

import logging
from typing import Any

from eth_account import Account
from eth_utils import keccak

from services.signer_shim.config import settings

logger = logging.getLogger("signer_shim.signer")


class TestnetSigner:
    """Manages disposable testnet key custody and executes secp256k1 ECDSA signing."""

    def __init__(self, private_key: str | None = None) -> None:
        key = private_key or settings.testnet_private_key
        # Verify disposable testnet key format
        clean_key = key.strip()
        if not clean_key.startswith("0x"):
            clean_key = f"0x{clean_key}"
        self._account = Account.from_key(clean_key)
        logger.info(
            "Initialized Signer Shim with disposable testnet hot address: %s",
            self._account.address,
        )

    @property
    def address(self) -> str:
        """The public address corresponding to the disposable testnet private key."""
        return self._account.address

    def sign_digest(self, digest_hex: str) -> dict[str, Any]:
        """Signs a 32-byte transaction signing digest using the disposable testnet private key."""
        clean_digest = digest_hex.strip()
        if clean_digest.startswith("0x"):
            clean_digest = clean_digest[2:]

        digest_bytes = bytes.fromhex(clean_digest)
        if len(digest_bytes) != 32:
            raise ValueError(f"Signing digest must be exactly 32 bytes, got {len(digest_bytes)}")

        # Execute secp256k1 signature over digest
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


# Singleton instance
testnet_signer = TestnetSigner()
