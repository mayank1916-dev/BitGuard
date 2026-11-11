"""Disposable testnet key custody and ECDSA transaction signing (Milestones S11 & S36).

Invariants:
- Invariant #1: Key Isolation: Only the signer shim holds a disposable TESTNET key (or interfaces with KMS).
  BitGuard never stores or uses signing keys.
- Invariant #9: Environment & Safety Boundary: Disposable keys only. No mainnet. No real funds.
"""

import logging
from typing import Any

from services.signer_shim.backends.base import SignerBackend
from services.signer_shim.backends.disposable import DisposableKeyBackend

logger = logging.getLogger("signer_shim.signer")


class TestnetSigner:
    """Manages disposable testnet key custody and executes secp256k1 ECDSA signing."""

    __test__ = False

    def __init__(self, backend: SignerBackend | None = None, private_key: str | None = None) -> None:
        if backend is not None:
            self._backend = backend
        else:
            self._backend = DisposableKeyBackend(private_key=private_key)

    @property
    def backend(self) -> SignerBackend:
        """The underlying SignerBackend instance."""
        return self._backend

    def set_backend(self, backend: SignerBackend) -> None:
        """Dynamically configures the active signer backend (e.g. for testing)."""
        self._backend = backend

    @property
    def address(self) -> str:
        """The public address corresponding to the signing key."""
        return self._backend.address

    def sign_digest(self, digest_hex: str) -> dict[str, Any]:
        """Signs a 32-byte transaction signing digest using the configured signer backend."""
        return self._backend.sign_digest(digest_hex)


# Singleton instance
testnet_signer = TestnetSigner()
