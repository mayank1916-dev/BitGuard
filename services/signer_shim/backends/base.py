"""Abstract Base Interface for Signer Shim Key Custody Backends (Milestone S36).

Invariants:
- Invariant #1: Key Isolation: BitGuard never stores or uses signing keys.
  Only the signer shim holds a disposable TESTNET key (or interfaces with an isolated KMS/HSM).
- Invariant #3: Fail-Closed Default: Cryptographic or backend communication failure raises
  an exception, triggering an immediate fail-closed REFUSED response.
- Invariant #9: Environment & Safety Boundary: Disposable keys and test environments only.
"""

from abc import ABC, abstractmethod
from typing import Any


class SignerBackend(ABC):
    """Abstract interface defining cryptographic signing operations for the Signer Shim."""

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Identifier name of the signer backend (e.g. 'disposable', 'aws_kms', 'vault_transit')."""
        pass

    @property
    @abstractmethod
    def address(self) -> str:
        """The canonical public address corresponding to the signing key."""
        pass

    @abstractmethod
    def sign_digest(self, digest_hex: str) -> dict[str, Any]:
        """Signs a 32-byte signing digest and returns canonical signature components.

        Args:
            digest_hex: 32-byte hex-encoded transaction signing digest.

        Returns:
            Dictionary containing:
            - 'r': 32-byte hex string (0x...)
            - 's': 32-byte hex string (0x...)
            - 'v': Recovery identifier integer (27, 28, or EIP-155 v)
            - 'signature': Full 65-byte serialized signature hex string (0x{r}{s}{v})
            - 'tx_hash': Keccak256 hash of serialized signature or transaction hash
            - 'address': Public address that produced the signature
        """
        pass

    @abstractmethod
    def get_backend_info(self) -> dict[str, str]:
        """Returns safe operational metadata regarding backend status and key identification."""
        pass
