"""Multi-Party Computation (MPC) and Hardware Security Module (HSM) Stub Backend (Milestone S36).

Architecture & Hardening Invariants:
- Invariant #1: Key Isolation: Private key shares are distributed across threshold MPC peers
  (e.g., Fireblocks, Qredo, Fordefi) or air-gapped PKCS#11 Hardware Security Modules
  (e.g., Thales Luna, Securosys PrimusX, Entrust nShield).
- Quorum & Threshold: Signatures require t-of-n non-colluding mathematical shares.
- Invariant #3: Fail-Closed Default: If MPC peer quorum is not reached or the PKCS#11 HSM
  session returns a CKR error code, the operation fails closed immediately.
"""

import logging
from typing import Any

from eth_utils import keccak

from services.signer_shim.backends.base import SignerBackend

logger = logging.getLogger("signer_shim.backends.mpc_hsm")


class MpcHsmStubBackend(SignerBackend):
    """Stub adapter representing MPC threshold clusters and PKCS#11 HSM appliances."""

    def __init__(
        self,
        vendor: str = "generic_mpc",
        cluster_id: str = "cluster-alpha-01",
        cached_address: str | None = None,
    ) -> None:
        self.vendor = vendor
        self.cluster_id = cluster_id
        self._address = cached_address or "0x0000000000000000000000000000000000000000"
        logger.info(
            "Configured MpcHsmStubBackend: vendor=%s cluster_id=%s address=%s",
            self.vendor,
            self.cluster_id,
            self._address,
        )

    @property
    def backend_name(self) -> str:
        return f"mpc_hsm:{self.vendor}"

    @property
    def address(self) -> str:
        return self._address

    def sign_digest(self, digest_hex: str) -> dict[str, Any]:
        """Executes threshold MPC signing or PKCS#11 C_Sign call.

        Note: This is an architectural adapter stub. In production deployment,
        this integrates with the vendor's gRPC / PKCS#11 dynamic library:
            - Fireblocks: Co-Signer callback API / Workspace Raw Transaction Signing.
            - PKCS#11: C_Initialize, C_OpenSession, C_Login, C_SignInit(CKM_ECDSA), C_Sign.
        """
        clean_digest = digest_hex.strip()
        if clean_digest.startswith("0x"):
            clean_digest = clean_digest[2:]

        digest_bytes = bytes.fromhex(clean_digest)
        if len(digest_bytes) != 32:
            raise ValueError(f"Signing digest must be exactly 32 bytes, got {len(digest_bytes)}")

        # Deterministic simulation of an external MPC signature for verification tests
        mock_r = f"0x{'11' * 32}"
        mock_s = f"0x{'22' * 32}"
        mock_v = 27
        full_sig_hex = f"{mock_r}{mock_s[2:]}{mock_v:02x}"
        tx_hash_hex = "0x" + keccak(bytes.fromhex(full_sig_hex[2:])).hex()

        return {
            "r": mock_r,
            "s": mock_s,
            "v": mock_v,
            "signature": full_sig_hex,
            "tx_hash": tx_hash_hex,
            "address": self.address,
        }

    def get_backend_info(self) -> dict[str, str]:
        return {
            "backend": "mpc_hsm",
            "vendor": self.vendor,
            "cluster_id": self.cluster_id,
            "address": self.address,
            "status": "stub_ready",
        }
