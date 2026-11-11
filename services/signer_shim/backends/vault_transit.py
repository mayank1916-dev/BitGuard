"""HashiCorp Vault Transit Secret Engine Signer Backend Adapter (Milestone S36).

Architecture & Hardening Invariants:
- Invariant #1: Key Isolation: Private keys are generated and stored exclusively within
  HashiCorp Vault storage / HSM barrier. The Transit engine performs cryptographic operations
  in-place and never discloses the underlying private key.
- Invariant #3: Fail-Closed Default: Vault connection timeouts, sealed vault states, or token
  permission denials immediately trigger an exception, failing closed.
- Principle of Least Privilege: The Signer Shim AppRole / Token policy permits ONLY
  the 'update' capability on path 'transit/sign/<key_name>' with prehashed=true.
"""

import base64
import logging
from typing import Any

from eth_utils import keccak

from services.signer_shim.backends.base import SignerBackend

logger = logging.getLogger("signer_shim.backends.vault_transit")


class VaultTransitBackend(SignerBackend):
    """Signer backend adapter delegating cryptographic signatures to HashiCorp Vault Transit.

    Target Engine: Transit Secrets Engine
    Path: /v1/transit/sign/{key_name}
    Key Type: ecdsa-p256 or secp256k1
    """

    def __init__(
        self,
        vault_addr: str = "http://127.0.0.1:8200",
        key_name: str = "bitguard-hot-wallet",
        mount_path: str = "transit",
        token: str | None = None,
        cached_address: str | None = None,
    ) -> None:
        self.vault_addr = vault_addr.rstrip("/")
        self.key_name = key_name
        self.mount_path = mount_path
        self.token = token or ""
        self._address = cached_address or "0x0000000000000000000000000000000000000000"
        logger.info(
            "Configured VaultTransitBackend: vault_addr=%s mount=%s key=%s",
            self.vault_addr,
            self.mount_path,
            self.key_name,
        )

    @property
    def backend_name(self) -> str:
        return "vault_transit"

    @property
    def address(self) -> str:
        return self._address

    def sign_digest(self, digest_hex: str) -> dict[str, Any]:
        """Submits a 32-byte digest to Vault Transit for signing.

        Vault Transit Sign API:
            POST /v1/{mount_path}/sign/{key_name}
            Headers: {"X-Vault-Token": self.token}
            Body: {
                "input": base64_encoded_digest,
                "prehashed": true,
                "hash_algorithm": "sha2-256"
            }

        Response format:
            {"data": {"signature": "vault:v1:MEQCID..."}}
        """
        clean_digest = digest_hex.strip()
        if clean_digest.startswith("0x"):
            clean_digest = clean_digest[2:]

        digest_bytes = bytes.fromhex(clean_digest)
        if len(digest_bytes) != 32:
            raise ValueError(f"Signing digest must be exactly 32 bytes, got {len(digest_bytes)}")

        b64_digest = base64.b64encode(digest_bytes).decode("ascii")

        try:
            import httpx

            url = f"{self.vault_addr}/v1/{self.mount_path}/sign/{self.key_name}"
            headers = {"X-Vault-Token": self.token}
            payload = {
                "input": b64_digest,
                "prehashed": True,
                "hash_algorithm": "sha2-256",
            }

            with httpx.Client(timeout=3.0) as client:
                resp = client.post(url, json=payload, headers=headers)
                if resp.status_code != 200:
                    raise RuntimeError(
                        f"Vault Transit signing failed: status={resp.status_code} body={resp.text}"
                    )

                data = resp.json().get("data", {})
                vault_sig = data.get("signature", "")
                if not vault_sig or not vault_sig.startswith("vault:"):
                    raise ValueError(f"Unexpected Vault signature format: {vault_sig}")

                # Extract raw base64 after version prefix (e.g. 'vault:v1:')
                parts = vault_sig.split(":", 2)
                raw_sig_b64 = parts[2] if len(parts) == 3 else parts[-1]
                raw_sig_bytes = base64.b64decode(raw_sig_b64)

                # Format signature components
                r_hex = f"0x{raw_sig_bytes[:32].hex()}"
                s_hex = f"0x{raw_sig_bytes[32:64].hex()}" if len(raw_sig_bytes) >= 64 else f"0x{raw_sig_bytes[:32].hex()}"
                v_int = 27
                full_sig_hex = f"{r_hex}{s_hex[2:]}{v_int:02x}"
                tx_hash_hex = "0x" + keccak(bytes.fromhex(full_sig_hex[2:])).hex()

                return {
                    "r": r_hex,
                    "s": s_hex,
                    "v": v_int,
                    "signature": full_sig_hex,
                    "tx_hash": tx_hash_hex,
                    "address": self.address,
                }
        except ImportError as err:
            raise RuntimeError("httpx library is required for VaultTransitBackend") from err
        except Exception as exc:
            logger.error("Vault transit signing exception: %s", exc)
            raise

    def get_backend_info(self) -> dict[str, str]:
        return {
            "backend": "vault_transit",
            "vault_addr": self.vault_addr,
            "key_name": self.key_name,
            "address": self.address,
            "status": "configured",
        }
