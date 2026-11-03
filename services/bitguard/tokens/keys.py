"""Ed25519 cryptographic key management and key sets with rotation support (Milestone S11)."""

import logging
from typing import Any

import nacl.encoding
import nacl.exceptions
import nacl.signing

from services.bitguard.tokens.models import KeyStatus

logger = logging.getLogger("bitguard.tokens.keys")


class TokenKey:
    """Represents an Ed25519 signing and/or verification key bound to a unique kid."""

    def __init__(
        self,
        kid: str,
        signing_key: nacl.signing.SigningKey | None = None,
        verify_key: nacl.signing.VerifyKey | None = None,
        status: KeyStatus = KeyStatus.ACTIVE,
    ) -> None:
        self.kid = kid
        self.status = status
        self._signing_key = signing_key
        if verify_key is not None:
            self._verify_key = verify_key
        elif signing_key is not None:
            self._verify_key = signing_key.verify_key
        else:
            raise ValueError("TokenKey requires either a signing_key or a verify_key")

    @property
    def can_sign(self) -> bool:
        """Indicates whether this key instance possesses private signing capability."""
        return self._signing_key is not None

    @property
    def signing_key(self) -> nacl.signing.SigningKey:
        if self._signing_key is None:
            raise ValueError(f"Key '{self.kid}' does not possess a private signing key")
        return self._signing_key

    @property
    def verify_key(self) -> nacl.signing.VerifyKey:
        return self._verify_key

    @property
    def public_hex(self) -> str:
        """Hex-encoded 32-byte Ed25519 public key."""
        return self._verify_key.encode(encoder=nacl.encoding.HexEncoder).decode("ascii")

    @classmethod
    def generate(cls, kid: str) -> "TokenKey":
        """Generates a fresh random Ed25519 keypair."""
        sk = nacl.signing.SigningKey.generate()
        return cls(kid=kid, signing_key=sk, status=KeyStatus.ACTIVE)

    @classmethod
    def from_seed_hex(cls, kid: str, seed_hex: str, status: KeyStatus = KeyStatus.ACTIVE) -> "TokenKey":
        """Reconstructs an Ed25519 keypair from a 32-byte hex seed."""
        raw_seed = bytes.fromhex(seed_hex[2:] if seed_hex.startswith("0x") else seed_hex)
        sk = nacl.signing.SigningKey(raw_seed)
        return cls(kid=kid, signing_key=sk, status=status)

    @classmethod
    def from_public_hex(cls, kid: str, pub_hex: str, status: KeyStatus = KeyStatus.ACTIVE) -> "TokenKey":
        """Constructs a verify-only TokenKey from a 32-byte public key hex."""
        raw_pub = bytes.fromhex(pub_hex[2:] if pub_hex.startswith("0x") else pub_hex)
        vk = nacl.signing.VerifyKey(raw_pub)
        return cls(kid=kid, verify_key=vk, status=status)


class KeySet:
    """Collection of BitGuard token verification and signing keys supporting rotation."""

    def __init__(self) -> None:
        self._keys: dict[str, TokenKey] = {}
        self._active_kid: str | None = None

    def add_key(self, key: TokenKey, set_active: bool = False) -> None:
        """Registers a token key in the key set."""
        self._keys[key.kid] = key
        if set_active or self._active_kid is None:
            self._active_kid = key.kid

    def retire_key(self, kid: str) -> None:
        """Marks a key as retired, disallowing subsequent token signing and verification."""
        if kid in self._keys:
            self._keys[kid].status = KeyStatus.RETIRED
            if self._active_kid == kid:
                self._active_kid = None

    def get_active_key(self) -> TokenKey:
        """Returns the currently active signing key."""
        if self._active_kid is None or self._active_kid not in self._keys:
            raise KeyError("No active signing key configured in key set")
        key = self._keys[self._active_kid]
        if key.status != KeyStatus.ACTIVE:
            raise ValueError(f"Active key '{self._active_kid}' is not in ACTIVE status")
        return key

    def get_key(self, kid: str) -> TokenKey | None:
        """Retrieves key by kid regardless of status."""
        return self._keys.get(kid)

    def export_public_key_set(self) -> dict[str, dict[str, str]]:
        """Serializes public keys for distribution to the signer shim."""
        return {
            kid: {
                "public_key": k.public_hex,
                "status": k.status.value,
            }
            for kid, k in self._keys.items()
        }

    @classmethod
    def from_public_key_dict(cls, data: dict[str, Any]) -> "KeySet":
        """Instantiates a verify-only KeySet from public key dictionary configuration."""
        ks = cls()
        for kid, info in data.items():
            pub_hex = info["public_key"]
            status_str = info.get("status", "ACTIVE")
            status = KeyStatus(status_str)
            key = TokenKey.from_public_hex(kid=kid, pub_hex=pub_hex, status=status)
            ks.add_key(key, set_active=(status == KeyStatus.ACTIVE))
        return ks
