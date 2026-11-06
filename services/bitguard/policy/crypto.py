"""Cryptographic utilities for canonical policy hashing and Ed25519 signatures (Milestone S20 / Section D)."""

import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

# Deterministic dev/lab release authority Ed25519 private key (exactly 32 bytes)
DEV_RELEASE_SEED = hashlib.sha256(b"bitguard_dev_release_authority_seed_2026").digest()
DEV_RELEASE_PRIVATE_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(DEV_RELEASE_SEED)
DEV_RELEASE_PUBLIC_KEY = DEV_RELEASE_PRIVATE_KEY.public_key()


def canonical_json(data: Any) -> bytes:
    """Serializes data into canonical JSON bytes with deterministic key ordering and spacing."""
    if hasattr(data, "model_dump"):
        data = data.model_dump(mode="json")
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def compute_content_hash(content: Any) -> str:
    """Computes deterministic SHA-256 hex digest of a policy document or dictionary."""
    raw_bytes = canonical_json(content)
    return hashlib.sha256(raw_bytes).hexdigest()


def sign_content_hash(
    content_hash_hex: str,
    private_key: ed25519.Ed25519PrivateKey | None = None,
) -> str:
    """Signs a content hash string using an Ed25519 private key, returning hex signature."""
    priv = private_key or DEV_RELEASE_PRIVATE_KEY
    data_bytes = content_hash_hex.encode("utf-8")
    sig_bytes = priv.sign(data_bytes)
    return sig_bytes.hex()


def verify_ed25519_signature(
    content_hash_hex: str,
    signature_hex: str,
    public_key: ed25519.Ed25519PublicKey | None = None,
) -> bool:
    """Verifies an Ed25519 hex signature over a content hash string."""
    pub = public_key or DEV_RELEASE_PUBLIC_KEY
    try:
        sig_bytes = bytes.fromhex(signature_hex.removeprefix("0x"))
        data_bytes = content_hash_hex.encode("utf-8")
        pub.verify(sig_bytes, data_bytes)
        return True
    except (ValueError, InvalidSignature):
        return False
