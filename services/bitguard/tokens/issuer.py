"""Approval token issuance using Ed25519 compact cryptographic signatures (Milestone S11)."""

import base64
import json
import secrets
import time

from services.bitguard.models import DecodedTx
from services.bitguard.tokens.keys import KeySet, TokenKey
from services.bitguard.tokens.models import ApprovalTokenClaims, TokenHeader


def _b64url_encode(data: bytes) -> str:
    """Encodes bytes into URL-safe base64 string without trailing padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def issue_token(
    decoded_tx: DecodedTx,
    wallet: str,
    chain: str,
    key_set: KeySet | None = None,
    signing_key: TokenKey | None = None,
    ttl_seconds: int = 60,
    nonce: str | None = None,
    now: int | None = None,
    epoch: int = 1,
) -> str:
    """Generates and cryptographically signs a compact one-time Ed25519 approval token.

    Claims:
    - digest: canonical keccak256 digest of unsigned transaction payload
    - wallet: hot wallet address
    - chain: target blockchain
    - iat: issued-at timestamp
    - exp: iat + 60s
    - nonce: 128-bit random hex (32 hex characters)
    - kid: key ID used for signature
    - epoch: token epoch counter for circuit breaker revocation
    """
    if signing_key is None:
        if key_set is None:
            raise ValueError("Either signing_key or key_set with an active key must be provided")
        signing_key = key_set.get_active_key()

    if not signing_key.can_sign:
        raise ValueError(f"Key '{signing_key.kid}' does not possess a private signing key")

    current_iat = now if now is not None else int(time.time())
    current_exp = current_iat + ttl_seconds
    token_nonce = nonce or secrets.token_hex(16)  # 128 bits = 16 bytes = 32 hex chars

    claims = ApprovalTokenClaims(
        digest=decoded_tx.digest,
        wallet=wallet.lower(),
        chain=chain.lower(),
        iat=current_iat,
        exp=current_exp,
        nonce=token_nonce,
        kid=signing_key.kid,
        epoch=epoch,
    )

    header = TokenHeader(
        alg="EdDSA",
        typ="JWT",
        kid=signing_key.kid,
    )

    header_bytes = json.dumps(header.model_dump(), separators=(",", ":"), sort_keys=True).encode("utf-8")
    claims_bytes = json.dumps(claims.model_dump(), separators=(",", ":"), sort_keys=True).encode("utf-8")

    b64_header = _b64url_encode(header_bytes)
    b64_claims = _b64url_encode(claims_bytes)

    signing_input = f"{b64_header}.{b64_claims}".encode("ascii")

    # Sign using PyNaCl Ed25519
    signed_obj = signing_key.signing_key.sign(signing_input)
    # PyNaCl returns signature + message, signature is first 64 bytes
    signature = signed_obj.signature
    b64_signature = _b64url_encode(signature)

    return f"{b64_header}.{b64_claims}.{b64_signature}"
