"""Approval token verification and cryptographic validation (Milestone S11)."""

import base64
import json
import logging
import time

import nacl.exceptions

from services.bitguard.tokens.keys import KeySet
from services.bitguard.tokens.models import (
    ApprovalTokenClaims,
    KeyStatus,
    TokenHeader,
    TokenVerificationResult,
)

logger = logging.getLogger("bitguard.tokens.verifier")


def _b64url_decode(s: str) -> bytes:
    """Decodes URL-safe base64 string handling missing padding."""
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def verify_token(
    token: str,
    key_set: KeySet,
    now: int | None = None,
) -> TokenVerificationResult:
    """Cryptographically verifies an Ed25519 approval token against a KeySet.

    Validation steps:
    1. Structure: exactly 3 base64url segments (header, payload, signature).
    2. Header: alg=EdDSA, valid JSON, extract kid.
    3. Key resolution: lookup kid; reject unknown or retired keys.
    4. Signature: Ed25519 signature verification over header.claims.
    5. Expiration: ensure current timestamp has not exceeded exp.
    """
    if not token or not isinstance(token, str):
        return TokenVerificationResult(
            valid=False,
            error_code="MALFORMED_TOKEN",
            error_detail="Token must be a non-empty string",
        )

    parts = token.strip().split(".")
    if len(parts) != 3:
        return TokenVerificationResult(
            valid=False,
            error_code="MALFORMED_TOKEN",
            error_detail=f"Expected 3 token segments (header.payload.signature), got {len(parts)}",
        )

    b64_header, b64_claims, b64_sig = parts

    # 1. Parse Header
    try:
        header_bytes = _b64url_decode(b64_header)
        header_data = json.loads(header_bytes.decode("utf-8"))
        header = TokenHeader.model_validate(header_data)
    except Exception as exc:
        return TokenVerificationResult(
            valid=False,
            error_code="MALFORMED_HEADER",
            error_detail=f"Invalid token header: {exc}",
        )

    if header.alg != "EdDSA":
        return TokenVerificationResult(
            valid=False,
            error_code="UNSUPPORTED_ALGORITHM",
            error_detail=f"Algorithm '{header.alg}' unsupported (expected EdDSA)",
        )

    # 2. Key Lookup and Status Check
    key = key_set.get_key(header.kid)
    if key is None:
        return TokenVerificationResult(
            valid=False,
            error_code="UNKNOWN_KID",
            error_detail=f"Key ID '{header.kid}' is not recognized in configured key set",
        )

    if key.status == KeyStatus.RETIRED:
        return TokenVerificationResult(
            valid=False,
            error_code="RETIRED_KID",
            error_detail=f"Key ID '{header.kid}' has been retired and cannot verify tokens",
        )

    # 3. Signature Verification
    signing_input = f"{b64_header}.{b64_claims}".encode("ascii")
    try:
        signature_bytes = _b64url_decode(b64_sig)
        if len(signature_bytes) != 64:
            raise ValueError(f"Ed25519 signature must be exactly 64 bytes, got {len(signature_bytes)}")
        # Verify using verify_key
        key.verify_key.verify(signing_input, signature_bytes)
    except (nacl.exceptions.BadSignatureError, Exception) as exc:
        return TokenVerificationResult(
            valid=False,
            error_code="INVALID_TOKEN_SIGNATURE",
            error_detail=f"Ed25519 signature verification failed: {exc}",
        )

    # 4. Parse Claims
    try:
        claims_bytes = _b64url_decode(b64_claims)
        claims_data = json.loads(claims_bytes.decode("utf-8"))
        claims = ApprovalTokenClaims.model_validate(claims_data)
    except Exception as exc:
        return TokenVerificationResult(
            valid=False,
            error_code="MALFORMED_CLAIMS",
            error_detail=f"Invalid token claims payload: {exc}",
        )

    # 5. Expiration Check
    current_time = now if now is not None else int(time.time())
    if current_time > claims.exp:
        return TokenVerificationResult(
            valid=False,
            claims=claims,
            error_code="TOKEN_EXPIRED",
            error_detail=f"Token expired at {claims.exp} (current time {current_time})",
        )

    return TokenVerificationResult(
        valid=True,
        claims=claims,
    )
