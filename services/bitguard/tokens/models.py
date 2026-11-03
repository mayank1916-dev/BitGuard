"""Pydantic data models for BitGuard Ed25519 approval tokens (Milestone S11 / F1)."""

import time
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class KeyStatus(StrEnum):
    """Lifecycle status for token signing/verification keys."""

    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


class ApprovalTokenClaims(BaseModel):
    """Cryptographic approval token claims bound to transaction parameters."""

    model_config = ConfigDict(populate_by_name=True)

    digest: str = Field(description="Canonical keccak256 digest of unsigned transaction payload")
    wallet: str = Field(description="Normalized hot wallet address")
    chain: str = Field(description="Canonical blockchain identifier (e.g. ethereum)")
    iat: int = Field(default_factory=lambda: int(time.time()), description="Issued-at Unix timestamp")
    exp: int = Field(description="Expiration Unix timestamp (strictly iat + 60s)")
    nonce: str = Field(description="Random 128-bit single-use hex nonce")
    kid: str = Field(description="Key identifier used for signature generation and rotation")


class TokenHeader(BaseModel):
    """Standard JWS header for Ed25519 approval tokens."""

    alg: str = Field(default="EdDSA", description="Signature algorithm (EdDSA Ed25519)")
    typ: str = Field(default="JWT", description="Token type")
    kid: str = Field(description="Key ID")


class TokenVerificationResult(BaseModel):
    """Outcome of token signature and claim verification."""

    valid: bool
    claims: ApprovalTokenClaims | None = None
    error_code: str | None = None
    error_detail: str | None = None
