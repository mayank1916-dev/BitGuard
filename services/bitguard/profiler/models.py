"""Address profiler and sanctions risk models (Milestone S27 / Section C)."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ListManifestFile(BaseModel):
    """Manifest entry for a single list file."""

    filename: str
    sha256: str
    count: int = 0
    updated_at: str | None = None


class ListManifest(BaseModel):
    """Manifest verifying integrity and authenticity of local lists."""

    version: str = "1.0.0"
    created_at: str
    files: list[ListManifestFile]
    signature: str | None = None  # Optional hex Ed25519 signature
    signer_public_key: str | None = None


class AddressProfile(BaseModel):
    """Cached deep profile for an address (populated out-of-band by ProfileWorker)."""

    address: str
    chain: str = "ethereum"
    is_contract: bool = False
    contract_age_blocks: int | None = None
    contract_age_days: float | None = None
    code_hash: str | None = None
    first_seen_at: datetime | None = None
    known_wallets_sent: list[str] = Field(default_factory=list)
    taint_exposure_score: float = 0.0  # 0.0 to 100.0 from AML provider
    taint_provider: str = "mock"
    is_sanctioned: bool = False
    is_blocked: bool = False
    is_known_bad_code: bool = False
    updated_at: float = 0.0
    expires_at: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProfileScoreResult(BaseModel):
    """Calculated risk score and reasons for a transaction destination."""

    risk_score: int = Field(ge=0, le=100)
    is_hard_deny: bool = False
    reasons: list[dict[str, Any]] = Field(default_factory=list)
    is_unprofiled: bool = False
