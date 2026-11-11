"""Data models for caller identity, build attestation, and SPIFFE verification (Milestone S33 / F16).

Invariants:
- Invariant #3: Fail-Closed Default. Unattested or unknown image digests result in HOLD.
- Invariant #7: Immutable Audit Trail. Identity attributes recorded on every Decision.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from services.bitguard.models import DecisionReason


class AllowedImageRecord(BaseModel):
    """Metadata record for an authorized container build image."""

    image: str = Field(description="Container image repository name")
    tag: str = Field(default="latest", description="Image tag or release name")
    digest: str = Field(description="Cryptographic SHA-256 digest of image (sha256:...)")
    built_at: datetime | None = Field(default=None, description="Attested build timestamp")


class AllowedImagesManifest(BaseModel):
    """Repository of authorized container image digests published by CI/CD."""

    version: str = "1.0.0"
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    allowed_images: list[AllowedImageRecord] = Field(default_factory=list)
    allowed_digests: list[str] = Field(default_factory=list)


class AttestationCheckResult(BaseModel):
    """Result of caller attestation and workload identity verification."""

    reasons: list[DecisionReason] = Field(default_factory=list)
    hold_required: bool = False
    details: dict[str, Any] = Field(default_factory=dict)
