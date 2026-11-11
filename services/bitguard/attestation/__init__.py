"""Caller identity and build attestation package (Milestone S33 / F16)."""

from services.bitguard.attestation.models import (
    AllowedImageRecord,
    AllowedImagesManifest,
    AttestationCheckResult,
)
from services.bitguard.attestation.store import AllowedImagesStore, allowed_images_store
from services.bitguard.attestation.verifier import (
    CallerAttestationVerifier,
    caller_attestation_verifier,
)

__all__ = [
    "AllowedImageRecord",
    "AllowedImagesManifest",
    "AllowedImagesStore",
    "AttestationCheckResult",
    "CallerAttestationVerifier",
    "allowed_images_store",
    "caller_attestation_verifier",
]
