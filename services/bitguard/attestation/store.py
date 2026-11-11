"""Allowed image store loading and caching policy/allowed_images.json (Milestone S33 / F16).

Invariants:
- Invariant #1: Fast in-memory digest lookups.
- Invariant #3: Fail-Closed Default. Unlisted digests are not permitted.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from services.bitguard.attestation.models import AllowedImageRecord, AllowedImagesManifest

logger = logging.getLogger("bitguard.attestation.store")


class AllowedImagesStore:
    """Thread-safe store for authorized container image digests published by CI."""

    def __init__(self, file_path: str | Path = "policy/allowed_images.json") -> None:
        self.file_path = Path(file_path)
        self._lock = threading.RLock()
        self._allowed_digests: set[str] = set()
        self._allowed_images: list[AllowedImageRecord] = []
        self._last_mtime: float = 0.0
        self._manifest: AllowedImagesManifest | None = None
        self._load_if_modified()

    def _load_if_modified(self) -> None:
        """Loads or reloads allowed_images.json if the file timestamp changed."""
        with self._lock:
            if not self.file_path.exists():
                return
            try:
                mtime = self.file_path.stat().st_mtime
                if mtime > self._last_mtime:
                    content = self.file_path.read_text(encoding="utf-8")
                    data = json.loads(content)
                    manifest = AllowedImagesManifest.model_validate(data)
                    self._manifest = manifest
                    self._allowed_images = manifest.allowed_images

                    # Collect all digests in lowercase for case-insensitive matching
                    digests: set[str] = {d.strip().lower() for d in manifest.allowed_digests}
                    for img in manifest.allowed_images:
                        if img.digest:
                            digests.add(img.digest.strip().lower())
                    self._allowed_digests = digests
                    self._last_mtime = mtime
                    logger.debug("Loaded %d allowed image digests from %s", len(digests), self.file_path)
            except Exception as exc:
                logger.warning("failed_loading_allowed_images: %s", exc)

    def is_digest_allowed(self, digest: str) -> bool:
        """Verifies if a container image digest is in the authorized policy set."""
        self._load_if_modified()
        if not digest:
            return False
        clean = digest.strip().lower()
        # Check both with and without sha256: prefix
        clean_with_prefix = clean if clean.startswith("sha256:") else f"sha256:{clean}"
        clean_without_prefix = clean.removeprefix("sha256:")
        with self._lock:
            return (
                clean_with_prefix in self._allowed_digests
                or clean_without_prefix in self._allowed_digests
            )

    def add_allowed_digest(self, digest: str, image: str | None = None, tag: str | None = None) -> None:
        """Dynamically registers an allowed image digest (useful in test environments)."""
        clean = digest.strip().lower()
        if not clean.startswith("sha256:"):
            clean = f"sha256:{clean}"
        with self._lock:
            self._allowed_digests.add(clean)
            if image:
                self._allowed_images.append(
                    AllowedImageRecord(
                        image=image,
                        tag=tag or "latest",
                        digest=clean,
                    )
                )

    def reset(self) -> None:
        """Resets the store and forces a reload from disk."""
        with self._lock:
            self._allowed_digests.clear()
            self._allowed_images.clear()
            self._last_mtime = 0.0
            self._load_if_modified()


# Global singleton store
allowed_images_store = AllowedImagesStore()
