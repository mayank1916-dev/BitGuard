"""Local sanctions, blocklists, and known-bad bytecode repository (Milestone S27 / Section C).

Invariants:
- Invariant #3: Fail-Closed Default. Poisoned or corrupted feeds fail closed and are rejected.
- Invariant #9: Environment & Safety Boundary. Use small FAKE fixture lists only; never fabricate real sanctioned addresses.
"""

import hashlib
import json
import logging
import shutil
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from services.bitguard.profiler.models import ListManifest

logger = logging.getLogger("bitguard.profiler.lists")


class ListIntegrityError(Exception):
    """Raised when a list file fails SHA-256 checksum or cryptographic signature verification."""


class SanctionListStore:
    """Thread-safe in-memory cache for sanctions, blocklists, and known-bad bytecode hashes.

    Provides sub-microsecond in-memory set matching and safe atomic hot-reloads.
    """

    def __init__(self, lists_dir: Path | None = None) -> None:
        self.lists_dir = lists_dir or Path("lists")
        self._lock = threading.RLock()
        self._sanctions: set[str] = set()
        self._blocklist: set[str] = set()
        self._known_bad_hashes: set[str] = set()
        self._manifest: ListManifest | None = None
        self._last_loaded_at: float = 0.0

    @property
    def sanctions_count(self) -> int:
        with self._lock:
            return len(self._sanctions)

    @property
    def blocklist_count(self) -> int:
        with self._lock:
            return len(self._blocklist)

    @property
    def known_bad_hashes_count(self) -> int:
        with self._lock:
            return len(self._known_bad_hashes)

    @property
    def manifest(self) -> ListManifest | None:
        with self._lock:
            return self._manifest

    # -----------------------------------------------------------------
    # Microsecond In-Memory Matching
    # -----------------------------------------------------------------

    def is_sanctioned(self, address: str) -> bool:
        """Microsecond lookup testing if address is on local sanctions list."""
        if not address:
            return False
        clean = address.strip().lower()
        return clean in self._sanctions

    def is_blocked(self, address: str) -> bool:
        """Microsecond lookup testing if address is on local blocklist."""
        if not address:
            return False
        clean = address.strip().lower()
        return clean in self._blocklist

    def is_known_bad_code(self, code_hash: str) -> bool:
        """Microsecond lookup testing if bytecode hash is known-bad."""
        if not code_hash:
            return False
        clean = code_hash.strip().lower()
        return clean in self._known_bad_hashes

    def match_address(self, address: str) -> str | None:
        """Returns the first matching list name for an address, or None."""
        if not address:
            return None
        clean = address.strip().lower()
        if clean in self._sanctions:
            return "SANCTIONS"
        if clean in self._blocklist:
            return "BLOCKLIST"
        return None

    # -----------------------------------------------------------------
    # Verification and Loading
    # -----------------------------------------------------------------

    def load_from_directory(self, directory: Path | None = None) -> None:
        """Loads and atomically activates lists from a verified directory."""
        dir_to_load = directory or self.lists_dir
        if not dir_to_load.exists():
            logger.warning("Sanction lists directory '%s' does not exist; initialized empty.", dir_to_load)
            return

        manifest_path = dir_to_load / "manifest.json"
        if not manifest_path.exists():
            logger.warning("Manifest file '%s' not found; refusing unverified list load.", manifest_path)
            return

        # 1. Parse manifest
        manifest = self._parse_manifest(manifest_path)

        # 2. Verify files and parse contents into staging sets
        sanctions, blocklist, bad_hashes = self._verify_and_parse_files(dir_to_load, manifest)

        # 3. Atomic swap into in-memory sets
        with self._lock:
            self._sanctions = sanctions
            self._blocklist = blocklist
            self._known_bad_hashes = bad_hashes
            self._manifest = manifest
            import time
            self._last_loaded_at = time.time()

        logger.info(
            "Sanction lists atomically loaded from %s (sanctions=%d, blocklist=%d, bad_hashes=%d)",
            dir_to_load, len(sanctions), len(blocklist), len(bad_hashes)
        )

    def refresh_from_staging(self, staging_dir: Path, target_dir: Path | None = None) -> None:
        """Atomically swaps verified staging lists into target directory and active memory.

        If any checksum or signature fails:
        - The poisoned update is completely rejected
        - Existing in-memory sets remain untouched
        - An alert is logged
        """
        dest_dir = target_dir or self.lists_dir
        manifest_path = staging_dir / "manifest.json"
        if not manifest_path.exists():
            err_msg = f"Staged manifest '{manifest_path}' does not exist; refresh rejected."
            logger.error("ALERT_LIST_INTEGRITY_FAILURE: %s", err_msg)
            raise ListIntegrityError(err_msg)

        # 1. Parse staged manifest
        manifest = self._parse_manifest(manifest_path)

        # 2. Verify all staged files against SHA-256 and signature
        try:
            sanctions, blocklist, bad_hashes = self._verify_and_parse_files(staging_dir, manifest)
        except Exception as exc:
            logger.critical(
                "ALERT_LIST_INTEGRITY_FAILURE: Staged list feed failed checksum verification: %s. "
                "Update rejected; active in-memory sets preserved.",
                exc
            )
            raise ListIntegrityError(f"Staged lists verification failed: {exc}") from exc

        # 3. Copy staged files to target directory
        dest_dir.mkdir(parents=True, exist_ok=True)
        for mf in manifest.files:
            src_f = staging_dir / mf.filename
            dst_f = dest_dir / mf.filename
            shutil.copy2(src_f, dst_f)
        shutil.copy2(manifest_path, dest_dir / "manifest.json")

        # 4. Atomically swap in-memory sets
        with self._lock:
            self._sanctions = sanctions
            self._blocklist = blocklist
            self._known_bad_hashes = bad_hashes
            self._manifest = manifest
            import time
            self._last_loaded_at = time.time()

        logger.info(
            "Sanction lists successfully refreshed and atomically swapped from staging (items=%d)",
            len(sanctions) + len(blocklist) + len(bad_hashes)
        )

    # -----------------------------------------------------------------
    # Internal Helpers
    # -----------------------------------------------------------------

    def _parse_manifest(self, manifest_path: Path) -> ListManifest:
        try:
            with open(manifest_path, encoding="utf-8") as f:
                data = json.load(f)
            manifest = ListManifest.model_validate(data)
        except Exception as exc:
            raise ListIntegrityError(f"Failed to parse manifest '{manifest_path}': {exc}") from exc

        # Verify signature if present
        if manifest.signature and manifest.signer_public_key:
            self._verify_manifest_signature(manifest)

        return manifest

    def _verify_manifest_signature(self, manifest: ListManifest) -> None:
        """Verifies Ed25519 signature over canonical manifest payload without signature field."""
        if not manifest.signer_public_key or not manifest.signature:
            raise ListIntegrityError("Manifest missing signature or signer public key")

        try:
            pub_bytes = bytes.fromhex(manifest.signer_public_key.removeprefix("0x"))
            sig_bytes = bytes.fromhex(manifest.signature.removeprefix("0x"))
            pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

            canonical_dict = manifest.model_dump(exclude={"signature"})
            canonical_bytes = json.dumps(canonical_dict, sort_keys=True).encode("utf-8")
            pub_key.verify(sig_bytes, canonical_bytes)
        except InvalidSignature as exc:
            raise ListIntegrityError("Manifest Ed25519 signature is invalid!") from exc
        except Exception as exc:
            raise ListIntegrityError(f"Manifest signature check error: {exc}") from exc

    def _verify_and_parse_files(
        self,
        base_dir: Path,
        manifest: ListManifest,
    ) -> tuple[set[str], set[str], set[str]]:
        """Verifies SHA-256 for each file in the manifest and returns parsed normalized sets."""
        sanctions: set[str] = set()
        blocklist: set[str] = set()
        bad_hashes: set[str] = set()

        for file_meta in manifest.files:
            file_path = base_dir / file_meta.filename
            if not file_path.exists():
                raise ListIntegrityError(f"List file '{file_meta.filename}' declared in manifest but not found on disk")

            with open(file_path, "rb") as f:
                content_bytes = f.read()

            computed_sha256 = hashlib.sha256(content_bytes).hexdigest().lower()
            expected_sha256 = file_meta.sha256.lower()

            if computed_sha256 != expected_sha256:
                raise ListIntegrityError(
                    f"Checksum mismatch for '{file_meta.filename}': "
                    f"expected {expected_sha256}, got {computed_sha256}"
                )

            # Parse content
            try:
                parsed_json = json.loads(content_bytes.decode("utf-8"))
            except Exception as exc:
                raise ListIntegrityError(f"File '{file_meta.filename}' contains invalid JSON: {exc}") from exc

            items = self._extract_items(parsed_json)
            name_lower = file_meta.filename.lower()
            if "sanction" in name_lower:
                sanctions.update(items)
            elif "block" in name_lower:
                blocklist.update(items)
            elif "hash" in name_lower or "code" in name_lower or "bytecode" in name_lower:
                bad_hashes.update(items)
            else:
                # Default to blocklist
                blocklist.update(items)

        return sanctions, blocklist, bad_hashes

    def _extract_items(self, parsed_json: Any) -> Iterable[str]:
        """Normalizes address / hash items from list or dictionary."""
        results: set[str] = set()
        raw_list: list[Any] = []
        if isinstance(parsed_json, list):
            raw_list = parsed_json
        elif isinstance(parsed_json, dict):
            raw_list = parsed_json.get("addresses") or parsed_json.get("hashes") or parsed_json.get("entries") or []

        for item in raw_list:
            if isinstance(item, str):
                results.add(item.strip().lower())
            elif isinstance(item, dict):
                val = item.get("address") or item.get("hash") or item.get("id")
                if isinstance(val, str):
                    results.add(val.strip().lower())
        return results

    def reset_for_test(
        self,
        sanctions: Iterable[str] | None = None,
        blocklist: Iterable[str] | None = None,
        bad_hashes: Iterable[str] | None = None,
    ) -> None:
        """Utility for test suites to set in-memory sets directly with FAKE addresses."""
        with self._lock:
            self._sanctions = {s.strip().lower() for s in (sanctions or [])}
            self._blocklist = {b.strip().lower() for b in (blocklist or [])}
            self._known_bad_hashes = {h.strip().lower() for h in (bad_hashes or [])}


# Global default instance
sanction_store = SanctionListStore()
