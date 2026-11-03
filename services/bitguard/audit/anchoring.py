"""Object-lock external anchoring service for BitGuard audit chain (Milestone S21 / F18).

Invariants:
- Invariant #7: Immutable Audit Trail. Periodic cryptographic anchor checkpoints
  written to WORM (Write Once, Read Many) object-locked cloud buckets.
- Invariant #8: Explicit Data Provenance.
"""

import logging
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from services.bitguard.audit.canonical import canonical_json
from services.bitguard.config import settings

logger = logging.getLogger("bitguard.audit.anchoring")


class ObjectLockAnchorService:
    """Manages writing and retrieving tamper-evident checkpoints from an object-locked bucket."""

    def __init__(self) -> None:
        self.endpoint = settings.audit_minio_endpoint
        self.bucket = settings.audit_minio_bucket
        self.access_key = settings.audit_minio_access_key
        self.secret_key = settings.audit_minio_secret_key
        self.interval_seconds = settings.audit_anchor_interval_seconds
        self.enabled = settings.audit_anchor_enabled

        self._lock = threading.Lock()
        self._local_anchors: list[dict[str, Any]] = []
        self._timer: threading.Timer | None = None
        self._stop_event = threading.Event()

    def set_endpoint(self, endpoint: str) -> None:
        """Configures custom S3/MinIO endpoint (test utility)."""
        self.endpoint = endpoint

    def clear(self) -> None:
        """Clears in-memory anchor cache (test utility)."""
        with self._lock:
            self._local_anchors.clear()

    def record_anchor(self, head_hash: str, seq: int, ts: float | None = None) -> dict[str, Any]:
        """Creates and stores an immutable anchor checkpoint {head_hash, seq, ts}."""
        anchor_ts = ts if ts is not None else time.time()
        anchor_data = {
            "head_hash": head_hash,
            "seq": seq,
            "ts": anchor_ts,
        }
        object_key = f"anchors/anchor_{seq:012d}_{int(anchor_ts)}.json"
        storage_uri = f"{self.endpoint}/{self.bucket}/{object_key}"

        # 1. Attempt upload to object-lock MinIO / S3 bucket
        uploaded = False
        retain_until = (datetime.now(UTC) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")

        try:
            with httpx.Client(timeout=1.0) as client:
                body = canonical_json(anchor_data).encode("utf-8")
                headers = {
                    "Content-Type": "application/json",
                    "x-amz-object-lock-mode": "GOVERNANCE",
                    "x-amz-object-lock-retain-until-date": retain_until,
                }
                # Basic auth compatibility for MinIO root credentials
                resp = client.put(storage_uri, content=body, headers=headers, auth=(self.access_key, self.secret_key))
                if resp.status_code in [200, 201]:
                    uploaded = True
                    logger.info("audit_anchor_written_to_minio: seq=%d head=%s", seq, head_hash[:16])
        except Exception as exc:
            logger.debug("minio_anchor_upload_unavailable_using_local_receipt: %s", exc)

        anchor_record = {
            "id": f"anc-{uuid.uuid4().hex[:12]}",
            "seq": seq,
            "head_hash": head_hash,
            "ts": anchor_ts,
            "storage_uri": storage_uri,
            "object_lock_mode": "GOVERNANCE",
            "uploaded": uploaded,
            "data_label": "REAL",
        }

        with self._lock:
            self._local_anchors.append(anchor_record)

        return anchor_record

    def get_latest_anchor(self) -> dict[str, Any] | None:
        """Returns the most recent anchor record or None if unanchored."""
        with self._lock:
            if not self._local_anchors:
                return None
            return dict(self._local_anchors[-1])

    def list_anchors(self) -> list[dict[str, Any]]:
        """Returns all recorded anchor checkpoints."""
        with self._lock:
            return [dict(a) for a in self._local_anchors]

    def add_simulated_anchor(self, head_hash: str, seq: int, ts: float | None = None) -> dict[str, Any]:
        """Manually records an anchor for test simulation."""
        return self.record_anchor(head_hash=head_hash, seq=seq, ts=ts)


anchor_service = ObjectLockAnchorService()
