"""Tamper-evident hash-chained audit ledger service for BitGuard (Invariant #7)."""

import hashlib
from datetime import UTC, datetime

from services.bitguard.models import AuditEntry, DataLabel


class AuditService:
    """Append-only cryptographic audit chain preserving tamper evidence."""

    GENESIS_PREV_HASH: str = "0" * 64

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def compute_entry_hash(
        self,
        prev_hash: str,
        timestamp: float,
        event_type: str,
        request_id: str,
        verdict: str,
    ) -> str:
        """Computes deterministic SHA-256 hash over chained fields."""
        payload = f"{prev_hash}:{timestamp}:{event_type}:{request_id}:{verdict}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def append_entry(
        self,
        event_type: str,
        request_id: str,
        verdict: str,
        data_label: DataLabel = DataLabel.REAL,
        timestamp: float | None = None,
    ) -> AuditEntry:
        """Appends a new immutable entry to the hash chain."""
        ts = timestamp if timestamp is not None else datetime.now(UTC).timestamp()
        idx = len(self._entries)
        prev_hash = self._entries[-1].entry_hash if self._entries else self.GENESIS_PREV_HASH
        entry_hash = self.compute_entry_hash(prev_hash, ts, event_type, request_id, verdict)

        entry = AuditEntry(
            index=idx,
            timestamp=ts,
            event_type=event_type,
            request_id=request_id,
            verdict=verdict,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            data_label=data_label,
        )
        self._entries.append(entry)
        return entry

    def verify_integrity(self) -> tuple[bool, int | None]:
        """Validates all cryptographic hashes and parent pointers across the entire chain."""
        expected_prev = self.GENESIS_PREV_HASH
        for i, entry in enumerate(self._entries):
            if entry.prev_hash != expected_prev:
                return False, i
            recomputed = self.compute_entry_hash(
                entry.prev_hash,
                entry.timestamp,
                entry.event_type,
                entry.request_id,
                entry.verdict,
            )
            if recomputed != entry.entry_hash:
                return False, i
            expected_prev = entry.entry_hash
        return True, None

    def get_entries(self) -> list[AuditEntry]:
        """Returns all audit chain entries."""
        return list(self._entries)


# Global singleton instance
audit_service = AuditService()
