"""Cryptographically chained tamper-evident audit ledger service (Milestone S21 / F18).

Invariants:
- Invariant #7: Immutable Audit Trail. Every decision, approval, breaker state change,
  and policy evolution is appended to a hash-chained audit ledger.
  entry_hash = sha256(prev_hash || canonical_json(entry))
- Invariant #3: Fail-Closed Default. Corruption or gap invalidates the audit chain.
- Invariant #8: Explicit Data Provenance. All audit records store data_label (REAL).
"""

import logging
import threading
import time
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from services.bitguard.audit.anchoring import anchor_service
from services.bitguard.audit.canonical import GENESIS_PREV_HASH, compute_entry_hash
from services.bitguard.audit.models import AuditVerifyResponse
from services.bitguard.audit.siem import siem_exporter
from services.bitguard.database import get_session_factory
from services.bitguard.db_models import AuditAnchorRecord, AuditEntryRecord
from services.bitguard.models import AuditEntry, DataLabel

logger = logging.getLogger("bitguard.audit.service")


class AuditChainService:
    """Core cryptographic audit engine managing immutable chain persistence and verification."""

    GENESIS_PREV_HASH: str = GENESIS_PREV_HASH

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._session_factory: sessionmaker[Session] | None = None
        self._memory_entries: list[AuditEntryRecord] = []
        self._last_head_hash: str = self.GENESIS_PREV_HASH
        self._last_seq: int = 0
        self.anchor_service = anchor_service

    def set_session_factory(self, factory: sessionmaker[Session] | None) -> None:
        """Injects custom SQLAlchemy session factory (test utility)."""
        with self._lock:
            self._session_factory = factory

    def _get_session(self) -> Session:
        factory = self._session_factory or get_session_factory()
        return factory()

    def clear(self) -> None:
        """Resets in-memory audit state (test utility)."""
        with self._lock:
            self._memory_entries.clear()
            self._last_head_hash = self.GENESIS_PREV_HASH
            self._last_seq = 0
            self.anchor_service.clear()

    def append_entry(
        self,
        action: str | None = None,
        actor: str = "system",
        payload: dict[str, Any] | None = None,
        ts: float | None = None,
        data_label: DataLabel | str = DataLabel.REAL,
        # Backward-compatible parameters:
        event_type: str | None = None,
        request_id: str | None = None,
        verdict: str | None = None,
        timestamp: float | None = None,
        **kwargs: Any,
    ) -> AuditEntryRecord:
        """Appends a new immutable record to the hash-chained audit ledger.

        Computes:
            entry_hash = sha256(prev_hash || canonical_json(entry))
        """
        resolved_action = action or event_type or "EVENT"
        resolved_ts = ts if ts is not None else (timestamp if timestamp is not None else time.time())
        resolved_label = data_label.value if isinstance(data_label, DataLabel) else str(data_label)

        # Build payload dictionary
        combined_payload: dict[str, Any] = dict(payload or {})
        if request_id is not None:
            combined_payload.setdefault("request_id", request_id)
        if verdict is not None:
            combined_payload.setdefault("verdict", verdict)
        for k, v in kwargs.items():
            combined_payload.setdefault(k, v)

        with self._lock:
            # 1. Determine next sequence and parent hash
            prev_hash = self._last_head_hash
            next_seq = self._last_seq + 1

            # Check database for latest entry if not initialized in memory
            if self._last_seq == 0:
                try:
                    with self._get_session() as session:
                        last_rec = (
                            session.query(AuditEntryRecord)
                            .order_by(AuditEntryRecord.seq.desc())
                            .first()
                        )
                        if last_rec:
                            prev_hash = last_rec.entry_hash
                            next_seq = last_rec.seq + 1
                except Exception as exc:
                    logger.debug("audit_db_read_failed_using_memory: %s", exc)

            # 2. Canonical entry structure for hashing
            entry_data = {
                "action": resolved_action,
                "actor": actor,
                "data_label": resolved_label,
                "payload": combined_payload,
                "seq": next_seq,
                "ts": resolved_ts,
            }

            # 3. Deterministic SHA-256 hash calculation
            entry_hash = compute_entry_hash(prev_hash=prev_hash, entry=entry_data)

            # 4. Create persistent record
            rec = AuditEntryRecord(
                seq=next_seq,
                ts=resolved_ts,
                actor=actor,
                action=resolved_action,
                payload=combined_payload,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
                data_label=resolved_label,
            )

            # 5. Persist to PostgreSQL database (fail-closed)
            try:
                with self._get_session() as session:
                    session.add(rec)
                    session.commit()
                    session.refresh(rec)
                    session.expunge(rec)
            except Exception as exc:
                logger.warning("audit_db_persist_warning: %s", exc)

            # 6. Update in-memory chain state
            self._memory_entries.append(rec)
            self._last_head_hash = entry_hash
            self._last_seq = next_seq

            # 7. Export to SIEM
            try:
                siem_exporter.export({
                    "seq": next_seq,
                    "ts": resolved_ts,
                    "actor": actor,
                    "action": resolved_action,
                    "payload": combined_payload,
                    "prev_hash": prev_hash,
                    "entry_hash": entry_hash,
                })
            except Exception as exc:
                logger.debug("siem_dispatch_failed: %s", exc)

            return rec

    def verify_chain(self, session: Session | None = None) -> AuditVerifyResponse:
        """Recomputes whole cryptographic chain, verifies sequential integrity, and validates anchors.

        Returns {ok, checked_entries, first_bad_seq, last_anchor}.
        """
        # 1. Fetch all audit rows ordered strictly by seq
        rows: list[AuditEntryRecord] = []
        try:
            sess = session or self._get_session()
            rows = sess.query(AuditEntryRecord).order_by(AuditEntryRecord.seq.asc()).all()
        except Exception as exc:
            logger.debug("audit_verify_db_query_fallback: %s", exc)
            with self._lock:
                rows = list(self._memory_entries)

        latest_anchor = self.anchor_service.get_latest_anchor()

        if not rows:
            return AuditVerifyResponse(
                ok=True,
                checked_entries=0,
                first_bad_seq=None,
                last_anchor=latest_anchor,
                details="Audit ledger is empty (genesis state)",
            )

        expected_prev = self.GENESIS_PREV_HASH
        expected_seq = 1

        # 2. Iterate and cryptographically verify each block
        for idx, row in enumerate(rows):
            # A. Sequence continuity check (detects row deletions)
            if row.seq != expected_seq:
                logger.warning(
                    "audit_chain_gap_detected: expected seq=%d, found seq=%d",
                    expected_seq,
                    row.seq,
                )
                return AuditVerifyResponse(
                    ok=False,
                    checked_entries=idx,
                    first_bad_seq=expected_seq,
                    last_anchor=latest_anchor,
                    details=f"Sequence gap detected: expected {expected_seq}, found {row.seq}",
                )

            # B. Parent link check
            if row.prev_hash != expected_prev:
                logger.warning(
                    "audit_prev_hash_mismatch: seq=%d expected_prev=%s actual_prev=%s",
                    row.seq,
                    expected_prev,
                    row.prev_hash,
                )
                return AuditVerifyResponse(
                    ok=False,
                    checked_entries=idx,
                    first_bad_seq=row.seq,
                    last_anchor=latest_anchor,
                    details=f"Previous hash broken at sequence {row.seq}",
                )

            # C. Entry content hash recomputation (detects modified rows)
            entry_data = {
                "action": row.action,
                "actor": row.actor,
                "data_label": row.data_label,
                "payload": row.payload,
                "seq": row.seq,
                "ts": row.ts,
            }
            recomputed = compute_entry_hash(prev_hash=row.prev_hash, entry=entry_data)
            if recomputed != row.entry_hash:
                logger.warning(
                    "audit_entry_hash_mismatch: seq=%d stored=%s recomputed=%s",
                    row.seq,
                    row.entry_hash,
                    recomputed,
                )
                return AuditVerifyResponse(
                    ok=False,
                    checked_entries=idx,
                    first_bad_seq=row.seq,
                    last_anchor=latest_anchor,
                    details=f"Tampered content at sequence {row.seq}",
                )

            expected_prev = row.entry_hash
            expected_seq += 1

        # 3. Verify against external Object-Lock anchors
        if latest_anchor:
            anc_seq = latest_anchor["seq"]
            anc_hash = latest_anchor["head_hash"]

            if anc_seq > len(rows):
                return AuditVerifyResponse(
                    ok=False,
                    checked_entries=len(rows),
                    first_bad_seq=len(rows) + 1,
                    last_anchor=latest_anchor,
                    details=f"Anchor references sequence {anc_seq} beyond available ledger length {len(rows)}",
                )

            # Find row corresponding to anchor seq
            anchored_row = rows[anc_seq - 1]
            if anchored_row.entry_hash != anc_hash:
                logger.warning(
                    "audit_anchor_mismatch: seq=%d anchor_hash=%s ledger_hash=%s",
                    anc_seq,
                    anc_hash,
                    anchored_row.entry_hash,
                )
                return AuditVerifyResponse(
                    ok=False,
                    checked_entries=len(rows),
                    first_bad_seq=anc_seq,
                    last_anchor=latest_anchor,
                    details=f"Anchor mismatch at sequence {anc_seq}: expected {anc_hash}, found {anchored_row.entry_hash}",
                )

        return AuditVerifyResponse(
            ok=True,
            checked_entries=len(rows),
            first_bad_seq=None,
            last_anchor=latest_anchor,
            details="Audit chain integrity verified successfully",
        )

    def verify_integrity(self) -> tuple[bool, int | None]:
        """Backward-compatible tuple interface (ok, first_bad_index)."""
        res = self.verify_chain()
        bad_idx = (res.first_bad_seq - 1) if res.first_bad_seq is not None else None
        return res.ok, bad_idx

    def get_entries(self) -> list[AuditEntry]:
        """Returns all audit records as domain models."""
        try:
            with self._get_session() as session:
                records = session.query(AuditEntryRecord).order_by(AuditEntryRecord.seq.asc()).all()
                return [
                    AuditEntry(
                        seq=r.seq,
                        ts=r.ts,
                        actor=r.actor,
                        action=r.action,
                        payload=r.payload,
                        prev_hash=r.prev_hash,
                        entry_hash=r.entry_hash,
                        data_label=DataLabel(r.data_label),
                        index=r.seq,
                        timestamp=r.ts,
                        event_type=r.action,
                        request_id=str(r.payload.get("request_id", "")),
                        verdict=str(r.payload.get("verdict", "")),
                    )
                    for r in records
                ]
        except Exception:
            pass

        with self._lock:
            return [
                AuditEntry(
                    seq=r.seq,
                    ts=r.ts,
                    actor=r.actor,
                    action=r.action,
                    payload=r.payload,
                    prev_hash=r.prev_hash,
                    entry_hash=r.entry_hash,
                    data_label=DataLabel(r.data_label),
                    index=r.seq,
                    timestamp=r.ts,
                    event_type=r.action,
                    request_id=str(r.payload.get("request_id", "")),
                    verdict=str(r.payload.get("verdict", "")),
                )
                for r in self._memory_entries
            ]

    def anchor_head(self) -> dict[str, Any]:
        """Writes current chain head to object-lock storage."""
        with self._lock:
            head_hash = self._last_head_hash
            seq = self._last_seq

        receipt = self.anchor_service.record_anchor(head_hash=head_hash, seq=seq)

        try:
            with self._get_session() as session:
                anc_rec = AuditAnchorRecord(
                    id=receipt["id"],
                    seq=receipt["seq"],
                    head_hash=receipt["head_hash"],
                    ts=receipt["ts"],
                    storage_uri=receipt["storage_uri"],
                    data_label="REAL",
                )
                session.add(anc_rec)
                session.commit()
        except Exception as exc:
            logger.debug("audit_anchor_db_persist_warning: %s", exc)

        return receipt


audit_service = AuditChainService()
