"""Decision persistence, filtering, cursor pagination, and audit integration (Milestone S13).

Invariants:
- Invariant #7: Immutable Audit Trail. Every decision is appended to the hash chain.
- Invariant #8: Explicit Data Provenance. All records store data_label (REAL, SYNTHETIC, REPORTED).
- Persists all decision fields: timings, reasons, mode, policy_version, data_label, wallet, chain.
- Indexed on created_at (time) and verdict.
"""

import logging
from collections import deque
from datetime import datetime

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from services.bitguard.audit_service import audit_service
from services.bitguard.database import get_session_factory
from services.bitguard.db_models import DecisionRecord
from services.bitguard.models import (
    DataLabel,
    Decision,
    DecisionReason,
    OperationMode,
    Verdict,
)
from services.bitguard.stream.broadcaster import stream_broadcaster

logger = logging.getLogger("bitguard.decision_store")


class DecisionStore:
    """Manages Postgres persistence, in-memory cache, filtering, and streaming of decisions."""

    def __init__(self, in_memory_capacity: int = 500) -> None:
        self._in_memory: deque[Decision] = deque(maxlen=in_memory_capacity)
        self._by_id: dict[str, Decision] = {}

    def _record_to_domain(self, record: DecisionRecord) -> Decision:
        """Converts a persisted SQLAlchemy DecisionRecord into a domain Decision model."""
        reasons = [
            DecisionReason(
                code=r.get("code", "UNKNOWN"),
                weight=r.get("weight", 0),
                detail=r.get("detail", ""),
            )
            for r in (record.reasons or [])
        ]
        would_verdict = Verdict(record.would_have_verdict) if record.would_have_verdict else None

        return Decision(
            request_id=record.request_id,
            verdict=Verdict(record.verdict),
            would_have_verdict=would_verdict,
            risk_score=record.risk_score,
            reasons=reasons,
            mode=OperationMode(record.mode),
            policy_version=record.policy_version,
            data_label=DataLabel(record.data_label),
            wallet_group=record.wallet_group,
            wallet=record.wallet,
            chain=record.chain,
            is_false_positive=record.is_false_positive,
            evaluation_latency_ms=record.evaluation_latency_ms,
            timings=dict(record.timings or {}),
            created_at=record.created_at,
        )

    def save_decision(self, decision: Decision, db: Session | None = None) -> Decision:
        """Persists a decision in Postgres, caches in memory, and broadcasts to live streams."""
        # 1. Update in-memory collections
        self._by_id[decision.request_id] = decision
        self._in_memory.appendleft(decision)

        # 2. Persist to Postgres database
        record = DecisionRecord(
            id=f"dec-{decision.request_id}",
            request_id=decision.request_id,
            verdict=decision.verdict.value,
            would_have_verdict=decision.would_have_verdict.value if decision.would_have_verdict else None,
            risk_score=decision.risk_score,
            reasons=[r.model_dump() for r in decision.reasons],
            mode=decision.mode.value,
            policy_version=decision.policy_version,
            data_label=decision.data_label.value,
            wallet_group=decision.wallet_group,
            wallet=decision.wallet,
            chain=decision.chain,
            caller_identity=decision.caller_identity,
            caller_image_digest=decision.caller_image_digest,
            caller_deploy_time=decision.caller_deploy_time,
            caller_source_ip=decision.caller_source_ip,
            is_false_positive=decision.is_false_positive,
            evaluation_latency_ms=decision.evaluation_latency_ms,
            timings=decision.timings,
            created_at=decision.created_at,
        )

        should_close = False
        session = db
        if session is None:
            try:
                factory = get_session_factory()
                session = factory()
                should_close = True
            except Exception as exc:
                logger.debug("postgres_connection_unavailable_using_memory: %s", exc)

        if session is not None:
            try:
                session.merge(record)
                session.commit()
            except Exception as exc:
                logger.warning("postgres_decision_persistence_error: %s", exc)
                try:
                    session.rollback()
                except Exception:
                    pass
            finally:
                if should_close:
                    session.close()

        # 3. Append to immutable hash-chained audit log (Invariant #7)
        audit_service.append_entry(
            event_type="DECISION",
            request_id=decision.request_id,
            verdict=decision.verdict.value,
            data_label=decision.data_label,
            caller_identity=decision.caller_identity,
            caller_image_digest=decision.caller_image_digest,
            caller_deploy_time=decision.caller_deploy_time.isoformat() if decision.caller_deploy_time else None,
            caller_source_ip=decision.caller_source_ip,
        )

        # 4. Broadcast live typed event to WebSocket stream subscribers
        try:
            stream_broadcaster.publish_decision(decision)
        except Exception as exc:
            logger.warning("stream_broadcast_error: %s", exc)

        return decision

    save = save_decision

    def get_decision(self, decision_id: str, db: Session | None = None) -> Decision | None:
        """Retrieves a single decision by request ID from memory or Postgres."""
        if decision_id in self._by_id:
            return self._by_id[decision_id]

        # Query database
        should_close = False
        session = db
        if session is None:
            try:
                session = get_session_factory()()
                should_close = True
            except Exception:
                return None

        try:
            stmt = select(DecisionRecord).where(
                (DecisionRecord.request_id == decision_id) | (DecisionRecord.id == decision_id)
            )
            rec = session.execute(stmt).scalar_one_or_none()
            if rec:
                dec = self._record_to_domain(rec)
                self._by_id[dec.request_id] = dec
                return dec
            return None
        finally:
            if should_close and session is not None:
                session.close()

    def get_last_n_decisions(self, n: int = 50) -> list[Decision]:
        """Returns the most recent N decisions for initial WebSocket handshake."""
        # Attempt DB query first for durable history, fallback to in-memory
        try:
            session = get_session_factory()()
            try:
                stmt = select(DecisionRecord).order_by(desc(DecisionRecord.created_at)).limit(n)
                records = session.execute(stmt).scalars().all()
                if records:
                    return [self._record_to_domain(r) for r in records]
            finally:
                session.close()
        except Exception:
            pass

        return list(self._in_memory)[:n]

    def list_decisions(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        verdict: Verdict | str | None = None,
        wallet: str | None = None,
        chain: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
        offset: int = 0,
        db: Session | None = None,
    ) -> tuple[list[Decision], str | None]:
        """Queries decisions with multi-field filtering and cursor-based pagination.

        Returns (decisions, next_cursor).
        """
        verdict_str = verdict.value if isinstance(verdict, Verdict) else verdict

        # Try Postgres query
        should_close = False
        session = db
        if session is None:
            try:
                session = get_session_factory()()
                should_close = True
            except Exception:
                session = None

        if session is not None:
            try:
                stmt = select(DecisionRecord)

                # Filter by time range
                if start_time:
                    stmt = stmt.where(DecisionRecord.created_at >= start_time)
                if end_time:
                    stmt = stmt.where(DecisionRecord.created_at <= end_time)

                # Filter by verdict (indexed)
                if verdict_str:
                    stmt = stmt.where(DecisionRecord.verdict == verdict_str.upper())

                # Filter by wallet and chain (indexed)
                if wallet:
                    stmt = stmt.where(DecisionRecord.wallet.ilike(wallet))
                if chain:
                    stmt = stmt.where(DecisionRecord.chain.ilike(chain))

                # Cursor pagination (based on created_at and id of cursor record)
                if cursor:
                    cursor_rec = session.execute(
                        select(DecisionRecord).where(
                            (DecisionRecord.request_id == cursor) | (DecisionRecord.id == cursor)
                        )
                    ).scalar_one_or_none()
                    if cursor_rec:
                        stmt = stmt.where(
                            (DecisionRecord.created_at < cursor_rec.created_at)
                            | (
                                (DecisionRecord.created_at == cursor_rec.created_at)
                                & (DecisionRecord.id < cursor_rec.id)
                            )
                        )

                stmt = stmt.order_by(desc(DecisionRecord.created_at), desc(DecisionRecord.id))

                if not cursor and offset > 0:
                    stmt = stmt.offset(offset)

                # Fetch limit + 1 to determine if next page exists
                stmt = stmt.limit(limit + 1)
                records = list(session.execute(stmt).scalars().all())

                next_cursor: str | None = None
                if len(records) > limit:
                    next_cursor = records[limit - 1].request_id
                    records = records[:limit]

                return [self._record_to_domain(r) for r in records], next_cursor
            except Exception as exc:
                logger.warning("postgres_query_failed_falling_back_to_memory: %s", exc)
            finally:
                if should_close:
                    session.close()

        # In-memory fallback
        all_decisions = list(self._in_memory)
        filtered: list[Decision] = []

        for d in all_decisions:
            if start_time and d.created_at < start_time:
                continue
            if end_time and d.created_at > end_time:
                continue
            if verdict_str and d.verdict.value != verdict_str.upper():
                continue
            if wallet and (not d.wallet or d.wallet.lower() != wallet.lower()):
                continue
            if chain and (not d.chain or d.chain.lower() != chain.lower()):
                continue
            filtered.append(d)

        # Sort descending by created_at
        filtered.sort(key=lambda x: x.created_at, reverse=True)

        # Handle cursor
        start_idx = 0
        if cursor:
            for idx, item in enumerate(filtered):
                if item.request_id == cursor:
                    start_idx = idx + 1
                    break
        elif offset > 0:
            start_idx = offset

        page = filtered[start_idx : start_idx + limit]
        next_c = page[-1].request_id if len(filtered) > (start_idx + limit) and page else None
        return page, next_c

    def clear(self) -> None:
        """Clears memory caches (test use only)."""
        self._in_memory.clear()
        self._by_id.clear()


# Global singleton instance
decision_store = DecisionStore()
