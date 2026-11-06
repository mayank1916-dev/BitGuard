"""Background worker for expiring quarantined hold tickets (Milestone S14).

Invariants & Rules:
- PENDING tickets past expires_at become EXPIRED.
- Original request counts as DENY (audit ledger entry).
- Limit reservations are released immediately.
- Emits stream event for live consoles.
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from services.bitguard.approvals.hold_store import hold_store
from services.bitguard.database import get_session_factory
from services.bitguard.db_models import HoldTicketRecord
from services.bitguard.limits.store import limit_store
from services.bitguard.models import HoldState
from services.bitguard.stream.broadcaster import stream_broadcaster

logger = logging.getLogger("bitguard.approvals.worker")


class HoldExpiryWorker:
    """Worker periodically sweeping and expiring quarantined tickets past their TTL."""

    def __init__(self, interval_seconds: float = 1.0) -> None:
        self.interval_seconds = interval_seconds
        self._running = False
        self._task: asyncio.Task[Any] | None = None

    def sweep_expired(self) -> list[str]:
        """Synchronously sweeps all tickets past expires_at, transitions to EXPIRED, and releases limits.

        Returns:
            List of expired ticket IDs.
        """
        now = datetime.now(UTC)
        expired_ids: list[str] = []

        # 1. Sweep database records if available
        try:
            factory = get_session_factory()
            with factory() as session:
                stmt = select(HoldTicketRecord).where(
                    HoldTicketRecord.state == HoldState.PENDING.value,
                    HoldTicketRecord.expires_at <= now,
                )
                records = session.execute(stmt).scalars().all()
                for rec in records:
                    expired_ids.append(rec.id)
        except Exception as exc:
            logger.debug("database_sweep_unavailable_checking_memory: %s", exc)

        # 2. Check in-memory tickets as well
        with hold_store._lock:
            for tid, t in hold_store._by_id.items():
                if t.state == HoldState.PENDING.value and t.expires_at <= now:
                    if tid not in expired_ids:
                        expired_ids.append(tid)

        # 3. Transition each expired ticket
        processed_ids: list[str] = []
        for tid in expired_ids:
            try:
                ticket = hold_store.get(tid)
                if ticket is None or ticket.state != HoldState.PENDING.value:
                    continue

                # Release limit reservation
                if ticket.reservation_id:
                    try:
                        limit_store.release(ticket.reservation_id)
                        logger.info("released_limit_reservation_on_expiry: ticket=%s res=%s", tid, ticket.reservation_id)
                    except Exception as exc:
                        logger.warning("failed_releasing_reservation_on_expiry: %s", exc)

                # Transition state to EXPIRED (writes AuditEntry with verdict DENY)
                hold_store.transition_state(
                    ticket_id=tid,
                    new_state=HoldState.EXPIRED.value,
                    actor="system",
                    reason="Quarantine hold expired past TTL without achieving approval quorum",
                )

                # Emit stream event
                data_label_val = ticket.data_label.value if hasattr(ticket.data_label, "value") else str(ticket.data_label)
                stream_broadcaster.publish_event(
                    event_type="HOLD_EXPIRED",
                    payload={
                        "hold_id": ticket.id,
                        "request_id": ticket.request_id,
                        "status": "EXPIRED",
                        "verdict": "DENY",
                        "reason": "EXPIRED_PAST_TTL",
                    },
                    data_label=data_label_val,
                )

                processed_ids.append(tid)
            except Exception as exc:
                logger.error("error_processing_expired_ticket: %s (%s)", tid, exc)

        return processed_ids

    async def _run_loop(self) -> None:
        """Background coroutine loop periodically invoking sweep_expired."""
        logger.info("hold_expiry_worker_started with interval %.1fs", self.interval_seconds)
        while self._running:
            try:
                self.sweep_expired()
            except Exception as exc:
                logger.error("error_in_hold_expiry_worker_loop: %s", exc)
            await asyncio.sleep(self.interval_seconds)

    def start(self) -> None:
        """Starts the background worker task."""
        if self._running:
            return
        self._running = True
        try:
            loop = asyncio.get_running_loop()
            self._task = loop.create_task(self._run_loop())
        except RuntimeError:
            # If no running event loop (e.g. sync test), loop is not started automatically
            pass

    def stop(self) -> None:
        """Stops the background worker."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            self._task = None


hold_expiry_worker = HoldExpiryWorker()
