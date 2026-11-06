"""Durable quarantine and hold ticket store with Postgres persistence and in-memory fallback (Milestone S14).

Invariants:
- Invariant #2: Approval Binding & Verification (one-time approval token).
- Invariant #6: Asymmetric Policy Evolution (cancelling only tightens policy).
- Invariant #7: Immutable Audit Trail (every transition writes an AuditEntry).
- Invariant #8: Explicit Data Provenance (data_label REAL, SYNTHETIC, REPORTED).
- Single-use guarantee: a ticket can produce at most one token (SELECT ... FOR UPDATE).
- Terminal states (DENIED, EXPIRED, CANCELLED, RELEASED) cannot change.
"""

import logging
import threading
from collections import deque
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.bitguard.approvals.exceptions import (
    HoldTicketNotFoundError,
    TicketAlreadyReleasedError,
)
from services.bitguard.approvals.state_machine import TERMINAL_STATES, validate_transition
from services.bitguard.audit_service import audit_service
from services.bitguard.database import get_session_factory
from services.bitguard.db_models import ApprovalRecord, HoldTicketRecord
from services.bitguard.decoders.evm import evm_decoder
from services.bitguard.models import Approval, DataLabel, DecisionReason, HoldState, HoldTicket
from services.bitguard.stream.broadcaster import stream_broadcaster

logger = logging.getLogger("bitguard.approvals.hold_store")


class HoldStore:
    """Manages Postgres persistence, atomic transitions, and memory cache of quarantined hold tickets."""

    def __init__(self, capacity: int = 500) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[str, HoldTicket] = {}
        self._order: deque[str] = deque(maxlen=capacity)

    def _record_to_domain(
        self,
        record: HoldTicketRecord,
        approvals: list[Approval] | None = None,
    ) -> HoldTicket:
        """Converts an ORM record into a domain model."""
        reasons = [
            DecisionReason(
                code=r.get("code", "UNKNOWN"),
                weight=r.get("weight", 0),
                detail=r.get("detail", ""),
            )
            for r in (record.reasons or [])
        ]
        resolved_digest = record.digest or record.tx_digest
        resolved_identity = record.requester_identity or record.requester_id
        resolved_state = record.state or record.status or "PENDING"

        return HoldTicket(
            id=record.id,
            request_id=record.request_id,
            tx_digest=resolved_digest,
            digest=resolved_digest,
            decoded_tx=record.decoded_tx,
            raw_tx=record.raw_tx,
            chain=record.chain or "ethereum",
            wallet=record.wallet,
            amount_usd=record.amount_usd or 0.0,
            requester_id=resolved_identity,
            requester_identity=resolved_identity,
            reservation_id=record.reservation_id,
            risk_score=record.risk_score or 0,
            reasons=reasons,
            state=resolved_state,
            status=resolved_state,
            expires_at=record.expires_at,
            created_at=record.created_at,
            release_not_before=record.release_not_before,
            released_at=record.released_at,
            approvals=approvals or [],
            signed_result=record.signed_result,
            data_label=DataLabel(record.data_label or "REAL"),
        )

    def create(self, ticket: HoldTicket, db: Session | None = None) -> HoldTicket:
        """Saves a new hold ticket to in-memory cache and database, and logs an AuditEntry."""
        # Auto-decode raw transaction if decoded_tx is not explicitly provided
        if ticket.decoded_tx is None and ticket.raw_tx:
            try:
                raw_bytes = bytes.fromhex(ticket.raw_tx.removeprefix("0x"))
                decoded = evm_decoder.decode(raw_bytes)
                ticket.decoded_tx = decoded.model_dump()
            except Exception as exc:
                logger.debug("could_not_pre_decode_raw_tx_on_create: %s", exc)

        with self._lock:
            self._by_id[ticket.id] = ticket
            if ticket.id not in self._order:
                self._order.appendleft(ticket.id)

        resolved_digest = ticket.digest or ticket.tx_digest
        resolved_identity = ticket.requester_identity or ticket.requester_id
        resolved_state = ticket.state or ticket.status or "PENDING"

        record = HoldTicketRecord(
            id=ticket.id,
            request_id=ticket.request_id,
            tx_digest=resolved_digest,
            digest=resolved_digest,
            decoded_tx=ticket.decoded_tx,
            raw_tx=ticket.raw_tx,
            chain=ticket.chain,
            wallet=ticket.wallet,
            amount_usd=ticket.amount_usd,
            requester_id=resolved_identity,
            requester_identity=resolved_identity,
            reservation_id=ticket.reservation_id,
            risk_score=ticket.risk_score,
            reasons=[r.model_dump() for r in ticket.reasons],
            state=resolved_state,
            status=resolved_state,
            expires_at=ticket.expires_at,
            created_at=ticket.created_at,
            release_not_before=ticket.release_not_before,
            released_at=ticket.released_at,
            signed_result=ticket.signed_result,
            data_label=ticket.data_label.value,
        )

        session = db
        should_close = False
        if session is None:
            try:
                factory = get_session_factory()
                session = factory()
                should_close = True
            except Exception as exc:
                logger.debug("database_unavailable_using_memory: %s", exc)

        if session is not None:
            try:
                session.merge(record)
                session.commit()
            except Exception as exc:
                logger.warning("database_hold_ticket_save_error: %s", exc)
                session.rollback()
            finally:
                if should_close:
                    session.close()

        # Invariant #7: Write AuditEntry on ticket creation
        try:
            audit_service.append_entry(
                action="HOLD_TICKET_CREATED",
                actor=resolved_identity or "system",
                payload={
                    "hold_id": ticket.id,
                    "digest": resolved_digest,
                    "chain": ticket.chain,
                    "wallet": ticket.wallet,
                    "amount_usd": ticket.amount_usd,
                    "reasons": [r.model_dump() for r in ticket.reasons],
                },
                verdict="HOLD",
                request_id=ticket.request_id,
                data_label=ticket.data_label,
            )
        except Exception as exc:
            logger.warning("audit_entry_write_failed: %s", exc)

        return ticket

    def get(self, ticket_id: str, db: Session | None = None) -> HoldTicket | None:
        """Retrieves a hold ticket by ID from memory or database."""
        with self._lock:
            ticket = self._by_id.get(ticket_id)
            if ticket is not None:
                return ticket

        session = db
        should_close = False
        if session is None:
            try:
                factory = get_session_factory()
                session = factory()
                should_close = True
            except Exception as exc:
                logger.debug("database_unavailable: %s", exc)

        if session is not None:
            try:
                record = session.get(HoldTicketRecord, ticket_id)
                if record is not None:
                    # Load approvals
                    stmt = select(ApprovalRecord).where(ApprovalRecord.hold_ticket_id == ticket_id)
                    appr_records = session.execute(stmt).scalars().all()
                    domain_approvals = [
                        Approval(
                            id=a.id,
                            hold_ticket_id=a.hold_ticket_id,
                            approver_id=a.approver_id,
                            approver_role=a.approver_role or "Approver",
                            tx_digest=a.tx_digest,
                            webauthn_signature=a.webauthn_signature,
                            assertion_data=a.assertion_data or {},
                            created_at=a.created_at,
                        )
                        for a in appr_records
                    ]
                    ticket = self._record_to_domain(record, domain_approvals)
                    with self._lock:
                        self._by_id[ticket_id] = ticket
                        if ticket_id not in self._order:
                            self._order.appendleft(ticket_id)
                    return ticket
            except Exception as exc:
                logger.warning("database_hold_ticket_get_error: %s", exc)
            finally:
                if should_close:
                    session.close()

        return None

    def add_approval(self, ticket_id: str, approval: Approval, db: Session | None = None) -> HoldTicket | None:
        """Appends an approval to a ticket."""
        ticket = self.get(ticket_id, db=db)
        if ticket is None:
            return None

        with self._lock:
            ticket.approvals.append(approval)
            self._by_id[ticket_id] = ticket

        record = ApprovalRecord(
            id=approval.id,
            hold_ticket_id=approval.hold_ticket_id,
            approver_id=approval.approver_id,
            approver_role=approval.approver_role,
            tx_digest=approval.tx_digest,
            webauthn_signature=approval.webauthn_signature,
            assertion_data=approval.assertion_data,
            created_at=approval.created_at,
        )

        session = db
        should_close = False
        if session is None:
            try:
                factory = get_session_factory()
                session = factory()
                should_close = True
            except Exception as exc:
                logger.debug("database_unavailable: %s", exc)

        if session is not None:
            try:
                session.merge(record)
                session.commit()
            except Exception as exc:
                logger.warning("database_approval_save_error: %s", exc)
                session.rollback()
            finally:
                if should_close:
                    session.close()

        return ticket

    def transition_state(
        self,
        ticket_id: str,
        new_state: str,
        actor: str = "system",
        reason: str = "",
        signed_result: dict[str, Any] | None = None,
        released_at: datetime | None = None,
        db: Session | None = None,
    ) -> HoldTicket:
        """Validates and applies a state transition, updating database, memory, and writing an AuditEntry.

        Raises:
            HoldTicketNotFoundError: If ticket does not exist.
            InvalidHoldStateTransitionError: If transition is invalid or modifies terminal state.
        """
        ticket = self.get(ticket_id, db=db)
        if ticket is None:
            raise HoldTicketNotFoundError(f"Hold ticket '{ticket_id}' not found", ticket_id=ticket_id)

        target = new_state.upper()
        # Enforce valid transitions and terminal state immutability in code
        validate_transition(ticket.state, target, ticket_id=ticket_id)

        session = db
        should_close = False
        if session is None:
            try:
                factory = get_session_factory()
                session = factory()
                should_close = True
            except Exception as exc:
                logger.debug("database_unavailable: %s", exc)

        if session is not None:
            try:
                record = session.get(HoldTicketRecord, ticket_id)
                if record is not None:
                    record.state = target
                    record.status = target
                    if signed_result is not None:
                        record.signed_result = signed_result
                    if released_at is not None:
                        record.released_at = released_at
                    session.commit()
            except Exception as exc:
                logger.warning("database_hold_ticket_transition_error: %s", exc)
                session.rollback()
                raise
            finally:
                if should_close:
                    session.close()

        # Update in-memory state
        with self._lock:
            old_state = ticket.state
            ticket.state = target
            ticket.status = target
            if signed_result is not None:
                ticket.signed_result = signed_result
            if released_at is not None:
                ticket.released_at = released_at
            self._by_id[ticket_id] = ticket

        # Invariant #7: Audit Entry for every transition
        verdict = (
            "ALLOW"
            if target == HoldState.RELEASED.value
            else ("DENY" if target in (HoldState.DENIED.value, HoldState.EXPIRED.value, HoldState.CANCELLED.value) else "HOLD")
        )
        try:
            audit_service.append_entry(
                action=f"HOLD_{target}",
                actor=actor,
                payload={
                    "hold_id": ticket_id,
                    "prev_state": old_state,
                    "new_state": target,
                    "reason": reason,
                },
                verdict=verdict,
                request_id=ticket.request_id,
                data_label=ticket.data_label,
            )
        except Exception as exc:
            logger.warning("audit_entry_write_failed: %s", exc)

        return ticket

    def atomic_release(
        self,
        ticket_id: str,
        actor: str = "system",
        signed_result: dict[str, Any] | None = None,
        db: Session | None = None,
    ) -> HoldTicket:
        """Atomically transitions ticket to RELEASED with single-use guarantee (SELECT ... FOR UPDATE).

        Raises:
            TicketAlreadyReleasedError: If ticket was already released or terminated.
        """
        now = datetime.now(UTC)

        session = db
        should_close = False
        if session is None:
            try:
                factory = get_session_factory()
                session = factory()
                should_close = True
            except Exception as exc:
                logger.debug("database_unavailable: %s", exc)

        with self._lock:
            if session is not None:
                try:
                    stmt = select(HoldTicketRecord).where(HoldTicketRecord.id == ticket_id)
                    # Use with_for_update if supported by dialect
                    try:
                        stmt = stmt.with_for_update()
                    except Exception:
                        pass
                    record = session.execute(stmt).scalar_one_or_none()
                    if record is None:
                        raise HoldTicketNotFoundError(f"Hold ticket '{ticket_id}' not found", ticket_id=ticket_id)

                    current_state = (record.state or record.status or "PENDING").upper()
                    if current_state in TERMINAL_STATES or record.released_at is not None:
                        raise TicketAlreadyReleasedError(
                            f"SINGLE_USE_VIOLATION: Ticket '{ticket_id}' has already been released or terminated (current state: {current_state})",
                            ticket_id=ticket_id,
                        )

                    record.state = HoldState.RELEASED.value
                    record.status = HoldState.RELEASED.value
                    record.released_at = now
                    if signed_result is not None:
                        record.signed_result = signed_result
                    session.commit()
                except (TicketAlreadyReleasedError, HoldTicketNotFoundError):
                    session.rollback()
                    raise
                except Exception as exc:
                    logger.warning("database_atomic_release_error: %s", exc)
                    session.rollback()
                    raise
                finally:
                    if should_close:
                        session.close()

            # Memory update with atomic check
            mem_ticket = self._by_id.get(ticket_id)
            if mem_ticket is not None:
                if (mem_ticket.state in TERMINAL_STATES and mem_ticket.state != HoldState.RELEASED.value) or (
                    mem_ticket.released_at is not None and session is None
                ):
                    raise TicketAlreadyReleasedError(
                        f"SINGLE_USE_VIOLATION: Ticket '{ticket_id}' already terminated in state {mem_ticket.state}",
                        ticket_id=ticket_id,
                    )
                mem_ticket.state = HoldState.RELEASED.value
                mem_ticket.status = HoldState.RELEASED.value
                mem_ticket.released_at = now
                if signed_result is not None:
                    mem_ticket.signed_result = signed_result
                self._by_id[ticket_id] = mem_ticket
                ticket = mem_ticket
            else:
                fetched_ticket = self.get(ticket_id)
                if fetched_ticket is None:
                    raise HoldTicketNotFoundError(f"Hold ticket '{ticket_id}' not found", ticket_id=ticket_id)
                ticket = fetched_ticket

        # Write AuditEntry
        try:
            audit_service.append_entry(
                action="HOLD_RELEASED",
                actor=actor,
                payload={"hold_id": ticket_id, "token_issued": True},
                verdict="ALLOW",
                request_id=ticket.request_id,
                data_label=ticket.data_label,
            )
        except Exception as exc:
            logger.warning("audit_entry_write_failed: %s", exc)

        # Publish stream event
        data_label_val = ticket.data_label.value if hasattr(ticket.data_label, "value") else str(ticket.data_label)
        stream_broadcaster.publish_event(
            event_type="HOLD_RELEASED",
            payload={
                "hold_id": ticket.id,
                "request_id": ticket.request_id,
                "status": "RELEASED",
                "signature": (signed_result or {}).get("signature"),
                "tx_hash": (signed_result or {}).get("tx_hash"),
            },
            data_label=data_label_val,
        )

        return ticket

    def update_status(
        self,
        ticket_id: str,
        status: str,
        signed_result: dict[str, Any] | None = None,
        db: Session | None = None,
    ) -> HoldTicket | None:
        """Backwards compatible status update forwarding to transition_state."""
        try:
            return self.transition_state(
                ticket_id=ticket_id,
                new_state=status,
                actor="system",
                signed_result=signed_result,
                db=db,
            )
        except Exception as exc:
            logger.warning("update_status_error: %s", exc)
            return None

    def list_active(
        self,
        limit: int = 50,
        state: str | None = None,
        db: Session | None = None,
    ) -> list[HoldTicket]:
        """Returns tickets ordered by recency, optionally filtered by state."""
        filter_state = state.upper() if state else None

        # 1. First attempt to load from database for persistent freshness
        session = db
        should_close = False
        if session is None:
            try:
                factory = get_session_factory()
                session = factory()
                should_close = True
            except Exception as exc:
                logger.debug("database_unavailable_using_memory: %s", exc)

        if session is not None:
            try:
                stmt = select(HoldTicketRecord).order_by(HoldTicketRecord.created_at.desc())
                if filter_state:
                    stmt = stmt.where(HoldTicketRecord.state == filter_state)
                stmt = stmt.limit(limit)

                records = session.execute(stmt).scalars().all()
                results: list[HoldTicket] = []
                for rec in records:
                    t = self._record_to_domain(rec)
                    with self._lock:
                        self._by_id[t.id] = t
                        if t.id not in self._order:
                            self._order.appendleft(t.id)
                    results.append(t)
                return results
            except Exception as exc:
                logger.warning("database_list_active_error: %s", exc)
            finally:
                if should_close:
                    session.close()

        # 2. Fallback to memory
        with self._lock:
            mem_results: list[HoldTicket] = []
            for tid in list(self._order):
                item = self._by_id.get(tid)
                if item:
                    if filter_state and item.state != filter_state:
                        continue
                    mem_results.append(item)
                if len(mem_results) >= limit:
                    break
            return mem_results

    def clear(self) -> None:
        """Clears in-memory cache (test helper)."""
        with self._lock:
            self._by_id.clear()
            self._order.clear()


hold_store = HoldStore()
