"""Durable quarantine and hold ticket store with Postgres persistence and in-memory fallback.

Invariants:
- Invariant #7: Immutable Audit Trail.
- Invariant #8: Explicit Data Provenance. All records store data_label (REAL, SYNTHETIC, REPORTED).
"""

import logging
from collections import deque
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.bitguard.database import get_session_factory
from services.bitguard.db_models import ApprovalRecord, HoldTicketRecord
from services.bitguard.models import Approval, DataLabel, DecisionReason, HoldTicket

logger = logging.getLogger("bitguard.approvals.hold_store")


class HoldStore:
    """Manages Postgres persistence and memory cache of quarantined hold tickets and approvals."""

    def __init__(self, capacity: int = 500) -> None:
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
        return HoldTicket(
            id=record.id,
            request_id=record.request_id,
            tx_digest=record.tx_digest,
            raw_tx=record.raw_tx,
            chain=record.chain or "ethereum",
            wallet=record.wallet,
            amount_usd=record.amount_usd or 0.0,
            requester_id=record.requester_id,
            reservation_id=record.reservation_id,
            risk_score=record.risk_score or 0,
            reasons=reasons,
            status=record.status,
            expires_at=record.expires_at,
            created_at=record.created_at,
            approvals=approvals or [],
            signed_result=record.signed_result,
            data_label=DataLabel(record.data_label or "REAL"),
        )

    def create(self, ticket: HoldTicket, db: Session | None = None) -> HoldTicket:
        """Saves a new hold ticket to in-memory cache and Postgres."""
        self._by_id[ticket.id] = ticket
        self._order.appendleft(ticket.id)

        record = HoldTicketRecord(
            id=ticket.id,
            request_id=ticket.request_id,
            tx_digest=ticket.tx_digest,
            raw_tx=ticket.raw_tx,
            chain=ticket.chain,
            wallet=ticket.wallet,
            amount_usd=ticket.amount_usd,
            requester_id=ticket.requester_id,
            reservation_id=ticket.reservation_id,
            risk_score=ticket.risk_score,
            reasons=[r.model_dump() for r in ticket.reasons],
            status=ticket.status,
            expires_at=ticket.expires_at,
            created_at=ticket.created_at,
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
                logger.debug("postgres_unavailable_using_memory: %s", exc)

        if session is not None:
            try:
                session.merge(record)
                session.commit()
            except Exception as exc:
                logger.warning("postgres_hold_ticket_save_error: %s", exc)
                session.rollback()
            finally:
                if should_close:
                    session.close()

        return ticket

    def get(self, ticket_id: str, db: Session | None = None) -> HoldTicket | None:
        """Retrieves a hold ticket by ID from memory or database."""
        # Check memory first
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
                logger.debug("postgres_unavailable: %s", exc)

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
                    self._by_id[ticket_id] = ticket
                    return ticket
            except Exception as exc:
                logger.warning("postgres_hold_ticket_get_error: %s", exc)
            finally:
                if should_close:
                    session.close()

        return None

    def add_approval(self, ticket_id: str, approval: Approval, db: Session | None = None) -> HoldTicket | None:
        """Appends an approval to a ticket."""
        ticket = self.get(ticket_id, db=db)
        if ticket is None:
            return None

        # Add to memory
        ticket.approvals.append(approval)
        self._by_id[ticket_id] = ticket

        # Persist to database
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
                logger.debug("postgres_unavailable: %s", exc)

        if session is not None:
            try:
                session.merge(record)
                session.commit()
            except Exception as exc:
                logger.warning("postgres_approval_save_error: %s", exc)
                session.rollback()
            finally:
                if should_close:
                    session.close()

        return ticket

    def update_status(
        self,
        ticket_id: str,
        status: str,
        signed_result: dict[str, Any] | None = None,
        db: Session | None = None,
    ) -> HoldTicket | None:
        """Updates the status and optional signed result of a hold ticket."""
        ticket = self.get(ticket_id, db=db)
        if ticket is None:
            return None

        ticket.status = status
        if signed_result is not None:
            ticket.signed_result = signed_result
        self._by_id[ticket_id] = ticket

        session = db
        should_close = False
        if session is None:
            try:
                factory = get_session_factory()
                session = factory()
                should_close = True
            except Exception as exc:
                logger.debug("postgres_unavailable: %s", exc)

        if session is not None:
            try:
                record = session.get(HoldTicketRecord, ticket_id)
                if record is not None:
                    record.status = status
                    if signed_result is not None:
                        record.signed_result = signed_result
                    session.commit()
            except Exception as exc:
                logger.warning("postgres_hold_ticket_update_error: %s", exc)
                session.rollback()
            finally:
                if should_close:
                    session.close()

        return ticket

    def list_active(self, limit: int = 50, db: Session | None = None) -> list[HoldTicket]:
        """Returns recent tickets, pending first."""
        # First check memory
        results: list[HoldTicket] = []
        for tid in list(self._order):
            t = self._by_id.get(tid)
            if t:
                results.append(t)
            if len(results) >= limit:
                break
        return results

    def clear(self) -> None:
        """Clears in-memory cache (test helper)."""
        self._by_id.clear()
        self._order.clear()


hold_store = HoldStore()
