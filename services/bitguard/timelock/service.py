"""Time-lock domain service and customer notice webhook dispatcher (Milestone S30 / F12).

Invariants:
- Invariant #1: Key Isolation (BitGuard never holds keys; releases to signer shim).
- Invariant #2: Approval Binding & Verification.
- Invariant #3: Fail-Closed Default (unknown, locked down, or expired tickets fail closed).
- Invariant #6: Asymmetric Policy Evolution (cancellation is instant tightening; release requires delay expiration).
- Invariant #7: Immutable Audit Trail.
- Invariant #8: Explicit Data Provenance (REAL or SYNTHETIC).
- Invariant #11: Strict Wording: 'reduces and contains unauthorized transaction signing'.
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from services.bitguard.approvals.hold_store import HoldStore, hold_store
from services.bitguard.audit.service import audit_service
from services.bitguard.engine.breaker_store import BreakerStore, breaker_store
from services.bitguard.models import (
    BreakerStateEnum,
    DataLabel,
    DecisionReason,
    HoldState,
    HoldTicket,
)
from services.bitguard.policy.models import TimeLockPolicy
from services.bitguard.timelock.store import TimelockItem, TimelockStore, timelock_store

logger = logging.getLogger("bitguard.timelock.service")


class CustomerNoticeWebhook:
    """Mock webhook dispatcher notifying customers of delayed time-locked transactions."""

    def __init__(self) -> None:
        self.notices: list[dict[str, Any]] = []

    def notify(self, ticket: HoldTicket, delay_minutes: float) -> dict[str, Any]:
        """Dispatches an asynchronous customer notice payload (mock implementation)."""
        notice = {
            "id": f"notif-{uuid.uuid4().hex[:10]}",
            "ticket_id": ticket.id,
            "request_id": ticket.request_id,
            "wallet": ticket.wallet,
            "chain": ticket.chain,
            "amount_usd": ticket.amount_usd,
            "state": ticket.state,
            "delay_minutes": delay_minutes,
            "release_not_before": (
                ticket.release_not_before.isoformat() if ticket.release_not_before else None
            ),
            "dispatched_at": datetime.now(UTC).isoformat(),
        }
        self.notices.append(notice)
        logger.info(
            "customer_notice_dispatched: ticket=%s wallet=%s delay=%.1fm",
            ticket.id,
            ticket.wallet,
            delay_minutes,
        )
        return notice

    def reset(self) -> None:
        """Clears recorded notices for test isolation."""
        self.notices.clear()


customer_notice_webhook = CustomerNoticeWebhook()


class TimelockService:
    """Orchestrates time-locked withdrawal quarantine, breaker scaling, and customer notifications."""

    def __init__(
        self,
        breaker_store_inst: BreakerStore | None = None,
        hold_store_inst: HoldStore | None = None,
        timelock_store_inst: TimelockStore | None = None,
        notice_webhook: CustomerNoticeWebhook | None = None,
    ) -> None:
        self.breaker_store = breaker_store_inst or breaker_store
        self.hold_store = hold_store_inst or hold_store
        self.timelock_store = timelock_store_inst or timelock_store
        self.notice_webhook = notice_webhook or customer_notice_webhook

    def create_timelock_ticket(
        self,
        request_id: str,
        raw_tx: str,
        tx_digest: str,
        wallet: str,
        chain: str = "ethereum",
        amount_usd: float = 0.0,
        asset: str = "ETH",
        requester_id: str | None = None,
        intent_id: str | None = None,
        policy: TimeLockPolicy | None = None,
        data_label: DataLabel = DataLabel.REAL,
        now: datetime | None = None,
    ) -> HoldTicket:
        """Creates a time-locked HoldTicket in PENDING_RELEASE state with delay scaled by breaker state."""
        current_time = now or datetime.now(UTC)
        tl_policy = policy or TimeLockPolicy()

        # Check circuit breaker state and apply delay multiplier (ELEVATED x2, HOLD x4)
        b_state = self.breaker_store.get_state()
        if b_state == BreakerStateEnum.LOCKDOWN:
            raise ValueError(
                "Cannot create time-lock under circuit breaker LOCKDOWN; all releases blocked."
            )

        multiplier = tl_policy.delay_multipliers.get(b_state.value, 1.0)
        total_delay_minutes = tl_policy.timelock_minutes * multiplier
        delay_seconds = int(total_delay_minutes * 60)
        release_not_before = current_time + timedelta(seconds=delay_seconds)
        expires_at = release_not_before + timedelta(hours=24)

        ticket_id = f"ht-{request_id}"
        ticket = HoldTicket(
            id=ticket_id,
            request_id=request_id,
            tx_digest=tx_digest,
            digest=tx_digest,
            raw_tx=raw_tx,
            chain=chain,
            wallet=wallet,
            amount_usd=amount_usd,
            requester_id=requester_id,
            intent_id=intent_id,
            risk_score=60,
            reasons=[
                DecisionReason(
                    code="TIMELOCK_DELAY",
                    weight=60,
                    detail=(
                        f"Withdrawal meets time-lock threshold ({amount_usd:,.2f} {asset}); delayed by "
                        f"{total_delay_minutes:.1f}m (breaker mult x{multiplier:.1f}) until {release_not_before.isoformat()}."
                    ),
                )
            ],
            state=HoldState.PENDING_RELEASE.value,
            status=HoldState.PENDING_RELEASE.value,
            release_not_before=release_not_before,
            expires_at=expires_at,
            created_at=current_time,
            data_label=data_label,
        )

        # 1. Save in hold_store
        self.hold_store.create(ticket)

        # 2. Also register in timelock_store
        self.timelock_store.add(
            TimelockItem(
                id=f"tl-{request_id}",
                request_id=request_id,
                chain=chain,
                wallet=wallet,
                asset=asset,
                amount_usd=amount_usd,
                status="QUEUED",
                release_time=release_not_before,
                created_at=current_time,
                data_label=data_label,
            )
        )

        # 3. Invariant #7: Append to audit log
        audit_service.append_entry(
            actor=requester_id or "system",
            action="TIMELOCK_ENQUEUED",
            payload={
                "ticket_id": ticket.id,
                "request_id": request_id,
                "amount_usd": amount_usd,
                "asset": asset,
                "delay_minutes": total_delay_minutes,
                "breaker_state": b_state.value,
                "release_not_before": release_not_before.isoformat(),
            },
        )

        # 4. Invoke optional customer notice webhook
        self.notice_webhook.notify(ticket, delay_minutes=total_delay_minutes)

        return ticket


# Global singleton instance
timelock_service = TimelockService()
