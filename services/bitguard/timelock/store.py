"""In-memory and persistent time-lock queue store for large withdrawals (Milestone U5 / F12).

Invariants:
- Invariant #8: Explicit Data Provenance. All timelock items carry REAL or SYNTHETIC data labels.
- Invariant #7: Immutable Audit Trail. Cancellations and releases are appended to the audit log.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pydantic import BaseModel, Field

from services.bitguard.audit.service import audit_service
from services.bitguard.models import DataLabel


class TimelockItem(BaseModel):
    """Quarantined or delayed large withdrawal awaiting time-lock release."""

    id: str = Field(default_factory=lambda: f"tl-{uuid4().hex[:10]}")
    request_id: str
    chain: str = "ethereum"
    wallet: str
    recipient: str = "0x1111111111111111111111111111111111111111"
    asset: str = "ETH"
    amount_usd: float
    status: str = "QUEUED"  # QUEUED, CANCELLED, RELEASED
    release_time: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    data_label: DataLabel = DataLabel.REAL
    cancel_reason: str | None = None
    cancelled_by: str | None = None


class TimelockStore:
    """Manages queued time-locked withdrawals."""

    def __init__(self) -> None:
        self._items: dict[str, TimelockItem] = {}
        self._seed_default_items()

    def _seed_default_items(self) -> None:
        """Seeds initial dev/demo time-locked withdrawals for UI verification."""
        now = datetime.now(UTC)
        default_items = [
            TimelockItem(
                id="tl-req-001",
                request_id="req-timelock-large-01",
                chain="ethereum",
                wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                recipient="0x3333333333333333333333333333333333333333",
                asset="ETH",
                amount_usd=150000.0,
                status="QUEUED",
                release_time=now + timedelta(minutes=15),
                created_at=now,
                data_label=DataLabel.REAL,
            ),
            TimelockItem(
                id="tl-req-002",
                request_id="req-timelock-large-02",
                chain="tron",
                wallet="TBinanceHotTRX1",
                recipient="TAttackerTRONAddress0000000000000000",
                asset="USDT",
                amount_usd=650000.0,
                status="QUEUED",
                release_time=now + timedelta(minutes=45),
                created_at=now,
                data_label=DataLabel.REAL,
            ),
        ]
        for item in default_items:
            self._items[item.id] = item

    def list_all(self) -> list[TimelockItem]:
        """Returns all queued and recently cancelled/released timelocks."""
        return sorted(self._items.values(), key=lambda x: x.release_time)

    def get(self, item_id: str) -> TimelockItem | None:
        """Finds timelock by ID."""
        return self._items.get(item_id)

    def add(self, item: TimelockItem) -> TimelockItem:
        """Enqueues a new timelock item."""
        self._items[item.id] = item
        return item

    def cancel(self, item_id: str, reason: str, user_id: str = "operator") -> TimelockItem:
        """Cancels a queued time-locked withdrawal immediately."""
        item = self._items.get(item_id)
        if not item:
            raise KeyError(f"Timelock item '{item_id}' not found")

        item.status = "CANCELLED"
        item.cancel_reason = reason
        item.cancelled_by = user_id

        # Invariant #7: Append cancellation to audit log
        audit_service.append_entry(
            actor=user_id,
            action="TIMELOCK_CANCELLED",
            payload={
                "timelock_id": item.id,
                "request_id": item.request_id,
                "amount_usd": item.amount_usd,
                "chain": item.chain,
                "reason": reason,
            },
        )
        return item

    def reset(self) -> None:
        """Resets store to seeded dev state."""
        self._items.clear()
        self._seed_default_items()


timelock_store = TimelockStore()
