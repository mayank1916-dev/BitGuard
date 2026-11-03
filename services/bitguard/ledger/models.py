"""Data models for custody ledger withdrawal intents (Milestone S08 / F2)."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class IntentStatus(StrEnum):
    """Lifecycle status of an exchange withdrawal intent."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    PAID = "PAID"
    CANCELLED = "CANCELLED"


class WithdrawalIntent(BaseModel):
    """Canonical representation of an authorized exchange withdrawal intent."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str
    status: str = Field(default=IntentStatus.PENDING.value)
    chain: str
    asset: str
    amount: str = Field(description="Exact amount in smallest integer units (e.g. wei/satoshis)")
    destination: str = Field(description="Destination address / recipient")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    consumed_at: datetime | None = None
