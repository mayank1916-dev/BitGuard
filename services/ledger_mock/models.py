"""Data models and database schemas for Ledger Mock service (Milestone S08 / F2)."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class IntentStatus(StrEnum):
    """Lifecycle status of a custodial withdrawal intent."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    PAID = "PAID"
    CANCELLED = "CANCELLED"


class Base(DeclarativeBase):
    """SQLAlchemy base for Ledger Mock."""

    pass


class WithdrawalIntentDB(Base):
    """Postgres table withdrawal_intents representing external custody ledger state."""

    __tablename__ = "withdrawal_intents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), default=IntentStatus.PENDING.value, index=True)
    chain: Mapped[str] = mapped_column(String(32), nullable=False)
    asset: Mapped[str] = mapped_column(String(64), nullable=False)
    amount: Mapped[str] = mapped_column(String(64), nullable=False)
    destination: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class WithdrawalIntentCreate(BaseModel):
    """Request payload to create a mock withdrawal intent."""

    id: str | None = Field(default=None, description="Optional custom ID; generated if omitted")
    chain: str
    asset: str
    amount: str = Field(description="Amount in smallest integer units (e.g. wei/satoshis)")
    destination: str
    status: IntentStatus = Field(default=IntentStatus.PENDING)


class WithdrawalIntentResponse(BaseModel):
    """Public intent response model."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    status: str
    chain: str
    asset: str
    amount: str
    destination: str
    created_at: datetime
    consumed_at: datetime | None = None
