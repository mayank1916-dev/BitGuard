"""SQLAlchemy database models for BitGuard persistent state."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON


class Base(DeclarativeBase):
    """Base declarative class for BitGuard database tables."""

    pass


# Use JSON which translates to JSONB on Postgres and generic JSON on SQLite
JsonType = JSON().with_variant(JSONB, "postgresql")


class DecisionRecord(Base):
    """Persisted decision outcomes issued by BitGuard policy engine."""

    __tablename__ = "decisions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    reasons: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, nullable=False, default=list)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    data_label: Mapped[str] = mapped_column(String(16), nullable=False)
    evaluation_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class HoldTicketRecord(Base):
    """Durable quarantine record for transactions placed in HOLD."""

    __tablename__ = "hold_tickets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    tx_digest: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    reasons: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class ApprovalRecord(Base):
    """Hardware-bound approval signatures for hold tickets."""

    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    hold_ticket_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    approver_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tx_digest: Mapped[str] = mapped_column(String(128), nullable=False)
    webauthn_signature: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class PolicyVersionRecord(Base):
    """Cryptographically signed, versioned policy manifests."""

    __tablename__ = "policy_versions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    author: Mapped[str] = mapped_column(String(128), nullable=False)
    rules: Mapped[dict[str, Any]] = mapped_column(JsonType, nullable=False, default=dict)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class AuditEntryRecord(Base):
    """Cryptographically chained tamper-evident audit ledger entries."""

    __tablename__ = "audit_entries"

    index: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[float] = mapped_column(Float, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    data_label: Mapped[str] = mapped_column(String(16), nullable=False)


class WatchedAddressRecord(Base):
    """Hot wallet address registrations for bytecode monitoring."""

    __tablename__ = "watched_addresses"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    address: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    chain: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    expected_code_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    allowed_delegates: Mapped[list[str]] = mapped_column(JsonType, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class BreakerStateRecord(Base):
    """Circuit breaker operational state."""

    __tablename__ = "breaker_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    data_label: Mapped[str] = mapped_column(String(16), default="REAL", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
