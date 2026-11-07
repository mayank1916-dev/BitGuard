"""SQLAlchemy database models for BitGuard persistent state."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    event,
    inspect,
    text,
)
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
    verdict: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    would_have_verdict: Mapped[str | None] = mapped_column(String(16), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    reasons: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, nullable=False, default=list)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    data_label: Mapped[str] = mapped_column(String(16), nullable=False)
    wallet_group: Mapped[str] = mapped_column(String(64), default="default", nullable=False)
    wallet: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    chain: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    evaluation_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    timings: Mapped[dict[str, Any]] = mapped_column(JsonType, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        index=True,
        nullable=False,
    )


class HoldTicketRecord(Base):
    """Durable quarantine record for transactions placed in HOLD (Milestone S14)."""

    __tablename__ = "hold_tickets"
    __table_args__ = (
        CheckConstraint(
            "state IN ('PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'CANCELLED', 'RELEASED')",
            name="ck_hold_tickets_valid_state",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    tx_digest: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    digest: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    decoded_tx: Mapped[dict[str, Any] | None] = mapped_column(JsonType, nullable=True)
    raw_tx: Mapped[str | None] = mapped_column(Text, nullable=True)
    chain: Mapped[str | None] = mapped_column(String(32), nullable=True, default="ethereum")
    wallet: Mapped[str | None] = mapped_column(String(128), nullable=True)
    amount_usd: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.0)
    requester_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    requester_identity: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reservation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    reasons: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, nullable=False, default=list)
    state: Mapped[str] = mapped_column(String(32), default="PENDING", server_default="PENDING", nullable=False, active_history=True)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", server_default="PENDING", nullable=False, active_history=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    release_not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    signed_result: Mapped[dict[str, Any] | None] = mapped_column(JsonType, nullable=True)
    data_label: Mapped[str | None] = mapped_column(String(16), nullable=True, default="REAL")


@event.listens_for(HoldTicketRecord, "before_update")
def validate_hold_ticket_record_transition(mapper: Any, connection: Any, target: HoldTicketRecord) -> None:
    from services.bitguard.approvals.state_machine import validate_transition

    insp = inspect(target)
    state_history = insp.attrs.state.history
    if state_history.has_changes():
        old_state = state_history.deleted[0] if state_history.deleted else target.state
        validate_transition(old_state, target.state, ticket_id=target.id)
        target.status = target.state
    elif insp.attrs.status.history.has_changes():
        old_status = insp.attrs.status.history.deleted[0] if insp.attrs.status.history.deleted else target.status
        validate_transition(old_status, target.status, ticket_id=target.id)
        target.state = target.status



@event.listens_for(HoldTicketRecord.__table__, "after_create")
def create_hold_ticket_triggers(target: Any, connection: Any, **kw: Any) -> None:
    dialect = connection.dialect.name
    if dialect == "sqlite":
        connection.execute(
            text("""
            CREATE TRIGGER IF NOT EXISTS trg_hold_tickets_terminal_state
            BEFORE UPDATE OF state, status ON hold_tickets
            FOR EACH ROW
            WHEN OLD.state IN ('DENIED', 'EXPIRED', 'CANCELLED', 'RELEASED') AND OLD.state != NEW.state
            BEGIN
                SELECT RAISE(ABORT, 'Cannot transition from terminal state');
            END;
            """)
        )



class ApprovalRecord(Base):
    """Hardware-bound approval signatures for hold tickets."""

    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    hold_ticket_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    approver_id: Mapped[str] = mapped_column(String(128), nullable=False)
    approver_role: Mapped[str | None] = mapped_column(String(64), nullable=True, default="Approver")
    tx_digest: Mapped[str] = mapped_column(String(128), nullable=False)
    webauthn_signature: Mapped[str] = mapped_column(Text, nullable=False)
    assertion_data: Mapped[dict[str, Any] | None] = mapped_column(JsonType, nullable=True, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class PolicyVersionRecord(Base):
    """Cryptographically signed, versioned policy manifests (Milestone S20 / Section D)."""

    __tablename__ = "policy_versions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    author: Mapped[str] = mapped_column(String(128), nullable=False)
    content: Mapped[dict[str, Any]] = mapped_column(JsonType, nullable=False, default=dict)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="DRAFT")
    change_type: Mapped[str] = mapped_column(String(32), nullable=False, default="TIGHTEN")
    ed25519_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    signatures: Mapped[list[Any]] = mapped_column(JsonType, nullable=False, default=list)
    approvals: Mapped[list[Any]] = mapped_column(JsonType, nullable=False, default=list)
    backtest_report_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cool_down_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rollback_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    rules: Mapped[dict[str, Any]] = mapped_column(JsonType, nullable=True, default=dict)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    def __init__(self, **kwargs: Any) -> None:
        if "content" in kwargs and "rules" not in kwargs:
            kwargs["rules"] = kwargs["content"]
        elif "rules" in kwargs and "content" not in kwargs:
            kwargs["content"] = kwargs["rules"]
        if "ed25519_signature" in kwargs and "signature" not in kwargs:
            kwargs["signature"] = kwargs["ed25519_signature"]
        elif "signature" in kwargs and "ed25519_signature" not in kwargs:
            kwargs["ed25519_signature"] = kwargs["signature"]
        if "status" in kwargs and "is_active" not in kwargs:
            kwargs["is_active"] = kwargs["status"] == "ACTIVE"
        elif "is_active" in kwargs and "status" not in kwargs:
            kwargs["status"] = "ACTIVE" if kwargs["is_active"] else "DRAFT"
        super().__init__(**kwargs)


class AuditEntryRecord(Base):
    """Cryptographically chained tamper-evident audit ledger entries (Milestone S21 / F18)."""

    __tablename__ = "audit_entries"

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[float] = mapped_column(Float, nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JsonType, nullable=False, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    data_label: Mapped[str] = mapped_column(String(16), nullable=False, default="REAL")

    def __init__(self, **kwargs: Any) -> None:
        if "seq" not in kwargs and "index" in kwargs:
            kwargs["seq"] = kwargs.pop("index")
        if "ts" not in kwargs and "timestamp" in kwargs:
            kwargs["ts"] = kwargs.pop("timestamp")
        if "action" not in kwargs and "event_type" in kwargs:
            kwargs["action"] = kwargs.pop("event_type")
        if "payload" not in kwargs:
            payload = {}
            if "request_id" in kwargs:
                payload["request_id"] = kwargs.pop("request_id")
            if "verdict" in kwargs:
                payload["verdict"] = kwargs.pop("verdict")
            kwargs["payload"] = payload
        else:
            kwargs.pop("request_id", None)
            kwargs.pop("verdict", None)
        super().__init__(**kwargs)

    @property
    def index(self) -> int:
        return self.seq

    @property
    def timestamp(self) -> float:
        return self.ts

    @property
    def event_type(self) -> str:
        return self.action

    @property
    def request_id(self) -> str:
        return str(self.payload.get("request_id", ""))

    @property
    def verdict(self) -> str:
        return str(self.payload.get("verdict", ""))


class AuditAnchorRecord(Base):
    """External object-lock anchor receipts for audit trail verification (Milestone S21 / F18)."""

    __tablename__ = "audit_anchors"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    head_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    ts: Mapped[float] = mapped_column(Float, nullable=False)
    storage_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    data_label: Mapped[str] = mapped_column(String(16), nullable=False, default="REAL")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class WatchedAddressRecord(Base):
    """Hot wallet address registrations for bytecode monitoring."""

    __tablename__ = "watched_addresses"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    address: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    chain: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    expected_code_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    allowed_delegates: Mapped[list[str]] = mapped_column(JsonType, nullable=False, default=list)
    last_known_nonce: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    signed_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_scanned_block: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", nullable=False)
    data_label: Mapped[str] = mapped_column(String(16), default="REAL", nullable=False)
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
    updated_by: Mapped[str] = mapped_column(String(64), default="system", nullable=False)
    token_epoch: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    data_label: Mapped[str] = mapped_column(String(16), default="REAL", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class DeescalationRequestRecord(Base):
    """Circuit breaker de-escalation request requiring 2-approver WebAuthn quorum."""

    __tablename__ = "breaker_deescalations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    current_state: Mapped[str] = mapped_column(String(32), nullable=False)
    target_state: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(64), nullable=False)
    challenge: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False)
    approvals_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class WalletGroupRecord(Base):
    """Hot wallet group mode and configuration state."""

    __tablename__ = "wallet_groups"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), default="SIMULATION", nullable=False)
    wallets: Mapped[list[str]] = mapped_column(JsonType, nullable=False, default=list)
    shadow_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enforce_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    unexplained_decode_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class DailyGroupMetricsRecord(Base):
    """Aggregated daily metrics per wallet group for promotion tracking."""

    __tablename__ = "daily_group_metrics"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)  # wallet_group:date
    wallet_group: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    date: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    would_have_blocked_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    would_have_blocked_value: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    allowed_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class WebAuthnCredentialRecord(Base):
    """Registered WebAuthn hardware credentials (Milestone S15 / F9)."""

    __tablename__ = "webauthn_credentials"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    credential_id: Mapped[str] = mapped_column(String(256), unique=True, index=True, nullable=False)
    public_key_cose: Mapped[str] = mapped_column(Text, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    transports: Mapped[list[str]] = mapped_column(JsonType, nullable=False, default=list)
    aaguid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    backup_eligible: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    backed_up: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class IncidentRecord(Base):
    """Incident response records and automated runbook tracking (Milestone S19 / F14)."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    trigger: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="CRITICAL", nullable=False)
    runbook_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    time_to_contain_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    timeline: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, nullable=False, default=list)
    checklist: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, nullable=False, default=list)
    approvals: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, nullable=False, default=list)
    escalation_level: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    data_label: Mapped[str] = mapped_column(String(16), default="REAL", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class BacktestReportRecord(Base):
    """Historical and synthetic backtest evaluation reports (Milestone S22 / F8)."""

    __tablename__ = "backtest_reports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    draft_policy_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    draft_policy_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    baseline_policy_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    baseline_policy_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    total_events: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    real_events_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    synthetic_events_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    allowed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    held_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    denied_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    holds_per_day: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    estimated_false_positives: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    synthetic_loss_prevented_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    synthetic_loss_allowed_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    policy_diff: Mapped[dict[str, Any]] = mapped_column(JsonType, nullable=False, default=dict)
    summary: Mapped[dict[str, Any]] = mapped_column(JsonType, nullable=False, default=dict)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
