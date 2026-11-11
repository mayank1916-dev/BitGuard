"""Data models and schemas for BitGuard Compliance and Audit Reports (Milestone S35 / F20).

Invariants:
- Invariant #7: Immutable Audit Trail (every report is stamped with hash-chain verification state).
- Invariant #8: Explicit Data Provenance (every figure and export is stamped with REAL, SYNTHETIC, or REPORTED).
- Invariant #11: Strict Wording & Claims (reduces and contains, target p99 under 15 ms, measured, pilot after audit).
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from services.bitguard.models import DataLabel


class ReportFormat(StrEnum):
    """Supported export media formats."""

    PDF = "pdf"
    CSV = "csv"
    JSON = "json"


class AuditChainVerificationStamp(BaseModel):
    """Cryptographic audit chain verification result stamped onto reports (Invariant #7)."""

    audit_chain_valid: bool
    checked_entries: int
    head_hash: str
    first_bad_seq: int | None = None
    last_anchor_uri: str | None = None
    verified_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    details: str = ""
    data_label: DataLabel = DataLabel.REAL


class IncidentPostMortemData(BaseModel):
    """Structured data payload for Incident Post-Mortem Report."""

    incident_id: str
    trigger: str
    severity: str
    status: str
    detected_at: datetime
    contained_at: datetime | None = None
    time_to_contain_ms: float | None = None
    resolved_at: datetime | None = None
    policy_version_at_time: str
    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    decisions_made: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    audit_verification: AuditChainVerificationStamp
    data_label: DataLabel = DataLabel.REAL


class MonthlyControlReportData(BaseModel):
    """Structured data payload for Monthly Control & Decision Report."""

    period: str  # YYYY-MM
    start_date: datetime
    end_date: datetime
    total_decisions: int
    decision_counts_by_verdict: dict[str, int]
    hold_counts: dict[str, int]
    false_positive_count: int
    false_positive_rate_pct: float
    time_to_contain_stats: dict[str, Any]
    approval_statistics: dict[str, Any]
    breaker_history: list[dict[str, Any]] = Field(default_factory=list)
    uptime_and_heartbeat: dict[str, Any] = Field(default_factory=dict)
    audit_verification: AuditChainVerificationStamp
    data_label: DataLabel = DataLabel.REAL


class PolicyChangeHistoryData(BaseModel):
    """Structured data payload for Policy Change and Approval History Report."""

    total_versions: int
    versions: list[dict[str, Any]] = Field(default_factory=list)
    audit_verification: AuditChainVerificationStamp
    data_label: DataLabel = DataLabel.REAL
