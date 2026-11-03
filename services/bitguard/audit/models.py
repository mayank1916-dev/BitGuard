"""Pydantic models for cryptographic audit chain and object-lock verification (Milestone S21 / F18)."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from services.bitguard.models import DataLabel


class AuditEntryModel(BaseModel):
    """Immutable audit chain record."""

    model_config = ConfigDict(populate_by_name=True)

    seq: int = Field(description="Strict monotonically increasing sequence number (1-based)")
    ts: float = Field(description="Unix timestamp in fractional seconds")
    actor: str = Field(description="Actor initiating or authorizing the event")
    action: str = Field(description="Action name or event category")
    payload: dict[str, Any] = Field(default_factory=dict, description="Canonical JSON event attributes")
    prev_hash: str = Field(description="Cryptographic hash of the parent entry or 64 zeroes for genesis")
    entry_hash: str = Field(description="SHA-256 hash of prev_hash concatenated with canonical_json(entry)")
    data_label: DataLabel = DataLabel.REAL


class AnchorRecordModel(BaseModel):
    """Receipt of an external object-lock anchor."""

    id: str
    seq: int
    head_hash: str
    ts: float
    storage_uri: str
    data_label: DataLabel = DataLabel.REAL


class AuditVerifyResponse(BaseModel):
    """Cryptographic chain integrity verification outcome."""

    ok: bool = Field(description="True if all hashes, sequences, and external anchors verify")
    checked_entries: int = Field(description="Total number of consecutive valid records checked")
    first_bad_seq: int | None = Field(default=None, description="Exact sequence number where tampering or gap was detected")
    last_anchor: dict[str, Any] | None = Field(default=None, description="Most recent external object-lock anchor metadata")
    details: str | None = Field(default=None, description="Diagnostic reason if integrity verification failed")
    data_label: DataLabel = DataLabel.REAL


class ManualAnchorResponse(BaseModel):
    """Response returned upon creating a manual object-lock anchor checkpoint."""

    status: str
    anchor: dict[str, Any]
    data_label: DataLabel = DataLabel.REAL
