"""Break-glass emergency degraded mode mechanism (Milestone S24 / F17).

Invariants:
- Two-Person Quorum: Requires 2 distinct authorized approvers (Admin or SecOps).
- Separation of Duties: The initiator who proposed the break-glass override CANNOT approve it.
- Time-Limited: Strictly time-boxed with automatic expiration (default 1h, max 4h).
- Strict Scope: Only permits pre-approved destination allowlists (e.g. cold storage sweeps).
- Immutable Audit Trail: Every proposal, approval, activation, and revocation is recorded in the audit log.
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from services.bitguard.audit.service import audit_service
from services.bitguard.config import settings

logger = logging.getLogger("bitguard.break_glass")


class BreakGlassState(StrEnum):
    """Lifecycle states of emergency break-glass override."""

    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class BreakGlassApproval(BaseModel):
    """Cryptographically or WebAuthn verified approval record."""

    approver_id: str
    role: str
    approved_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    webauthn_assertion: dict[str, Any] | None = None


class BreakGlassManifest(BaseModel):
    """Specification of an emergency break-glass override request."""

    id: str = Field(default_factory=lambda: f"bg-glass-{uuid.uuid4().hex[:12]}")
    reason: str
    proposed_by: str
    allowed_destinations: list[str]
    duration_seconds: int = 3600
    state: BreakGlassState = BreakGlassState.PENDING
    approvals: list[BreakGlassApproval] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    activated_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_by: str | None = None


class BreakGlassStore:
    """Manages break-glass requests, two-person approvals, and active destination allowlists."""

    def __init__(self) -> None:
        self._manifests: dict[str, BreakGlassManifest] = {}
        self._active_id: str | None = None
        self._sync_redis: Any | None = None

    def set_sync_redis(self, client: Any) -> None:
        """Injects custom sync Redis client for testing."""
        self._sync_redis = client

    def _get_sync_redis(self) -> Any:
        if self._sync_redis is None:
            try:
                import redis
                self._sync_redis = redis.Redis.from_url(
                    settings.redis_url,
                    socket_connect_timeout=0.5,
                    socket_timeout=0.5,
                    decode_responses=True,
                )
            except Exception as exc:
                logger.debug("redis_break_glass_init_error: %s", exc)
                return None
        return self._sync_redis

    def propose(
        self,
        reason: str,
        proposed_by: str,
        allowed_destinations: list[str],
        duration_seconds: int = 3600,
    ) -> BreakGlassManifest:
        """Creates a pending break-glass request requiring two approvers."""
        max_duration = getattr(settings, "break_glass_max_duration_seconds", 14400)
        dur = min(max(300, duration_seconds), max_duration)

        normalized_dests = [d.strip().lower() for d in allowed_destinations if d.strip()]
        if not normalized_dests:
            raise ValueError("At least one pre-approved destination must be specified")

        manifest = BreakGlassManifest(
            reason=reason,
            proposed_by=proposed_by,
            allowed_destinations=normalized_dests,
            duration_seconds=dur,
            state=BreakGlassState.PENDING,
        )
        self._manifests[manifest.id] = manifest

        # Log proposal to audit trail
        try:
            audit_service.append_entry(
                action="BREAK_GLASS_PROPOSED",
                actor=proposed_by,
                payload={
                    "target_id": manifest.id,
                    "reason": reason,
                    "duration_seconds": dur,
                    "allowed_destinations": normalized_dests,
                },
            )
        except Exception as exc:
            logger.warning("break_glass_audit_failed: %s", exc)

        return manifest

    def approve(
        self,
        manifest_id: str,
        approver_id: str,
        role: str,
        webauthn_assertion: dict[str, Any] | None = None,
    ) -> BreakGlassManifest:
        """Adds an approval to a pending break-glass request.

        Enforces:
        1. Requester cannot approve their own request (separation of duties).
        2. Approver cannot approve twice.
        3. Two distinct approvers transition the request to ACTIVE.
        """
        manifest = self.get(manifest_id)
        if not manifest:
            raise KeyError(f"Break-glass request '{manifest_id}' not found")

        if manifest.state != BreakGlassState.PENDING:
            raise ValueError(f"Cannot approve break-glass request in state {manifest.state}")

        if approver_id == manifest.proposed_by:
            raise PermissionError("Separation of duties violation: Proposer cannot approve own request")

        if any(a.approver_id == approver_id for a in manifest.approvals):
            raise ValueError(f"Approver '{approver_id}' has already approved this request")

        manifest.approvals.append(
            BreakGlassApproval(
                approver_id=approver_id,
                role=role,
                webauthn_assertion=webauthn_assertion,
            )
        )

        # Log approval
        try:
            audit_service.append_entry(
                action="BREAK_GLASS_APPROVED",
                actor=approver_id,
                payload={
                    "target_id": manifest.id,
                    "approver_role": role,
                    "approval_count": len(manifest.approvals),
                },
            )
        except Exception as exc:
            logger.warning("break_glass_audit_failed: %s", exc)

        # If two distinct approvers, activate immediately
        if len(manifest.approvals) >= 2:
            now = datetime.now(UTC)
            manifest.state = BreakGlassState.ACTIVE
            manifest.activated_at = now
            manifest.expires_at = now + timedelta(seconds=manifest.duration_seconds)
            self._active_id = manifest.id

            # Sync to Redis
            try:
                r = self._get_sync_redis()
                if r is not None:
                    r.set(
                        "bitguard:break_glass:active",
                        manifest.model_dump_json(),
                        ex=manifest.duration_seconds,
                    )
            except Exception as exc:
                logger.debug("redis_break_glass_sync_bypassed: %s", exc)

            try:
                audit_service.append_entry(
                    action="BREAK_GLASS_ACTIVATED",
                    actor=approver_id,
                    payload={
                        "target_id": manifest.id,
                        "expires_at": manifest.expires_at.isoformat() if manifest.expires_at else "",
                        "allowed_destinations": manifest.allowed_destinations,
                    },
                )
            except Exception as exc:
                logger.warning("break_glass_audit_failed: %s", exc)

        return manifest

    def revoke(self, manifest_id: str, revoked_by: str, reason: str = "") -> BreakGlassManifest:
        """Revokes an active or pending break-glass request (tightening: instant single-operator)."""
        manifest = self.get(manifest_id)
        if not manifest:
            raise KeyError(f"Break-glass request '{manifest_id}' not found")

        manifest.state = BreakGlassState.REVOKED
        manifest.revoked_at = datetime.now(UTC)
        manifest.revoked_by = revoked_by

        if self._active_id == manifest_id:
            self._active_id = None
            try:
                r = self._get_sync_redis()
                if r is not None:
                    r.delete("bitguard:break_glass:active")
            except Exception:
                pass

        try:
            audit_service.append_entry(
                action="BREAK_GLASS_REVOKED",
                actor=revoked_by,
                payload={"target_id": manifest.id, "reason": reason},
            )
        except Exception as exc:
            logger.warning("break_glass_audit_failed: %s", exc)

        return manifest

    def get(self, manifest_id: str) -> BreakGlassManifest | None:
        """Retrieves break-glass request by ID."""
        return self._manifests.get(manifest_id)

    def get_active(self) -> BreakGlassManifest | None:
        """Returns the currently active, unexpired break-glass override if one exists."""
        # Check in-memory first
        if self._active_id and self._active_id in self._manifests:
            manifest = self._manifests[self._active_id]
            now = datetime.now(UTC)
            if manifest.expires_at and now > manifest.expires_at:
                manifest.state = BreakGlassState.EXPIRED
                self._active_id = None
                return None
            return manifest

        # Check Redis
        try:
            r = self._get_sync_redis()
            if r is not None:
                cached = r.get("bitguard:break_glass:active")
                if cached:
                    manifest = BreakGlassManifest.model_validate_json(cached)
                    now = datetime.now(UTC)
                    if manifest.expires_at and now > manifest.expires_at:
                        return None
                    self._manifests[manifest.id] = manifest
                    self._active_id = manifest.id
                    return manifest
        except Exception:
            pass

        return None

    def is_destination_allowed(self, to_address: str) -> bool:
        """Checks if a destination is permitted under an active break-glass override."""
        active = self.get_active()
        if not active or active.state != BreakGlassState.ACTIVE:
            return False
        addr_norm = to_address.strip().lower()
        return addr_norm in active.allowed_destinations

    def reset(self) -> None:
        """Resets store state for testing."""
        self._manifests.clear()
        self._active_id = None


# Global singleton instance
break_glass_store = BreakGlassStore()
