"""Distributed circuit breaker store with Redis caching and PostgreSQL persistence (Milestone S18 / F9, F14).

Invariants:
- Invariant #3: Fail-Closed Default (outage preserves the highest/strictest state seen).
- Invariant #6: Asymmetric Policy Evolution (tightening/lockdown = one person, instant; loosening/unlock = 2-approver WebAuthn quorum).
- Invariant #7: Immutable Audit Trail (all escalations and de-escalations appended to hash-chained audit ledger).
- Invariant #8: Explicit Data Provenance (data_label REAL).
"""

import hashlib
import json
import logging
import threading
import time
import uuid
from datetime import UTC, datetime

import redis
from sqlalchemy.orm import Session, sessionmaker

from services.bitguard.approvals.models import WebAuthnAssertion
from services.bitguard.approvals.webauthn import webauthn_verifier
from services.bitguard.audit_service import audit_service
from services.bitguard.breaker.base import BreakerStore
from services.bitguard.breaker.epoch_store import token_epoch_store
from services.bitguard.breaker.key_hook import key_policy_hook
from services.bitguard.breaker.models import (
    BREAKER_STATE_RANKS,
    BreakerStateEnum,
    BreakerStatusResponse,
    DeescalateApprovalResult,
    DeescalationApprovalModel,
    DeescalationRequestModel,
)
from services.bitguard.config import settings
from services.bitguard.database import get_session_factory
from services.bitguard.db_models import (
    BreakerStateRecord,
    DeescalationRequestRecord,
)
from services.bitguard.models import BreakerState, DataLabel
from services.bitguard.stream.broadcaster import stream_broadcaster

logger = logging.getLogger("bitguard.breaker.store")


class DistributedBreakerStore(BreakerStore):
    """Distributed, resilient Circuit Breaker store coordinating multi-instance operational states."""

    def __init__(
        self,
        redis_client: redis.Redis | None = None,
        session_factory: sessionmaker[Session] | None = None,
        redis_key: str = "bitguard:breaker:state",
    ) -> None:
        self._redis_key = redis_key
        self._lock = threading.Lock()
        self._session_factory = session_factory
        self._custom_redis = redis_client
        self._redis_instance: redis.Redis | None = redis_client

        # Local in-memory fail-safe cache
        self._cached_state: BreakerStateEnum = BreakerStateEnum.NORMAL
        self._cached_reason: str = "Nominal operations"
        self._cached_updated_at: datetime = datetime.now(UTC)
        self._cached_updated_by: str = "system"
        self._active_deescalation_id: str | None = None

        # In-memory store for de-escalation requests (mirrored in DB)
        self._requests: dict[str, DeescalationRequestModel] = {}

    def _get_redis(self) -> redis.Redis:
        if self._redis_instance is None:
            self._redis_instance = redis.Redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=0.2,
                socket_timeout=0.2,
            )
        return self._redis_instance

    def _get_session(self) -> Session:
        factory = self._session_factory or get_session_factory()
        return factory()

    def set_redis_client(self, client: redis.Redis | None) -> None:
        """Injects custom Redis client (test utility)."""
        with self._lock:
            self._redis_instance = client
            self._custom_redis = client

    def set_session_factory(self, factory: sessionmaker[Session] | None) -> None:
        """Injects custom session factory (test utility)."""
        with self._lock:
            self._session_factory = factory

    def _append_audit_entry(
        self,
        event_type: str,
        request_id: str,
        verdict: str,
        extra_detail: str = "",
    ) -> None:
        """Appends an immutable audit entry via canonical audit_service."""
        try:
            audit_service.append_entry(
                action=event_type,
                actor=self._cached_updated_by or "system",
                payload={"request_id": request_id, "verdict": verdict, "detail": extra_detail},
                data_label=DataLabel.REAL,
            )
        except Exception as exc:
            logger.warning("breaker_audit_log_append_failed: %s", exc)

    def get_state(self) -> BreakerStateEnum:
        """Returns the active circuit breaker state: NORMAL, ELEVATED, HOLD, or LOCKDOWN.

        In the event of a Redis or database outage, guarantees fail-closed semantics:
        the state returned is at least as strict as the strictest known state.
        """
        with self._lock:
            retrieved_state: BreakerStateEnum | None = None

            # 1. Try Redis cache
            try:
                r = self._get_redis()
                cached = r.get(self._redis_key)
                if cached:
                    data = json.loads(cached)
                    state_val = data.get("state")
                    if state_val and state_val in BreakerStateEnum.__members__:
                        retrieved_state = BreakerStateEnum(state_val)
                        self._cached_reason = data.get("reason", self._cached_reason)
                        self._cached_updated_by = data.get("updated_by", self._cached_updated_by)
            except Exception as exc:
                logger.warning("breaker_redis_read_outage: %s", exc)

            # 2. Try Postgres DB if Redis didn't yield a state
            if retrieved_state is None:
                try:
                    with self._get_session() as session:
                        rec = session.query(BreakerStateRecord).filter_by(id=1).first()
                        if rec and rec.state in BreakerStateEnum.__members__:
                            retrieved_state = BreakerStateEnum(rec.state)
                            self._cached_reason = rec.reason or self._cached_reason
                            self._cached_updated_by = rec.updated_by or self._cached_updated_by
                except Exception as exc:
                    logger.warning("breaker_db_read_outage: %s", exc)

            # 3. Fail-Closed Reconciliation:
            # Never downgrade below our local cached state during store outages
            if retrieved_state is not None:
                # If cached state has higher rank, preserve strictest (fail closed)
                if BREAKER_STATE_RANKS[self._cached_state] > BREAKER_STATE_RANKS[retrieved_state]:
                    return self._cached_state
                self._cached_state = retrieved_state
                return self._cached_state

            # Fall back to cached local state
            return self._cached_state

    def get_status(self) -> BreakerStatusResponse:
        """Returns detailed operational status model for GET /v1/breaker."""
        current_state = self.get_state()
        epoch = token_epoch_store.get_current_epoch()
        return BreakerStatusResponse(
            state=current_state,
            reason=self._cached_reason,
            updated_at=self._cached_updated_at,
            updated_by=self._cached_updated_by,
            token_epoch=epoch,
            active_deescalation_request_id=self._active_deescalation_id,
            data_label=DataLabel.REAL,
        )

    def set_state(self, state: BreakerStateEnum, reason: str = "") -> None:
        """Updates circuit breaker state across all storage tiers."""
        formatted_reason = (
            f"[{state.value}] {reason}"
            if (reason and state.value not in reason)
            else (reason or f"State transitioned to {state.value}")
        )
        self._apply_state_change(
            target_state=state,
            reason=formatted_reason,
            updated_by="system",
            is_escalation=(BREAKER_STATE_RANKS[state] > BREAKER_STATE_RANKS[self._cached_state]),
        )

    def _apply_state_change(
        self,
        target_state: BreakerStateEnum,
        reason: str,
        updated_by: str,
        is_escalation: bool,
    ) -> BreakerState:
        with self._lock:
            now = datetime.now(UTC)
            self._cached_state = target_state
            self._cached_reason = reason
            self._cached_updated_at = now
            self._cached_updated_by = updated_by

            # When entering HOLD or LOCKDOWN:
            # 1. Increment token epoch in Redis (revokes live tokens)
            # 2. Trigger KeyUsePolicyHook to disable KMS/HSM signing keys
            new_epoch = token_epoch_store.get_current_epoch()
            if target_state in [BreakerStateEnum.HOLD, BreakerStateEnum.LOCKDOWN]:
                new_epoch = token_epoch_store.increment_epoch()
                key_policy_hook.on_breaker_state_change(target_state, reason=reason)
            elif target_state == BreakerStateEnum.NORMAL:
                key_policy_hook.on_breaker_state_change(target_state, reason=reason)

            # Persist to Postgres
            try:
                with self._get_session() as session:
                    rec = session.query(BreakerStateRecord).filter_by(id=1).first()
                    if rec:
                        rec.state = target_state.value
                        rec.reason = reason
                        rec.updated_by = updated_by
                        rec.token_epoch = new_epoch
                        rec.updated_at = now
                    else:
                        rec = BreakerStateRecord(
                            id=1,
                            state=target_state.value,
                            reason=reason,
                            updated_by=updated_by,
                            token_epoch=new_epoch,
                            updated_at=now,
                            data_label="REAL",
                        )
                        session.add(rec)
                    session.commit()
            except Exception as exc:
                logger.warning("breaker_db_write_failure: %s", exc)

            # Update Redis cache
            try:
                r = self._get_redis()
                payload = json.dumps(
                    {
                        "state": target_state.value,
                        "reason": reason,
                        "updated_by": updated_by,
                        "token_epoch": new_epoch,
                        "updated_at": now.isoformat(),
                    }
                )
                r.set(self._redis_key, payload)
            except Exception as exc:
                logger.warning("breaker_redis_write_failure: %s", exc)

            # Append to immutable audit log
            action_tag = "BREAKER_ESCALATE" if is_escalation else "BREAKER_DEESCALATE"
            self._append_audit_entry(
                event_type=action_tag,
                request_id=f"brk-{uuid.uuid4().hex[:8]}",
                verdict=target_state.value,
                extra_detail=f"updated_by={updated_by}; reason={reason}",
            )

            # Push live WebSocket stream event
            try:
                stream_broadcaster.publish_event(
                    event_type="breaker_state_change",
                    payload={
                        "state": target_state.value,
                        "reason": reason,
                        "updated_by": updated_by,
                        "token_epoch": new_epoch,
                    },
                    data_label="REAL",
                )
            except Exception as exc:
                logger.warning("breaker_websocket_broadcast_failed: %s", exc)

            return BreakerState(
                state=target_state,
                reason=reason,
                updated_at=now,
                updated_by=updated_by,
                token_epoch=new_epoch,
                active_deescalation_request_id=self._active_deescalation_id,
                data_label=DataLabel.REAL,
            )

    def escalate(
        self,
        target_state: BreakerStateEnum,
        reason: str,
        updated_by: str,
    ) -> BreakerState:
        """Escalates circuit breaker to a strictly higher operational restriction state instantly."""
        current_state = self.get_state()
        if BREAKER_STATE_RANKS[target_state] <= BREAKER_STATE_RANKS[current_state]:
            raise ValueError(
                f"Escalation requires target state strictly higher than current state '{current_state.value}'; "
                f"got '{target_state.value}'."
            )

        return self._apply_state_change(
            target_state=target_state,
            reason=reason,
            updated_by=updated_by,
            is_escalation=True,
        )

    def create_deescalation_request(
        self,
        target_state: BreakerStateEnum,
        reason: str,
        requested_by: str,
    ) -> DeescalationRequestModel:
        """Creates a proposed state lowering proposal requiring 2 distinct approvers with WebAuthn."""
        current_state = self.get_state()
        if BREAKER_STATE_RANKS[target_state] >= BREAKER_STATE_RANKS[current_state]:
            raise ValueError(
                f"De-escalation requires target state strictly lower than current state '{current_state.value}'; "
                f"got '{target_state.value}'."
            )

        req_id = f"brk-req-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC)

        # 32-byte deterministic challenge over request params
        challenge_payload = f"deescalate:{req_id}:{current_state.value}:{target_state.value}:{now.timestamp()}"
        challenge = "0x" + hashlib.sha256(challenge_payload.encode("utf-8")).hexdigest()

        request_model = DeescalationRequestModel(
            id=req_id,
            current_state=current_state,
            target_state=target_state,
            reason=reason,
            requested_by=requested_by,
            challenge=challenge,
            status="PENDING",
            approvals=[],
            created_at=now,
            required_approvals=2,
            data_label=DataLabel.REAL,
        )

        with self._lock:
            self._requests[req_id] = request_model
            self._active_deescalation_id = req_id

        # Persist to Postgres
        try:
            with self._get_session() as session:
                rec = DeescalationRequestRecord(
                    id=req_id,
                    current_state=current_state.value,
                    target_state=target_state.value,
                    reason=reason,
                    requested_by=requested_by,
                    challenge=challenge,
                    status="PENDING",
                    approvals_json="[]",
                    created_at=now,
                )
                session.add(rec)
                session.commit()
        except Exception as exc:
            logger.warning("breaker_deescalate_req_db_persist_failed: %s", exc)

        # Audit entry
        self._append_audit_entry(
            event_type="BREAKER_DEESCALATE_REQUEST",
            request_id=req_id,
            verdict=target_state.value,
            extra_detail=f"requested_by={requested_by}; reason={reason}; challenge={challenge}",
        )

        return request_model

    def _lookup_request(self, request_id: str) -> DeescalationRequestModel | None:
        """Looks up a de-escalation proposal in memory or PostgreSQL."""
        req = self._requests.get(request_id)
        if req is not None:
            return req

        try:
            with self._get_session() as session:
                db_rec = session.query(DeescalationRequestRecord).filter_by(id=request_id).first()
                if db_rec:
                    apprs = [
                        DeescalationApprovalModel(**a)
                        for a in json.loads(db_rec.approvals_json or "[]")
                    ]
                    req = DeescalationRequestModel(
                        id=db_rec.id,
                        current_state=BreakerStateEnum(db_rec.current_state),
                        target_state=BreakerStateEnum(db_rec.target_state),
                        reason=db_rec.reason,
                        requested_by=db_rec.requested_by,
                        challenge=db_rec.challenge,
                        status=db_rec.status,
                        approvals=apprs,
                        created_at=db_rec.created_at,
                        resolved_at=db_rec.resolved_at,
                        required_approvals=2,
                    )
                    self._requests[request_id] = req
                    return req
        except Exception as exc:
            logger.warning("db_lookup_deescalation_req_failed: %s", exc)

        return None

    def get_deescalation_request(self, request_id: str) -> DeescalationRequestModel | None:
        """Retrieves a specific de-escalation request by ID."""
        with self._lock:
            return self._lookup_request(request_id)

    def get_active_deescalation_request(self) -> DeescalationRequestModel | None:
        """Retrieves the active de-escalation request if one is currently pending."""
        with self._lock:
            if not self._active_deescalation_id:
                return None
            req = self._lookup_request(self._active_deescalation_id)
            if req and req.status == "PENDING":
                return req
            return None

    def approve_deescalation(
        self,
        request_id: str,
        approver_id: str,
        assertion: WebAuthnAssertion,
    ) -> DeescalateApprovalResult:
        """Submits a WebAuthn approval over the de-escalation challenge.

        Enforces:
        - Requester cannot approve their own proposal (Separation of duties).
        - Each approver must be distinct.
        - WebAuthn cryptographic verification over challenge.
        - Exactly 2 distinct approvals required for unlock.
        """
        with self._lock:
            # 1. Lookup request
            req = self._lookup_request(request_id)
            if req is None:
                raise ValueError(f"De-escalation request '{request_id}' not found")

            if req.status != "PENDING":
                raise ValueError(f"De-escalation request '{request_id}' is already {req.status}")

            # 2. Separation of duties
            if approver_id == req.requested_by:
                raise ValueError(
                    f"Separation of duties violation: requester '{approver_id}' cannot approve their own de-escalation request"
                )

            # 3. Duplicate approver check
            if any(a.approver_id == approver_id for a in req.approvals):
                raise ValueError(f"Approver '{approver_id}' has already approved this request")

            # 4. Verify WebAuthn assertion
            webauthn_verifier.verify_assertion(
                assertion=assertion,
                expected_digest=req.challenge,
                approver_id=approver_id,
            )

            # 5. Record approval
            approval_entry = DeescalationApprovalModel(
                approver_id=approver_id,
                timestamp=time.time(),
                signature=assertion.signature[:64],
            )
            req.approvals.append(approval_entry)

            # 6. Check quorum threshold (2 of 2)
            if len(req.approvals) < 2:
                # Quorum pending
                self._update_deescalation_db(req)
                return DeescalateApprovalResult(
                    request_id=request_id,
                    status="PENDING",
                    approvals_count=len(req.approvals),
                    required_approvals=2,
                    message="Approval 1 of 2 recorded. Awaiting second approver WebAuthn assertion.",
                    new_breaker_state=None,
                    data_label=DataLabel.REAL,
                )

            # Quorum reached (2 of 2)!
            req.status = "APPROVED"
            req.resolved_at = datetime.now(UTC)
            self._active_deescalation_id = None
            self._update_deescalation_db(req)

        # Lower circuit breaker state
        new_state = self._apply_state_change(
            target_state=req.target_state,
            reason=f"Quorum unlock approved by {req.approvals[0].approver_id} and {req.approvals[1].approver_id}: {req.reason}",
            updated_by=f"quorum:{req.approvals[0].approver_id}+{req.approvals[1].approver_id}",
            is_escalation=False,
        )

        return DeescalateApprovalResult(
            request_id=request_id,
            status="APPROVED",
            approvals_count=2,
            required_approvals=2,
            message=f"Quorum reached (2 of 2). Breaker state de-escalated to {new_state.state.value}.",
            new_breaker_state=new_state.state,
            data_label=DataLabel.REAL,
        )

    def _update_deescalation_db(self, req: DeescalationRequestModel) -> None:
        try:
            with self._get_session() as session:
                rec = session.query(DeescalationRequestRecord).filter_by(id=req.id).first()
                if rec:
                    rec.status = req.status
                    rec.resolved_at = req.resolved_at
                    rec.approvals_json = json.dumps([a.model_dump() for a in req.approvals])
                    session.commit()
        except Exception as exc:
            logger.warning("breaker_deescalate_req_db_update_failed: %s", exc)

    def reset(self) -> None:
        """Resets breaker state to nominal (test utility)."""
        with self._lock:
            self._cached_state = BreakerStateEnum.NORMAL
            self._cached_reason = "Nominal operations"
            self._cached_updated_at = datetime.now(UTC)
            self._cached_updated_by = "system"
            self._active_deescalation_id = None
            self._requests.clear()
            token_epoch_store.reset(1)
            key_policy_hook.reset()

            try:
                r = self._get_redis()
                r.delete(self._redis_key)
            except Exception:
                pass

            try:
                with self._get_session() as session:
                    rec = session.query(BreakerStateRecord).filter_by(id=1).first()
                    if rec:
                        rec.state = "NORMAL"
                        rec.reason = "Nominal operations"
                        rec.token_epoch = 1
                        session.commit()
            except Exception:
                pass


# Global singleton instance
distributed_breaker_store = DistributedBreakerStore()
