"""Versioned Policy Management engine with asymmetric evolution, cryptographic activation, and integrity verification (Milestone S20 / Section D).

Invariants:
- Invariant #6: Asymmetric Policy Evolution:
  Tightening = one person (Operator/SecOps/Admin), instant.
  Loosening = quorum (2 WebAuthn approvers) + cool-down delay + attached backtest report.
  Author CANNOT approve their own change.
  MIXED is treated as LOOSEN.
- Invariant #7: Immutable Audit Trail: Every proposal, approval, activation, rollback, and integrity failure is logged.
- Invariant #8: Explicit Data Provenance (data_label REAL).
- Integrity Check: periodic comparison of engine hash vs database ACTIVE record. Mismatch => alert and fail closed.
"""

import json
import logging
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from services.bitguard.approvals.models import WebAuthnAssertion
from services.bitguard.approvals.webauthn import (
    WebAuthnVerificationError,
    webauthn_verifier,
)
from services.bitguard.audit_service import audit_service
from services.bitguard.breaker import distributed_breaker_store
from services.bitguard.breaker.models import BreakerStateEnum
from services.bitguard.config import settings
from services.bitguard.engine.pipeline import decision_engine
from services.bitguard.models import DataLabel, OperationMode, Role, UserResponse
from services.bitguard.policy.classifier import classify_change
from services.bitguard.policy.crypto import (
    compute_content_hash,
    sign_content_hash,
    verify_ed25519_signature,
)
from services.bitguard.policy.models import (
    ChangeClassification,
    LimitsPolicy,
    PolicyApproval,
    PolicyDocument,
    PolicyIntegrityResponse,
    PolicyStatus,
    PolicyVersion,
    ProposePolicyRequest,
    ThresholdsPolicy,
    TimeLockPolicy,
    WalletGroupPolicy,
)
from services.bitguard.policy.store import policy_store
from services.bitguard.stream.broadcaster import stream_broadcaster

logger = logging.getLogger("bitguard.policy.service")


class PolicyService:
    """Core Policy Management Service governing policy versioning, cryptographic signing, and engine hot-reloading."""

    def __init__(self) -> None:
        self.last_healthy_version_id: str | None = None
        self.last_healthy_version_hash: str | None = None
        self.previous_active_version_id: str | None = None
        self.baseline_version_id: str = "pv-baseline-v1.0.0"
        self.get_or_create_baseline()

    def get_or_create_baseline(self) -> PolicyVersion:
        """Ensures an initial signed baseline policy version exists and is active."""
        active = policy_store.get_active()
        if active:
            self.last_healthy_version_id = active.id
            self.last_healthy_version_hash = active.content_hash
            decision_engine.reload_policy(active.content, content_hash=active.content_hash)
            return active

        baseline_doc = PolicyDocument(
            version="v1.0.0",
            description="Initial verified defensive policy baseline",
            limits=LimitsPolicy(
                global_daily_usd=1_000_000.0,
                global_single_tx_usd=100_000.0,
                global_velocity_limit_usd=500_000.0,
                wallet_daily_usd={},
                asset_daily_limits={},
                chain_daily_limits={},
            ),
            thresholds=ThresholdsPolicy(
                single_tx_usd=50_000.0,
                velocity_spike_multiplier=3.0,
                hold_score=50,
            ),
            wallet_groups={
                "default": WalletGroupPolicy(
                    mode=OperationMode.SIMULATION,
                    wallets=["0x742d35Cc6634C0532925a3b844Bc454e4438f44e"],
                )
            },
            delegate_allowlist=["0x1111111111111111111111111111111111111111"],
            owned_addresses=["0x742d35Cc6634C0532925a3b844Bc454e4438f44e"],
            time_lock=TimeLockPolicy(min_amount_usd=100_000.0, delay_seconds=3600),
            risk_weights={
                "NEW_CONTRACT": 30,
                "HIGH_VALUE": 40,
                "DELEGATION_OWNED_ADDRESS": 95,
            },
        )

        content_hash = compute_content_hash(baseline_doc)
        sig = sign_content_hash(content_hash)

        baseline_version = PolicyVersion(
            id="pv-baseline-v1.0.0",
            version="v1.0.0",
            author="system",
            created_at=datetime.now(UTC),
            status=PolicyStatus.ACTIVE,
            content=baseline_doc,
            content_hash=content_hash,
            change_type=ChangeClassification.TIGHTEN,
            ed25519_signature=sig,
            signatures=[{"type": "Ed25519", "signature": sig, "signer": "release_authority"}],
            activated_at=datetime.now(UTC),
            data_label=DataLabel.REAL,
        )

        policy_store.save(baseline_version)
        self.last_healthy_version_id = baseline_version.id
        self.last_healthy_version_hash = baseline_version.content_hash
        decision_engine.reload_policy(baseline_doc, content_hash=content_hash)
        return baseline_version

    def propose_policy(
        self,
        request: ProposePolicyRequest,
        author_user: UserResponse,
    ) -> PolicyVersion:
        """Proposes a new versioned policy manifest, classifies changes, and schedules requirements."""
        # Check for duplicate version
        existing = policy_store.get_by_version(request.version)
        if existing:
            raise ValueError(f"Policy version '{request.version}' already exists")

        # Get current active baseline to classify change
        current_active = self.get_or_create_baseline()
        change_type = classify_change(current_active.content, request.content)

        content_hash = compute_content_hash(request.content)

        # Ed25519 signature: either provided or signed with release authority
        ed25519_sig = request.ed25519_signature or sign_content_hash(content_hash)

        now = datetime.now(UTC)
        cool_down_until: datetime | None = None
        if change_type in [ChangeClassification.LOOSEN, ChangeClassification.MIXED]:
            cooldown_seconds = getattr(settings, "policy_cooldown_seconds", 60)
            cool_down_until = now + timedelta(seconds=cooldown_seconds)

        new_version = PolicyVersion(
            id=f"pv-{uuid4().hex[:12]}",
            version=request.version,
            author=author_user.id,
            created_at=now,
            status=PolicyStatus.PENDING,
            content=request.content,
            content_hash=content_hash,
            change_type=change_type,
            ed25519_signature=ed25519_sig,
            signatures=[{"type": "Ed25519", "signature": ed25519_sig, "signer": "release_authority"}],
            backtest_report_id=request.backtest_report_id,
            cool_down_until=cool_down_until,
            data_label=DataLabel.REAL,
        )

        policy_store.save(new_version)

        # Invariant #7: Append immutable audit record
        audit_service.append_entry(
            action=f"POLICY_PROPOSED:{new_version.version}",
            actor=author_user.email,
            payload={
                "version_id": new_version.id,
                "version": new_version.version,
                "change_type": change_type.value,
                "content_hash": content_hash,
                "backtest_report_id": request.backtest_report_id,
            },
            data_label=DataLabel.REAL,
        )

        stream_broadcaster.publish_event(
            event_type="POLICY_UPDATE",
            payload=new_version.model_dump(mode="json"),
            data_label="REAL",
        )

        return new_version

    def approve_policy(
        self,
        version_id: str,
        approver_user: UserResponse,
        assertion: WebAuthnAssertion,
    ) -> PolicyVersion:
        """Records a WebAuthn approval for a pending policy change enforcing separation of duties."""
        policy_ver = policy_store.get(version_id)
        if not policy_ver:
            raise KeyError(f"Policy version '{version_id}' not found")

        if policy_ver.status != PolicyStatus.PENDING:
            raise ValueError(f"Policy version '{policy_ver.version}' is not in PENDING state (status={policy_ver.status.value})")

        # Invariant #6: Author cannot approve their own change
        if approver_user.id == policy_ver.author or approver_user.email == policy_ver.author:
            raise PermissionError("Policy author cannot approve their own change (Separation of duties)")

        # Invariant #6: Each approver must be distinct
        for existing_appr in policy_ver.approvals:
            if existing_appr.approver_id == approver_user.id or existing_appr.approver_email == approver_user.email:
                raise ValueError(f"Approver '{approver_user.email}' has already approved this policy version")

        # Loosening requires an attached backtest report matching draft policy hash (TASK S22)
        if policy_ver.change_type in [ChangeClassification.LOOSEN, ChangeClassification.MIXED]:
            if not policy_ver.backtest_report_id:
                raise ValueError(
                    f"Loosening policy change ({policy_ver.change_type.value}) requires an attached "
                    "backtest_report_id; cannot approve without backtest evidence"
                )
            from services.bitguard.backtest.service import backtest_service
            report = backtest_service.get_report(policy_ver.backtest_report_id)
            if not report:
                raise ValueError(
                    f"Attached backtest report '{policy_ver.backtest_report_id}' was not found"
                )
            if report.draft_policy_hash != policy_ver.content_hash:
                raise ValueError(
                    f"Attached backtest report draft policy hash ({report.draft_policy_hash}) "
                    f"does not match proposed policy content hash ({policy_ver.content_hash})"
                )

        # Invariant #5: Cryptographic WebAuthn assertion verification
        try:
            webauthn_verifier.verify_assertion(
                assertion=assertion,
                expected_digest=policy_ver.content_hash,
                approver_id=approver_user.id,
            )
        except WebAuthnVerificationError as exc:
            logger.warning("Policy WebAuthn verification failed: %s", exc)
            raise ValueError(f"WebAuthn verification failed: {exc.detail}") from exc

        now = datetime.now(UTC)
        approval_record = PolicyApproval(
            approver_id=approver_user.id,
            approver_email=approver_user.email,
            approver_role=approver_user.role,
            approved_at=now,
            webauthn_assertion=assertion,
            assertion_hash=f"passert-{uuid4().hex[:12]}",
        )
        policy_ver.approvals.append(approval_record)
        policy_store.save(policy_ver)

        # Invariant #7: Immutable audit trail
        audit_service.append_entry(
            action=f"POLICY_APPROVED:{policy_ver.version}",
            actor=approver_user.email,
            payload={
                "version_id": policy_ver.id,
                "version": policy_ver.version,
                "approvals_count": len(policy_ver.approvals),
                "approver_role": approver_user.role.value,
            },
            data_label=DataLabel.REAL,
        )

        stream_broadcaster.publish_event(
            event_type="POLICY_UPDATE",
            payload=policy_ver.model_dump(mode="json"),
            data_label="REAL",
        )

        return policy_ver

    def activate_policy(
        self,
        version_id: str,
        activator_user: UserResponse,
        ed25519_sig_override: str | None = None,
    ) -> PolicyVersion:
        """Activates a policy version after verifying signature, quorum, cool-down, and content hash."""
        policy_ver = policy_store.get(version_id)
        if not policy_ver:
            raise KeyError(f"Policy version '{version_id}' not found")

        if policy_ver.status == PolicyStatus.ACTIVE:
            return policy_ver

        now = datetime.now(UTC)

        # Invariant #6: Asymmetric governance checks
        if policy_ver.change_type in [ChangeClassification.LOOSEN, ChangeClassification.MIXED]:
            # Requires 2 distinct approvers
            if len(policy_ver.approvals) < 2:
                raise ValueError(
                    f"Loosening policy change ({policy_ver.change_type.value}) requires 2 distinct WebAuthn "
                    f"approvers; got {len(policy_ver.approvals)}"
                )

            # Requires attached backtest report matching draft policy hash (TASK S22)
            if not policy_ver.backtest_report_id:
                raise ValueError(
                    f"Loosening policy change ({policy_ver.change_type.value}) requires an attached backtest_report_id"
                )
            from services.bitguard.backtest.service import backtest_service
            report = backtest_service.get_report(policy_ver.backtest_report_id)
            if not report:
                raise ValueError(
                    f"Attached backtest report '{policy_ver.backtest_report_id}' was not found"
                )
            if report.draft_policy_hash != policy_ver.content_hash:
                raise ValueError(
                    f"Attached backtest report draft policy hash ({report.draft_policy_hash}) "
                    f"does not match policy content hash ({policy_ver.content_hash})"
                )

            # Enforce cool-down delay
            if policy_ver.cool_down_until and now < policy_ver.cool_down_until:
                remaining_sec = int((policy_ver.cool_down_until - now).total_seconds())
                raise ValueError(
                    f"Policy is in cool-down delay; activation allowed after cool-down completes ({remaining_sec}s remaining)"
                )
        else:
            # TIGHTEN: One authorized Operator, SecOps, or Admin can activate instantly
            if activator_user.role not in [Role.OPERATOR, Role.SECOPS, Role.ADMIN]:
                raise PermissionError("Only Operator, SecOps, or Admin roles can activate policy changes")

        # Cryptographic verification: Content Hash integrity
        recomputed_hash = compute_content_hash(policy_ver.content)
        if recomputed_hash != policy_ver.content_hash:
            raise ValueError(
                f"Policy content hash mismatch: expected {policy_ver.content_hash}, computed {recomputed_hash}. "
                "Document has been tampered with."
            )

        # Cryptographic verification: Ed25519 signature
        target_sig = ed25519_sig_override or policy_ver.ed25519_signature
        if not target_sig:
            target_sig = sign_content_hash(policy_ver.content_hash)
            policy_ver.ed25519_signature = target_sig

        if not verify_ed25519_signature(policy_ver.content_hash, target_sig):
            raise ValueError("Invalid Ed25519 release authority signature over policy content hash")

        # Track previous active version for auto-rollback
        prev_active = policy_store.get_active()
        if prev_active and prev_active.id != policy_ver.id:
            self.previous_active_version_id = prev_active.id
            self.last_healthy_version_id = prev_active.id
            self.last_healthy_version_hash = prev_active.content_hash

        # Update store status
        policy_store.set_active(policy_ver.id)

        # Hot-reload Decision Engine
        try:
            decision_engine.reload_policy(policy_ver.content, content_hash=policy_ver.content_hash)
            self.last_healthy_version_hash = policy_ver.content_hash
        except Exception as exc:
            # Auto-rollback on hot-reload validation error
            logger.error("Hot-reload validation failed on version %s: %s. Initiating auto-rollback.", policy_ver.id, exc)
            self.auto_rollback(
                version_id=policy_ver.id,
                reason=f"Validation error during engine hot-reload: {exc}",
            )
            raise ValueError(f"Policy validation failed during engine reload; auto-rolled back: {exc}") from exc

        # Invariant #7: Append immutable audit record
        audit_service.append_entry(
            action=f"POLICY_ACTIVATED:{policy_ver.version}",
            actor=activator_user.email,
            payload={
                "version_id": policy_ver.id,
                "version": policy_ver.version,
                "change_type": policy_ver.change_type.value,
                "content_hash": policy_ver.content_hash,
                "ed25519_signature": policy_ver.ed25519_signature,
            },
            data_label=DataLabel.REAL,
        )

        stream_broadcaster.publish_event(
            event_type="POLICY_HOT_RELOAD",
            payload={"version_id": policy_ver.id, "version": policy_ver.version, "hash": policy_ver.content_hash},
            data_label="REAL",
        )

        # Broadcast Redis pub/sub trigger for distributed engines
        self._publish_redis_reload_event(policy_ver.id, policy_ver.content_hash)

        logger.info("Policy version %s activated successfully (change_type=%s)", policy_ver.version, policy_ver.change_type.value)
        return policy_ver

    def _publish_redis_reload_event(self, version_id: str, content_hash: str) -> None:
        """Publishes policy reload event to Redis pub/sub channel for distributed engines."""
        try:
            import redis

            r = redis.Redis.from_url(settings.redis_url, socket_timeout=1.0)
            payload = json.dumps({"version_id": version_id, "hash": content_hash})
            r.publish("bitguard:policy:reload", payload)
            r.set("bitguard:policy:active_version_id", version_id)
        except Exception as exc:
            logger.debug("Redis pub/sub reload broadcast bypassed: %s", exc)

    def poll_active_version(self) -> PolicyVersion | None:
        """Polls the active version pointer and hot-reloads decision engine if changed."""
        active = policy_store.get_active()
        if not active:
            return None

        if active.content_hash != decision_engine.active_policy_hash:
            logger.info("Engine detected updated active policy pointer: %s. Hot-reloading.", active.version)
            decision_engine.reload_policy(active.content, content_hash=active.content_hash)
            self.last_healthy_version_id = active.id
            self.last_healthy_version_hash = active.content_hash

        return active

    def auto_rollback(
        self,
        version_id: str | None = None,
        reason: str = "Validation or health check failure",
    ) -> PolicyVersion:
        """Reverts active policy to the previous verified healthy version upon validation or health check failure."""
        current_active = policy_store.get_active()
        active_id = version_id or (current_active.id if current_active else "unknown")

        target_id = self.previous_active_version_id
        if not target_id or target_id == active_id:
            # Fallback to baseline
            baseline_ver = policy_store.get_by_version("v1.0.0") or policy_store.get("pv-baseline-v1.0.0")
            target_id = baseline_ver.id if baseline_ver else self.baseline_version_id

        reverted_version = policy_store.rollback(
            current_active_id=active_id,
            target_version_id=target_id,
            reason=reason,
        )

        # Hot-reload engine with reverted policy
        decision_engine.reload_policy(reverted_version.content, content_hash=reverted_version.content_hash)
        self.last_healthy_version_id = reverted_version.id
        self.last_healthy_version_hash = reverted_version.content_hash

        # Invariant #7: Append audit entry
        audit_service.append_entry(
            action=f"POLICY_AUTO_ROLLEDBACK:{reverted_version.version}",
            actor="policy_auto_rollback_service",
            payload={
                "rolled_back_from": active_id,
                "restored_version": reverted_version.version,
                "reason": reason,
            },
            data_label=DataLabel.REAL,
        )

        stream_broadcaster.publish_event(
            event_type="POLICY_AUTO_ROLLBACK",
            payload={
                "rolled_back_from": active_id,
                "restored_version": reverted_version.version,
                "reason": reason,
            },
            data_label="REAL",
        )

        logger.warning(
            "AUTO_ROLLBACK_EXECUTED: Reverted from %s to %s. Reason: %s",
            active_id,
            reverted_version.version,
            reason,
        )
        return reverted_version

    def run_integrity_check(self) -> PolicyIntegrityResponse:
        """Compares engine in-memory loaded policy hash against DB active record and cryptographic signature.

        Integrity Check Invariant:
        Engines compare loaded policy hash against ACTIVE record; mismatch or direct database
        tampering => alert and fail closed (reverts engine to last verified safe version).
        """
        active_db = policy_store.get_active()
        if not active_db:
            return PolicyIntegrityResponse(
                valid=False,
                active_version_id="none",
                active_version_hash="",
                memory_version_hash=decision_engine.active_policy_hash,
                db_version_hash="",
                ed25519_verified=False,
                details="No ACTIVE policy record found in database",
            )

        db_hash = active_db.content_hash
        mem_hash = decision_engine.active_policy_hash

        # 1. Recompute content hash from DB content to detect direct SQL edits
        recomputed_db_hash = compute_content_hash(active_db.content)
        content_tampered = (recomputed_db_hash != db_hash)

        # 2. Check Ed25519 signature
        sig_valid = False
        if active_db.ed25519_signature:
            sig_valid = verify_ed25519_signature(db_hash, active_db.ed25519_signature)

        # 3. Check memory hash matches database hash
        memory_mismatch = (mem_hash != db_hash)

        if content_tampered or not sig_valid or memory_mismatch:
            tamper_reason = []
            if content_tampered:
                tamper_reason.append(f"Direct DB content edit detected (recomputed {recomputed_db_hash} != stored {db_hash})")
            if not sig_valid:
                tamper_reason.append("Invalid or missing Ed25519 release signature on active record")
            if memory_mismatch:
                tamper_reason.append(f"Engine memory hash mismatch (mem {mem_hash} != db {db_hash})")

            details_msg = "; ".join(tamper_reason)
            logger.critical("POLICY_INTEGRITY_COMPROMISED: %s. Initiating fail-closed remediation.", details_msg)

            # Invariant #3 & #6: Fail closed - revert to last verified healthy version
            if self.last_healthy_version_id and self.last_healthy_version_id != active_db.id:
                fallback_ver = policy_store.get(self.last_healthy_version_id)
                if fallback_ver:
                    decision_engine.reload_policy(fallback_ver.content, content_hash=fallback_ver.content_hash)
            else:
                baseline = self.get_or_create_baseline()
                decision_engine.reload_policy(baseline.content, content_hash=baseline.content_hash)

            # Elevate circuit breaker to HOLD to contain unauthorized signing risk
            distributed_breaker_store.set_state(
                BreakerStateEnum.HOLD,
                reason=f"Policy integrity compromised: {details_msg}",
            )

            # Invariant #7: Append immutable audit record
            audit_service.append_entry(
                action="POLICY_INTEGRITY_TAMPER_DETECTED",
                actor="policy_integrity_scanner",
                payload={
                    "active_db_id": active_db.id,
                    "db_hash": db_hash,
                    "memory_hash": mem_hash,
                    "recomputed_hash": recomputed_db_hash,
                    "details": details_msg,
                },
                data_label=DataLabel.REAL,
            )

            stream_broadcaster.publish_event(
                event_type="POLICY_INTEGRITY_ALERT",
                payload={"status": "TAMPER_DETECTED", "details": details_msg},
                data_label="REAL",
            )

            return PolicyIntegrityResponse(
                valid=False,
                active_version_id=active_db.id,
                active_version_hash=db_hash,
                memory_version_hash=mem_hash,
                db_version_hash=recomputed_db_hash,
                ed25519_verified=sig_valid,
                details=details_msg,
            )

        return PolicyIntegrityResponse(
            valid=True,
            active_version_id=active_db.id,
            active_version_hash=db_hash,
            memory_version_hash=mem_hash,
            db_version_hash=db_hash,
            ed25519_verified=True,
            details="Policy integrity verified: database record, memory cache, and Ed25519 release signature match",
        )


policy_service = PolicyService()
