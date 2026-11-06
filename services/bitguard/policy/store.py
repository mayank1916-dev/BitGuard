"""Database repository and memory cache for Versioned Policies (Milestone S20 / Section D)."""

import logging
import threading
from datetime import UTC, datetime

from sqlalchemy.orm import Session, sessionmaker

from services.bitguard.database import get_session_factory
from services.bitguard.db_models import PolicyVersionRecord
from services.bitguard.policy.models import (
    ChangeClassification,
    PolicyApproval,
    PolicyDocument,
    PolicyStatus,
    PolicyVersion,
)

logger = logging.getLogger("bitguard.policy.store")


class PolicyStore:
    """Thread-safe persistence store for signed policy versions."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._session_factory: sessionmaker[Session] | None = None
        self._memory_versions: dict[str, PolicyVersion] = {}
        self._active_version_id: str | None = None

    def set_session_factory(self, factory: sessionmaker[Session] | None) -> None:
        with self._lock:
            self._session_factory = factory

    def _get_session(self) -> Session:
        factory = self._session_factory or get_session_factory()
        return factory()

    def clear(self) -> None:
        with self._lock:
            self._memory_versions.clear()
            self._active_version_id = None

    def save(self, policy_ver: PolicyVersion) -> PolicyVersion:
        """Persists or updates a policy version record in DB and memory."""
        with self._lock:
            self._memory_versions[policy_ver.id] = policy_ver
            if policy_ver.status == PolicyStatus.ACTIVE:
                self._active_version_id = policy_ver.id

            try:
                with self._get_session() as session:
                    rec = session.query(PolicyVersionRecord).filter_by(id=policy_ver.id).first()
                    content_dict = policy_ver.content.model_dump(mode="json")
                    approvals_dict = [a.model_dump(mode="json") for a in policy_ver.approvals]

                    if rec:
                        rec.version = policy_ver.version
                        rec.content = content_dict
                        rec.content_hash = policy_ver.content_hash
                        rec.status = policy_ver.status.value
                        rec.change_type = policy_ver.change_type.value
                        rec.ed25519_signature = policy_ver.ed25519_signature
                        rec.signatures = policy_ver.signatures
                        rec.approvals = approvals_dict
                        rec.backtest_report_id = policy_ver.backtest_report_id
                        rec.cool_down_until = policy_ver.cool_down_until
                        rec.activated_at = policy_ver.activated_at
                        rec.rolled_back_at = policy_ver.rolled_back_at
                        rec.rollback_reason = policy_ver.rollback_reason
                        rec.is_active = (policy_ver.status == PolicyStatus.ACTIVE)
                        rec.rules = content_dict
                    else:
                        rec = PolicyVersionRecord(
                            id=policy_ver.id,
                            version=policy_ver.version,
                            author=policy_ver.author,
                            content=content_dict,
                            content_hash=policy_ver.content_hash,
                            status=policy_ver.status.value,
                            change_type=policy_ver.change_type.value,
                            ed25519_signature=policy_ver.ed25519_signature,
                            signatures=policy_ver.signatures,
                            approvals=approvals_dict,
                            backtest_report_id=policy_ver.backtest_report_id,
                            cool_down_until=policy_ver.cool_down_until,
                            activated_at=policy_ver.activated_at,
                            rolled_back_at=policy_ver.rolled_back_at,
                            rollback_reason=policy_ver.rollback_reason,
                            is_active=(policy_ver.status == PolicyStatus.ACTIVE),
                            rules=content_dict,
                            created_at=policy_ver.created_at,
                        )
                        session.add(rec)
                    session.commit()
            except Exception as exc:
                logger.debug("Database policy version save bypassed: %s", exc)

        return policy_ver

    def get(self, version_id: str) -> PolicyVersion | None:
        """Retrieves policy version by ID."""
        with self._lock:
            if version_id in self._memory_versions:
                return self._memory_versions[version_id]

            try:
                with self._get_session() as session:
                    rec = session.query(PolicyVersionRecord).filter_by(id=version_id).first()
                    if rec:
                        pv = self._record_to_model(rec)
                        self._memory_versions[pv.id] = pv
                        return pv
            except Exception as exc:
                logger.debug("Database policy version read bypassed: %s", exc)

        return None

    def get_by_version(self, version_str: str) -> PolicyVersion | None:
        """Retrieves policy version by version string (e.g. 'v1.0.0')."""
        with self._lock:
            for pv in self._memory_versions.values():
                if pv.version == version_str:
                    return pv

            try:
                with self._get_session() as session:
                    rec = session.query(PolicyVersionRecord).filter_by(version=version_str).first()
                    if rec:
                        pv = self._record_to_model(rec)
                        self._memory_versions[pv.id] = pv
                        return pv
            except Exception as exc:
                logger.debug("Database policy version read bypassed: %s", exc)

        return None

    def get_active(self) -> PolicyVersion | None:
        """Retrieves currently active policy version."""
        with self._lock:
            if self._active_version_id and self._active_version_id in self._memory_versions:
                active_pv = self._memory_versions[self._active_version_id]
                if active_pv.status == PolicyStatus.ACTIVE:
                    return active_pv

            # Query database
            try:
                with self._get_session() as session:
                    rec = (
                        session.query(PolicyVersionRecord)
                        .filter_by(status=PolicyStatus.ACTIVE.value)
                        .order_by(PolicyVersionRecord.created_at.desc())
                        .first()
                    )
                    if not rec:
                        # Fallback to is_active column
                        rec = (
                            session.query(PolicyVersionRecord)
                            .filter_by(is_active=True)
                            .order_by(PolicyVersionRecord.created_at.desc())
                            .first()
                        )

                    if rec:
                        pv = self._record_to_model(rec)
                        self._memory_versions[pv.id] = pv
                        self._active_version_id = pv.id
                        return pv
            except Exception as exc:
                logger.debug("Database active policy read bypassed: %s", exc)

            # Check memory
            for pv in self._memory_versions.values():
                if pv.status == PolicyStatus.ACTIVE:
                    self._active_version_id = pv.id
                    return pv

        return None

    def list_all(self, limit: int = 50) -> list[PolicyVersion]:
        """Lists all policy versions sorted by created_at descending."""
        with self._lock:
            try:
                with self._get_session() as session:
                    records = (
                        session.query(PolicyVersionRecord)
                        .order_by(PolicyVersionRecord.created_at.desc())
                        .limit(limit)
                        .all()
                    )
                    for rec in records:
                        if rec.id not in self._memory_versions:
                            self._memory_versions[rec.id] = self._record_to_model(rec)
            except Exception as exc:
                logger.debug("Database list policy versions bypassed: %s", exc)

            results = list(self._memory_versions.values())
            results.sort(key=lambda p: p.created_at, reverse=True)
            return results[:limit]

    def set_active(self, version_id: str) -> PolicyVersion:
        """Sets target policy version as ACTIVE and deactivates all others."""
        target = self.get(version_id)
        if not target:
            raise KeyError(f"Policy version '{version_id}' not found")

        now = datetime.now(UTC)
        with self._lock:
            # Mark all currently active versions inactive in memory
            for pv in self._memory_versions.values():
                if pv.id != version_id and pv.status == PolicyStatus.ACTIVE:
                    pv.status = PolicyStatus.DRAFT

            target.status = PolicyStatus.ACTIVE
            target.activated_at = now
            self._active_version_id = target.id
            self._memory_versions[target.id] = target

            try:
                with self._get_session() as session:
                    # Update all other active records
                    active_recs = session.query(PolicyVersionRecord).filter(
                        PolicyVersionRecord.id != version_id,
                        (PolicyVersionRecord.status == PolicyStatus.ACTIVE.value)
                        | (PolicyVersionRecord.is_active == True),  # noqa: E712
                    ).all()
                    for r in active_recs:
                        r.status = PolicyStatus.DRAFT.value
                        r.is_active = False

                    target_rec = session.query(PolicyVersionRecord).filter_by(id=version_id).first()
                    if target_rec:
                        target_rec.status = PolicyStatus.ACTIVE.value
                        target_rec.is_active = True
                        target_rec.activated_at = now
                    session.commit()
            except Exception as exc:
                logger.debug("Database set_active transaction bypassed: %s", exc)

        return target

    def rollback(
        self,
        current_active_id: str,
        target_version_id: str,
        reason: str,
    ) -> PolicyVersion:
        """Rolls back the active policy version to target version."""
        current = self.get(current_active_id)
        target = self.get(target_version_id)
        if not target:
            raise KeyError(f"Target rollback policy version '{target_version_id}' not found")

        now = datetime.now(UTC)
        with self._lock:
            if current:
                current.status = PolicyStatus.ROLLED_BACK
                current.rolled_back_at = now
                current.rollback_reason = reason
                self._memory_versions[current.id] = current

            target.status = PolicyStatus.ACTIVE
            target.activated_at = now
            self._active_version_id = target.id
            self._memory_versions[target.id] = target

            try:
                with self._get_session() as session:
                    if current:
                        c_rec = session.query(PolicyVersionRecord).filter_by(id=current.id).first()
                        if c_rec:
                            c_rec.status = PolicyStatus.ROLLED_BACK.value
                            c_rec.is_active = False
                            c_rec.rolled_back_at = now
                            c_rec.rollback_reason = reason

                    t_rec = session.query(PolicyVersionRecord).filter_by(id=target.id).first()
                    if t_rec:
                        t_rec.status = PolicyStatus.ACTIVE.value
                        t_rec.is_active = True
                        t_rec.activated_at = now
                    session.commit()
            except Exception as exc:
                logger.debug("Database rollback transaction bypassed: %s", exc)

        return target

    def _record_to_model(self, rec: PolicyVersionRecord) -> PolicyVersion:
        raw_content = rec.content or rec.rules or {}
        policy_doc = PolicyDocument(**raw_content) if isinstance(raw_content, dict) and "limits" in raw_content else PolicyDocument()
        approvals = [PolicyApproval(**a) for a in (rec.approvals or [])]

        raw_status = rec.status or ("ACTIVE" if rec.is_active else "DRAFT")
        status_enum = PolicyStatus(raw_status) if raw_status in PolicyStatus.__members__ else PolicyStatus.DRAFT

        raw_change = rec.change_type or "TIGHTEN"
        change_enum = ChangeClassification(raw_change) if raw_change in ChangeClassification.__members__ else ChangeClassification.TIGHTEN

        return PolicyVersion(
            id=rec.id,
            version=rec.version,
            author=rec.author,
            created_at=rec.created_at,
            status=status_enum,
            content=policy_doc,
            content_hash=rec.content_hash or "",
            change_type=change_enum,
            ed25519_signature=rec.ed25519_signature or rec.signature,
            signatures=rec.signatures or [],
            approvals=approvals,
            backtest_report_id=rec.backtest_report_id,
            cool_down_until=rec.cool_down_until,
            activated_at=rec.activated_at,
            rolled_back_at=rec.rolled_back_at,
            rollback_reason=rec.rollback_reason,
        )


policy_store = PolicyStore()
