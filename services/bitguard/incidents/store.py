"""Storage repository for incidents with database persistence and memory caching (Milestone S19 / F14)."""

import logging
import threading
from datetime import UTC, datetime

from sqlalchemy.orm import Session, sessionmaker

from services.bitguard.database import get_session_factory
from services.bitguard.db_models import IncidentRecord
from services.bitguard.incidents.models import (
    ChecklistItem,
    Incident,
    IncidentApproval,
    IncidentStatus,
    TimelineEvent,
)
from services.bitguard.models import DataLabel

logger = logging.getLogger("bitguard.incidents.store")


class IncidentStore:
    """Thread-safe incident persistence repository."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._session_factory: sessionmaker[Session] | None = None
        # in-memory cache: incident_id -> Incident
        self._memory_incidents: dict[str, Incident] = {}

    def set_session_factory(self, factory: sessionmaker[Session] | None) -> None:
        with self._lock:
            self._session_factory = factory

    def _get_session(self) -> Session:
        factory = self._session_factory or get_session_factory()
        return factory()

    def clear(self) -> None:
        with self._lock:
            self._memory_incidents.clear()

    def save(self, incident: Incident) -> Incident:
        """Persists or updates an incident record."""
        now = datetime.now(UTC)
        with self._lock:
            self._memory_incidents[incident.id] = incident

            try:
                with self._get_session() as session:
                    rec = session.query(IncidentRecord).filter_by(id=incident.id).first()
                    timeline_dicts = [t.model_dump(mode="json") for t in incident.timeline]
                    checklist_dicts = [c.model_dump(mode="json") for c in incident.checklist]
                    approval_dicts = [a.model_dump(mode="json") for a in incident.approvals]

                    if rec:
                        rec.status = incident.status.value
                        rec.severity = incident.severity
                        rec.contained_at = incident.contained_at
                        rec.time_to_contain_ms = incident.time_to_contain_ms
                        rec.resolved_at = incident.resolved_at
                        rec.timeline = timeline_dicts
                        rec.checklist = checklist_dicts
                        rec.approvals = approval_dicts
                        rec.escalation_level = incident.escalation_level
                        rec.acknowledged = incident.acknowledged
                        rec.acknowledged_at = incident.acknowledged_at
                        rec.acknowledged_by = incident.acknowledged_by
                        rec.updated_at = now
                    else:
                        rec = IncidentRecord(
                            id=incident.id,
                            trigger=incident.trigger,
                            status=incident.status.value,
                            severity=incident.severity,
                            runbook_id=incident.runbook_id,
                            detected_at=incident.detected_at,
                            contained_at=incident.contained_at,
                            time_to_contain_ms=incident.time_to_contain_ms,
                            resolved_at=incident.resolved_at,
                            timeline=timeline_dicts,
                            checklist=checklist_dicts,
                            approvals=approval_dicts,
                            escalation_level=incident.escalation_level,
                            acknowledged=incident.acknowledged,
                            acknowledged_at=incident.acknowledged_at,
                            acknowledged_by=incident.acknowledged_by,
                            data_label=incident.data_label.value if hasattr(incident.data_label, "value") else str(incident.data_label),
                            created_at=incident.detected_at,
                            updated_at=now,
                        )
                        session.add(rec)
                    session.commit()
            except Exception as exc:
                logger.debug("Database incident persistence bypassed: %s", exc)

        return incident

    def get(self, incident_id: str) -> Incident | None:
        """Retrieves an incident by its ID."""
        with self._lock:
            if incident_id in self._memory_incidents:
                return self._memory_incidents[incident_id]

            try:
                with self._get_session() as session:
                    rec = session.query(IncidentRecord).filter_by(id=incident_id).first()
                    if rec:
                        incident = self._record_to_model(rec)
                        self._memory_incidents[rec.id] = incident
                        return incident
            except Exception as exc:
                logger.debug("Database incident read bypassed: %s", exc)

        return None

    def list_all(
        self,
        status: str | None = None,
        trigger: str | None = None,
        limit: int = 50,
    ) -> list[Incident]:
        """Lists incidents sorted by detected_at descending."""
        with self._lock:
            # Sync with database if available
            try:
                with self._get_session() as session:
                    query = session.query(IncidentRecord)
                    if status:
                        query = query.filter_by(status=status)
                    if trigger:
                        query = query.filter_by(trigger=trigger)
                    records = query.order_by(IncidentRecord.detected_at.desc()).limit(limit).all()
                    for rec in records:
                        if rec.id not in self._memory_incidents:
                            self._memory_incidents[rec.id] = self._record_to_model(rec)
            except Exception as exc:
                logger.debug("Database incident listing bypassed: %s", exc)

            results = list(self._memory_incidents.values())
            if status:
                results = [i for i in results if i.status.value.upper() == status.upper()]
            if trigger:
                results = [i for i in results if i.trigger.upper() == trigger.upper()]

            results.sort(key=lambda i: i.detected_at, reverse=True)
            return results[:limit]

    def _record_to_model(self, rec: IncidentRecord) -> Incident:
        timeline = [TimelineEvent(**t) for t in (rec.timeline or [])]
        checklist = [ChecklistItem(**c) for c in (rec.checklist or [])]
        approvals = [IncidentApproval(**a) for a in (rec.approvals or [])]
        return Incident(
            id=rec.id,
            trigger=rec.trigger,
            status=IncidentStatus(rec.status),
            severity=rec.severity,
            runbook_id=rec.runbook_id,
            detected_at=rec.detected_at,
            contained_at=rec.contained_at,
            time_to_contain_ms=rec.time_to_contain_ms,
            resolved_at=rec.resolved_at,
            timeline=timeline,
            checklist=checklist,
            approvals=approvals,
            escalation_level=rec.escalation_level,
            acknowledged=rec.acknowledged,
            acknowledged_at=rec.acknowledged_at,
            acknowledged_by=rec.acknowledged_by,
            data_label=DataLabel(rec.data_label) if rec.data_label in DataLabel.__members__ else DataLabel.REAL,
        )


incident_store = IncidentStore()
