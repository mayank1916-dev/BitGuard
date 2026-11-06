"""Tiered escalation engine for incident notifications and on-call paging (Milestone S19 / F14).

Invariants:
- Invariant #5: WebAuthn Hardware Approvals. Paging messages contain deep links only, never approve buttons.
- Invariant #7: Immutable Audit Trail. Every escalation and acknowledgment appends to hash-chained audit log.
- Invariant #8: Explicit Data Provenance (data_label REAL).
"""

import asyncio
import logging
from datetime import UTC, datetime

from services.bitguard.audit_service import audit_service
from services.bitguard.config import settings
from services.bitguard.incidents.models import Incident, IncidentStatus, TimelineEvent
from services.bitguard.incidents.notifiers import oncall_notifier
from services.bitguard.incidents.store import incident_store
from services.bitguard.models import DataLabel
from services.bitguard.stream.broadcaster import stream_broadcaster

logger = logging.getLogger("bitguard.incidents.escalation")


class EscalationManager:
    """Monitors incident acknowledgment deadlines and triggers tiered escalation."""

    def __init__(self, ack_timeout_seconds: int | None = None) -> None:
        self.default_ack_timeout_seconds = (
            ack_timeout_seconds
            if ack_timeout_seconds is not None
            else getattr(settings, "oncall_ack_timeout_seconds", 300)
        )

    async def check_and_escalate_incidents(
        self,
        now: datetime | None = None,
        ack_timeout_seconds: int | None = None,
    ) -> list[Incident]:
        """Checks active incidents and escalates any unacknowledged incidents whose deadline expired."""
        current_time = now or datetime.now(UTC)
        timeout_sec = (
            ack_timeout_seconds
            if ack_timeout_seconds is not None
            else self.default_ack_timeout_seconds
        )

        escalated_incidents: list[Incident] = []
        active_incidents = incident_store.list_all()

        for inc in active_incidents:
            # Only escalate unacknowledged, unresolved incidents
            if inc.status == IncidentStatus.RESOLVED or inc.acknowledged:
                continue

            # Calculate deadline based on escalation_level
            elapsed = (current_time - inc.detected_at).total_seconds()
            required_threshold = timeout_sec * inc.escalation_level

            if elapsed >= required_threshold:
                inc.escalation_level += 1
                inc.status = IncidentStatus.ESCALATED

                escalation_msg = (
                    f"On-call acknowledgment timed out after {int(elapsed)}s. "
                    f"Escalated to Tier {inc.escalation_level}"
                )
                inc.timeline.append(
                    TimelineEvent(
                        event_type="INCIDENT_ESCALATED",
                        message=escalation_msg,
                        details={
                            "new_level": inc.escalation_level,
                            "elapsed_seconds": elapsed,
                            "threshold_seconds": required_threshold,
                        },
                    )
                )

                # Page next tier via configured notifiers (Slack, PagerDuty, mock)
                await oncall_notifier.page_oncall(
                    incident=inc,
                    level=inc.escalation_level,
                    message=f"Escalation Tier {inc.escalation_level}: incident {inc.id} unacknowledged",
                )

                # Append immutable audit entry
                audit_service.append_entry(
                    action=f"INCIDENT_ESCALATED:L{inc.escalation_level}",
                    actor="escalation_manager",
                    payload={
                        "incident_id": inc.id,
                        "level": inc.escalation_level,
                        "elapsed_seconds": elapsed,
                    },
                    data_label=DataLabel.REAL,
                )

                # Save and publish update
                incident_store.save(inc)
                stream_broadcaster.publish_event(
                    event_type="INCIDENT_UPDATE",
                    payload=inc.model_dump(mode="json"),
                    data_label="REAL",
                )

                escalated_incidents.append(inc)
                logger.warning(
                    "Incident %s unacknowledged after %.1fs. Escalated to tier %d",
                    inc.id,
                    elapsed,
                    inc.escalation_level,
                )

        return escalated_incidents

    def check_and_escalate_incidents_sync(
        self,
        now: datetime | None = None,
        ack_timeout_seconds: int | None = None,
    ) -> list[Incident]:
        """Synchronous wrapper for test harnesses and sync callers."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor() as pool:
                    return pool.submit(
                        asyncio.run,
                        self.check_and_escalate_incidents(now, ack_timeout_seconds),
                    ).result()
            return loop.run_until_complete(
                self.check_and_escalate_incidents(now, ack_timeout_seconds)
            )
        except Exception:
            return asyncio.run(
                self.check_and_escalate_incidents(now, ack_timeout_seconds)
            )

    async def acknowledge_incident(
        self,
        incident_id: str,
        acknowledged_by: str = "oncall_engineer",
    ) -> Incident:
        """Records on-call acknowledgment of the incident."""
        incident = incident_store.get(incident_id)
        if not incident:
            raise KeyError(f"Incident '{incident_id}' not found")

        if incident.acknowledged:
            return incident

        now = datetime.now(UTC)
        incident.acknowledged = True
        incident.acknowledged_at = now
        incident.acknowledged_by = acknowledged_by

        incident.timeline.append(
            TimelineEvent(
                event_type="ONCALL_ACKNOWLEDGED",
                message=f"Incident acknowledged by {acknowledged_by}",
                details={"acknowledged_by": acknowledged_by, "acknowledged_at": now.isoformat()},
            )
        )

        incident_store.save(incident)

        audit_service.append_entry(
            action="INCIDENT_ACKNOWLEDGED",
            actor=acknowledged_by,
            payload={"incident_id": incident.id},
            data_label=DataLabel.REAL,
        )

        stream_broadcaster.publish_event(
            event_type="INCIDENT_UPDATE",
            payload=incident.model_dump(mode="json"),
            data_label="REAL",
        )

        return incident

    async def manual_escalate(
        self,
        incident_id: str,
        reason: str = "Manual operator escalation",
        escalated_by: str = "operator",
    ) -> Incident:
        """Manually raises the escalation level of an incident."""
        incident = incident_store.get(incident_id)
        if not incident:
            raise KeyError(f"Incident '{incident_id}' not found")

        incident.escalation_level += 1
        incident.status = IncidentStatus.ESCALATED

        incident.timeline.append(
            TimelineEvent(
                event_type="INCIDENT_MANUAL_ESCALATED",
                message=f"Manually escalated to Tier {incident.escalation_level} by {escalated_by}: {reason}",
                details={
                    "level": incident.escalation_level,
                    "reason": reason,
                    "escalated_by": escalated_by,
                },
            )
        )

        await oncall_notifier.page_oncall(
            incident=incident,
            level=incident.escalation_level,
            message=f"Tier {incident.escalation_level} manual escalation: {reason}",
        )

        audit_service.append_entry(
            action=f"INCIDENT_MANUAL_ESCALATED:L{incident.escalation_level}",
            actor=escalated_by,
            payload={"incident_id": incident.id, "level": incident.escalation_level, "reason": reason},
            data_label=DataLabel.REAL,
        )

        incident_store.save(incident)
        stream_broadcaster.publish_event(
            event_type="INCIDENT_UPDATE",
            payload=incident.model_dump(mode="json"),
            data_label="REAL",
        )

        return incident


escalation_manager = EscalationManager()
