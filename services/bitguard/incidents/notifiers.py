"""Pluggable on-call notification and tiered escalation channels (Milestone S19 / F14).

Invariants:
- Invariant #5: WebAuthn Hardware Approvals. Notifications carry deep links only;
  NEVER inline approve buttons. Approvals require WebAuthn hardware keys in the console.
"""

import abc
import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from services.bitguard.config import settings
from services.bitguard.incidents.models import Incident

logger = logging.getLogger("bitguard.incidents.notifiers")

CONSOLE_BASE_URL = "https://console.bitguard.exchange"


class BaseOnCallNotifier(abc.ABC):
    """Abstract interface for incident on-call paging channels."""

    @abc.abstractmethod
    async def page_oncall(self, incident: Incident, level: int = 1, message: str = "") -> bool:
        """Dispatches an on-call page for an incident."""
        raise NotImplementedError


class SlackOnCallNotifier(BaseOnCallNotifier):
    """Slack webhook notifier. Invariant #5: text and links only; NO approve buttons."""

    def __init__(
        self,
        webhook_url: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.webhook_url = webhook_url or settings.oncall_slack_webhook
        self.transport = transport
        self.sent_payloads: list[dict[str, Any]] = []

    def format_payload(self, incident: Incident, level: int, message: str) -> dict[str, Any]:
        console_link = f"{CONSOLE_BASE_URL}/incidents/{incident.id}"
        time_to_contain_str = (
            f"{incident.time_to_contain_ms:.2f} ms"
            if incident.time_to_contain_ms is not None
            else "Pending containment"
        )
        text = (
            f"🚨 *[BitGuard Incident Alert - Level {level}]*\n"
            f"• Incident ID: `{incident.id}`\n"
            f"• Trigger: `{incident.trigger}` | Severity: `{incident.severity}`\n"
            f"• Status: `{incident.status}` | Time to Contain: `{time_to_contain_str}`\n"
            f"• Note: {message or 'Immediate on-call review required'}\n"
            f"Review in BitGuard Console: {console_link}"
        )
        return {"text": text, "level": level, "incident_id": incident.id}

    async def page_oncall(self, incident: Incident, level: int = 1, message: str = "") -> bool:
        payload = self.format_payload(incident, level, message)
        self.sent_payloads.append(payload)

        if not self.webhook_url:
            logger.info(
                "Slack on-call notification queued (mock/unconfigured): incident=%s level=%d",
                incident.id,
                level,
            )
            return True

        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=5.0) as client:
                res = await client.post(self.webhook_url, json=payload)
                return res.status_code < 400
        except Exception as exc:
            logger.warning("failed_sending_slack_oncall_page: %s", exc)
            return False


class PagerDutyOnCallNotifier(BaseOnCallNotifier):
    """PagerDuty Events API v2 notifier. Invariant #5: event trigger with link only."""

    def __init__(
        self,
        routing_key: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.routing_key = routing_key or settings.oncall_pagerduty_routing_key
        self.transport = transport
        self.sent_payloads: list[dict[str, Any]] = []

    def format_payload(self, incident: Incident, level: int, message: str) -> dict[str, Any]:
        console_link = f"{CONSOLE_BASE_URL}/incidents/{incident.id}"
        severity_map = {"CRITICAL": "critical", "HIGH": "error", "MEDIUM": "warning"}
        pd_severity = severity_map.get(incident.severity, "error")

        return {
            "routing_key": self.routing_key or "default-pagerduty-key",
            "event_action": "trigger",
            "dedup_key": f"bitguard-incident-{incident.id}-level-{level}",
            "payload": {
                "summary": f"[Level {level}] BitGuard Security Incident {incident.id} ({incident.trigger})",
                "severity": pd_severity,
                "source": "bitguard-runbook-engine",
                "custom_details": {
                    "incident_id": incident.id,
                    "trigger": incident.trigger,
                    "status": incident.status,
                    "level": level,
                    "time_to_contain_ms": incident.time_to_contain_ms,
                    "note": message,
                    "console_url": console_link,
                },
            },
            "links": [
                {
                    "href": console_link,
                    "text": "Review Incident in BitGuard Console",
                }
            ],
        }

    async def page_oncall(self, incident: Incident, level: int = 1, message: str = "") -> bool:
        payload = self.format_payload(incident, level, message)
        self.sent_payloads.append(payload)

        if not self.routing_key:
            logger.info(
                "PagerDuty on-call notification queued (mock/unconfigured): incident=%s level=%d",
                incident.id,
                level,
            )
            return True

        url = "https://events.pagerduty.com/v2/enqueue"
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=5.0) as client:
                res = await client.post(url, json=payload)
                return res.status_code < 400
        except Exception as exc:
            logger.warning("failed_sending_pagerduty_oncall_page: %s", exc)
            return False


class MockOnCallNotifier(BaseOnCallNotifier):
    """Test mock tracking all dispatched on-call pages and escalation levels in memory."""

    def __init__(self) -> None:
        self.dispatched_pages: list[dict[str, Any]] = []

    def clear(self) -> None:
        self.dispatched_pages.clear()

    async def page_oncall(self, incident: Incident, level: int = 1, message: str = "") -> bool:
        self.dispatched_pages.append({
            "incident_id": incident.id,
            "trigger": incident.trigger,
            "level": level,
            "message": message,
            "timestamp": datetime.now(UTC),
            "status": incident.status,
        })
        logger.info(
            "Mock on-call paged: incident=%s level=%d trigger=%s",
            incident.id,
            level,
            incident.trigger,
        )
        return True


class CompositeOnCallNotifier(BaseOnCallNotifier):
    """Broadcasts on-call alerts to all configured channels (Slack, PagerDuty, and test mocks)."""

    def __init__(self, notifiers: list[BaseOnCallNotifier] | None = None) -> None:
        self.mock_notifier = MockOnCallNotifier()
        self.notifiers: list[BaseOnCallNotifier] = notifiers or [
            SlackOnCallNotifier(),
            PagerDutyOnCallNotifier(),
            self.mock_notifier,
        ]

    def clear(self) -> None:
        self.mock_notifier.clear()

    async def page_oncall(self, incident: Incident, level: int = 1, message: str = "") -> bool:
        results = []
        for n in self.notifiers:
            res = await n.page_oncall(incident, level=level, message=message)
            results.append(res)
        return any(results)


# Global on-call notification dispatcher
oncall_notifier = CompositeOnCallNotifier()
