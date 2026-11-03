"""Pluggable notification system for quarantine hold events (Milestone S16 / F10).

Invariants:
- Invariant #5: WebAuthn Hardware Approvals. Slack/Telegram/PagerDuty are notifications only
  and carry a link, never an approve button.
- Strict Wording: Messages contain ONLY a console link and a short non-actionable summary.
"""

import abc
import logging
from typing import Any

import httpx

from services.bitguard.models import HoldTicket

logger = logging.getLogger("bitguard.approvals.notifiers")

CONSOLE_BASE_URL = "https://console.bitguard.exchange"


class BaseNotifier(abc.ABC):
    """Abstract base class for BitGuard incident and hold notifiers."""

    @abc.abstractmethod
    async def send_notification(self, ticket: HoldTicket) -> bool:
        """Dispatches an informational hold notification containing link only."""
        raise NotImplementedError


class SlackNotifier(BaseNotifier):
    """Slack webhook notifier. Invariant #5: text and links only; NO approve buttons."""

    def __init__(self, webhook_url: str | None = None, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.webhook_url = webhook_url
        self.transport = transport
        self.sent_payloads: list[dict[str, Any]] = []

    def format_payload(self, ticket: HoldTicket) -> dict[str, Any]:
        console_link = f"{CONSOLE_BASE_URL}/holds/{ticket.id}"
        reasons_summary = ", ".join(r.code for r in ticket.reasons) or "Security policy hold"
        text = (
            f"🚨 *[BitGuard Notice]* Transaction placed on quarantine HOLD.\n"
            f"• Ticket: `{ticket.id}`\n"
            f"• Chain: `{ticket.chain}` | Amount: `${ticket.amount_usd:,.2f}`\n"
            f"• Risk Score: `{ticket.risk_score}`\n"
            f"• Reasons: {reasons_summary}\n"
            f"Review in BitGuard Console: {console_link}"
        )
        return {"text": text}

    async def send_notification(self, ticket: HoldTicket) -> bool:
        payload = self.format_payload(ticket)
        self.sent_payloads.append(payload)

        if not self.webhook_url:
            logger.info("Slack notification queued (mock/unconfigured): %s", ticket.id)
            return True

        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=5.0) as client:
                res = await client.post(self.webhook_url, json=payload)
                return res.status_code < 400
        except Exception as exc:
            logger.warning("failed_sending_slack_notification: %s", exc)
            return False


class TelegramNotifier(BaseNotifier):
    """Telegram bot notifier. Invariant #5: text message with link only; NO inline buttons."""

    def __init__(
        self,
        bot_token: str | None = None,
        chat_id: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.transport = transport
        self.sent_payloads: list[dict[str, Any]] = []

    def format_payload(self, ticket: HoldTicket) -> dict[str, Any]:
        console_link = f"{CONSOLE_BASE_URL}/holds/{ticket.id}"
        reasons_summary = ", ".join(r.code for r in ticket.reasons) or "Quarantine review"
        text = (
            f"🚨 *BitGuard Alert*: Quarantine HOLD on ticket `{ticket.id}`\n"
            f"Chain: {ticket.chain} | Amount: ${ticket.amount_usd:,.2f}\n"
            f"Reasons: {reasons_summary}\n"
            f"Console link: {console_link}"
        )
        return {
            "chat_id": self.chat_id or "default-chat",
            "text": text,
            "parse_mode": "Markdown",
        }

    async def send_notification(self, ticket: HoldTicket) -> bool:
        payload = self.format_payload(ticket)
        self.sent_payloads.append(payload)

        if not self.bot_token or not self.chat_id:
            logger.info("Telegram notification queued (mock/unconfigured): %s", ticket.id)
            return True

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=5.0) as client:
                res = await client.post(url, json=payload)
                return res.status_code < 400
        except Exception as exc:
            logger.warning("failed_sending_telegram_notification: %s", exc)
            return False


class PagerDutyNotifier(BaseNotifier):
    """PagerDuty Events API v2 notifier. Invariant #5: event trigger with link only."""

    def __init__(self, routing_key: str | None = None, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.routing_key = routing_key
        self.transport = transport
        self.sent_payloads: list[dict[str, Any]] = []

    def format_payload(self, ticket: HoldTicket) -> dict[str, Any]:
        console_link = f"{CONSOLE_BASE_URL}/holds/{ticket.id}"
        return {
            "routing_key": self.routing_key or "default-routing-key",
            "event_action": "trigger",
            "dedup_key": f"bitguard-hold-{ticket.id}",
            "payload": {
                "summary": f"BitGuard Quarantine HOLD on ticket {ticket.id} (${ticket.amount_usd:,.2f})",
                "severity": "warning",
                "source": "bitguard-decision-point",
                "custom_details": {
                    "hold_id": ticket.id,
                    "request_id": ticket.request_id,
                    "risk_score": ticket.risk_score,
                    "console_url": console_link,
                },
            },
            "links": [
                {
                    "href": console_link,
                    "text": "Review Transaction in BitGuard Console",
                }
            ],
        }

    async def send_notification(self, ticket: HoldTicket) -> bool:
        payload = self.format_payload(ticket)
        self.sent_payloads.append(payload)

        if not self.routing_key:
            logger.info("PagerDuty notification queued (mock/unconfigured): %s", ticket.id)
            return True

        url = "https://events.pagerduty.com/v2/enqueue"
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=5.0) as client:
                res = await client.post(url, json=payload)
                return res.status_code < 400
        except Exception as exc:
            logger.warning("failed_sending_pagerduty_notification: %s", exc)
            return False


class CompositeNotifier(BaseNotifier):
    """Broadcasts hold notifications to all registered channels."""

    def __init__(self, notifiers: list[BaseNotifier] | None = None) -> None:
        self.notifiers: list[BaseNotifier] = notifiers or [
            SlackNotifier(),
            TelegramNotifier(),
            PagerDutyNotifier(),
        ]

    async def send_notification(self, ticket: HoldTicket) -> bool:
        results = []
        for n in self.notifiers:
            res = await n.send_notification(ticket)
            results.append(res)
        return all(results)


notifier = CompositeNotifier()
