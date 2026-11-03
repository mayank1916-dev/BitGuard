"""SIEM log exporter for BitGuard audit events (Milestone S21 / F18).

Supports RFC 5424 Syslog and OpenTelemetry LogRecord formats.
Off by default, configurable via settings (audit_siem_enabled).
"""

import logging
import socket
from datetime import UTC, datetime
from typing import Any

import httpx

from services.bitguard.audit.canonical import canonical_json
from services.bitguard.config import settings

logger = logging.getLogger("bitguard.audit.siem")


class SiemExporter:
    """Exports structured audit records to corporate SIEM solutions."""

    def __init__(self) -> None:
        self.enabled: bool = getattr(settings, "audit_siem_enabled", False)
        self.format: str = getattr(settings, "audit_siem_format", "syslog")
        self.syslog_host: str = getattr(settings, "audit_siem_syslog_host", "localhost")
        self.syslog_port: int = getattr(settings, "audit_siem_syslog_port", 514)
        self.otel_endpoint: str = getattr(settings, "audit_siem_otel_endpoint", "http://localhost:4318/v1/logs")

    def format_rfc5424(self, entry: dict[str, Any]) -> str:
        """Formats audit entry into RFC 5424 Syslog message.

        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROC-ID MSG-ID STRUCTURED-DATA MSG
        """
        # Facility local0 (16), severity Notice (5) -> PRI = 16*8 + 5 = 133
        pri = 133
        iso_ts = datetime.fromtimestamp(entry.get("ts", 0), tz=UTC).isoformat()
        hostname = socket.gethostname() or "bitguard-host"
        app_name = "bitguard"
        proc_id = "firewall"
        msg_id = "AUDIT"

        sd = (
            f'[bitguard@52834 seq="{entry.get("seq")}" '
            f'action="{entry.get("action")}" '
            f'actor="{entry.get("actor")}" '
            f'entry_hash="{entry.get("entry_hash")}"]'
        )
        body = canonical_json(entry.get("payload", {}))
        return f"<{pri}>1 {iso_ts} {hostname} {app_name} {proc_id} {msg_id} {sd} {body}\n"

    def format_otel_log_record(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Formats audit entry into OpenTelemetry Logs Data Model (OTLP)."""
        time_nano = int(entry.get("ts", 0) * 1e9)
        return {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "bitguard"}},
                            {"key": "service.namespace", "value": {"stringValue": "firewall"}},
                        ]
                    },
                    "scopeLogs": [
                        {
                            "scope": {"name": "bitguard.audit"},
                            "logRecords": [
                                {
                                    "timeUnixNano": str(time_nano),
                                    "observedTimeUnixNano": str(time_nano),
                                    "severityNumber": 9,  # INFO
                                    "severityText": "INFO",
                                    "body": {"stringValue": canonical_json(entry)},
                                    "attributes": [
                                        {"key": "audit.seq", "value": {"intValue": entry.get("seq", 0)}},
                                        {"key": "audit.action", "value": {"stringValue": str(entry.get("action", ""))}},
                                        {"key": "audit.actor", "value": {"stringValue": str(entry.get("actor", ""))}},
                                        {"key": "audit.entry_hash", "value": {"stringValue": str(entry.get("entry_hash", ""))}},
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }

    def export(self, entry: dict[str, Any]) -> None:
        """Dispatches audit entry to configured SIEM destination (fail-safe)."""
        if not self.enabled:
            return

        try:
            if self.format in ["syslog", "both"]:
                msg = self.format_rfc5424(entry)
                # Send via UDP socket (RFC 5426)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(0.5)
                    sock.sendto(msg.encode("utf-8"), (self.syslog_host, self.syslog_port))
        except Exception as exc:
            logger.debug("siem_syslog_export_failed: %s", exc)

        try:
            if self.format in ["otel", "both"]:
                payload = self.format_otel_log_record(entry)
                with httpx.Client(timeout=0.5) as client:
                    client.post(self.otel_endpoint, json=payload)
        except Exception as exc:
            logger.debug("siem_otel_export_failed: %s", exc)


siem_exporter = SiemExporter()
