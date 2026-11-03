"""Mock implementation of LedgerConnector for testing and local operation (Milestone S08 / F2)."""

import logging
import threading
from datetime import UTC, datetime

import httpx

from services.bitguard.config import settings
from services.bitguard.ledger.base import LedgerConnector
from services.bitguard.ledger.models import IntentStatus, WithdrawalIntent

logger = logging.getLogger("bitguard.mock_ledger")


class MockLedgerConnector(LedgerConnector):
    """Thread-safe mock ledger connector providing read-only queries and atomic consumption tracking."""

    def __init__(self, ledger_url: str | None = None) -> None:
        self._ledger_url = ledger_url or settings.ledger_mock_url
        self._lock = threading.Lock()
        self._intents: dict[str, WithdrawalIntent] = {}
        self._consumed_ids: set[str] = set()

    def register_intent(self, intent: WithdrawalIntent) -> WithdrawalIntent:
        """Adds or updates an intent in the local in-memory store (test utility)."""
        with self._lock:
            self._intents[intent.id] = intent.model_copy()
            return self._intents[intent.id]

    def approve_intent(self, intent_id: str) -> bool:
        """Approves a pending intent in the local store (test utility)."""
        with self._lock:
            intent = self._intents.get(intent_id)
            if not intent:
                return False
            if intent.status in [IntentStatus.PAID.value, IntentStatus.CANCELLED.value]:
                return False
            intent.status = IntentStatus.APPROVED.value
            return True

    def get_intent(self, intent_id: str) -> WithdrawalIntent | None:
        """Read-only intent lookup. Checks in-memory store first, falls back to HTTP service if configured."""
        if not intent_id:
            return None

        with self._lock:
            intent = self._intents.get(intent_id)
            if intent is not None:
                return intent.model_copy()

        # Optional HTTP lookup to Ledger Mock service
        if self._ledger_url:
            try:
                resp = httpx.get(f"{self._ledger_url}/intents/{intent_id}", timeout=2.0)
                if resp.status_code == 200:
                    data = resp.json()
                    intent = WithdrawalIntent.model_validate(data)
                    with self._lock:
                        self._intents[intent_id] = intent
                    return intent.model_copy()
            except Exception as exc:
                logger.debug("remote_ledger_lookup_failed: %s", exc)

        return None

    def mark_consumed(self, intent_id: str) -> bool:
        """Atomically marks intent as consumed (idempotency enforcement)."""
        if not intent_id:
            return False

        with self._lock:
            if intent_id in self._consumed_ids:
                return False

            intent = self._intents.get(intent_id)
            if intent and intent.status == IntentStatus.PAID.value:
                self._consumed_ids.add(intent_id)
                return False

            self._consumed_ids.add(intent_id)
            if intent:
                intent.status = IntentStatus.PAID.value
                intent.consumed_at = datetime.now(UTC)

        # Notify remote service if configured
        if self._ledger_url:
            try:
                httpx.post(f"{self._ledger_url}/intents/{intent_id}/consume", timeout=2.0)
            except Exception as exc:
                logger.debug("remote_ledger_consume_failed: %s", exc)

        return True

    def is_consumed(self, intent_id: str) -> bool:
        """Checks if the intent has already been consumed / replayed."""
        if not intent_id:
            return False

        with self._lock:
            return intent_id in self._consumed_ids

    def reset(self) -> None:
        """Resets local state (test utility)."""
        with self._lock:
            self._intents.clear()
            self._consumed_ids.clear()


# Default singleton instance
mock_ledger_connector = MockLedgerConnector()
