"""Abstract interface for exchange custody ledger connectors (Milestone S08 / F2)."""

from abc import ABC, abstractmethod

from services.bitguard.ledger.models import WithdrawalIntent


class LedgerConnector(ABC):
    """Abstract connector to external custody and exchange ledger systems.

    Invariant #3 & #4: Fail-closed on missing ledger intent or store outage.
    Reads are strictly read-only and have zero side-effects.
    """

    @abstractmethod
    def get_intent(self, intent_id: str) -> WithdrawalIntent | None:
        """Retrieves a withdrawal intent by identifier.

        Must be idempotent and strictly read-only.
        Returns None if the intent does not exist or cannot be found.
        """
        ...

    @abstractmethod
    def mark_consumed(self, intent_id: str) -> bool:
        """Atomically marks a withdrawal intent as consumed/paid.

        Returns True if the intent was transitioned to consumed.
        Returns False if the intent was already consumed or does not exist.
        """
        ...

    @abstractmethod
    def is_consumed(self, intent_id: str) -> bool:
        """Checks if a withdrawal intent has already been consumed / replayed."""
        ...
