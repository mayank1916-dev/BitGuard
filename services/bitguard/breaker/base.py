"""Abstract interface for Circuit Breaker state stores."""

from abc import ABC, abstractmethod

from services.bitguard.models import BreakerStateEnum


class BreakerStore(ABC):
    """Abstract store for querying and updating circuit breaker operational condition."""

    @abstractmethod
    def get_state(self) -> BreakerStateEnum:
        """Returns the active circuit breaker state: NORMAL, ELEVATED, HOLD, or LOCKDOWN."""
        ...

    @abstractmethod
    def set_state(self, state: BreakerStateEnum, reason: str = "") -> None:
        """Updates the circuit breaker state (administrative or automated)."""
        ...

    @abstractmethod
    def reset(self) -> None:
        """Resets the circuit breaker state to nominal."""
        ...
