"""Circuit breaker state store interface and in-memory stub (Milestone S10 / F5 hook)."""

import threading
from abc import ABC, abstractmethod

from services.bitguard.models import BreakerStateEnum


class BreakerStore(ABC):
    """Abstract store for querying circuit breaker operational condition."""

    @abstractmethod
    def get_state(self) -> BreakerStateEnum:
        """Returns the active circuit breaker state: NORMAL, ELEVATED, HOLD, or LOCKDOWN."""
        ...

    @abstractmethod
    def set_state(self, state: BreakerStateEnum, reason: str = "") -> None:
        """Updates the circuit breaker state (administrative or automated)."""
        ...


class MemoryBreakerStore(BreakerStore):
    """Thread-safe in-memory circuit breaker store."""

    def __init__(self, initial_state: BreakerStateEnum = BreakerStateEnum.NORMAL) -> None:
        self._lock = threading.Lock()
        self._state: BreakerStateEnum = initial_state
        self._reason: str = "Initial nominal operational state"

    def get_state(self) -> BreakerStateEnum:
        with self._lock:
            return self._state

    def set_state(self, state: BreakerStateEnum, reason: str = "") -> None:
        with self._lock:
            self._state = state
            self._reason = reason

    def reset(self) -> None:
        with self._lock:
            self._state = BreakerStateEnum.NORMAL
            self._reason = "Reset to NORMAL"


# Default singleton breaker store
breaker_store = MemoryBreakerStore()
