"""Pluggable AML taint and exposure provider interface (Milestone S27)."""

import logging
from abc import ABC, abstractmethod

logger = logging.getLogger("bitguard.profiler.provider")


class TaintProvider(ABC):
    """Abstract interface for external AML, compliance, and taint scoring providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the provider vendor (e.g. Chainalysis, Elliptic, TRM)."""
        ...

    @abstractmethod
    def get_taint_score(self, chain: str, address: str) -> float:
        """Returns taint / risk exposure score between 0.0 (clean) and 100.0 (severe taint).

        Note: Invoked out-of-band by the ProfileWorker, never on the signing path.
        """
        ...


class MockTaintProvider(TaintProvider):
    """Configurable mock provider for testing and deterministic lab simulations."""

    def __init__(self, default_score: float = 0.0) -> None:
        self._scores: dict[str, float] = {}
        self._default_score = default_score

    @property
    def name(self) -> str:
        return "mock"

    def set_address_taint(self, address: str, score: float) -> None:
        """Configures test fixture taint score for a normalized address."""
        self._scores[address.lower()] = max(0.0, min(100.0, score))

    def clear(self) -> None:
        self._scores.clear()

    def get_taint_score(self, chain: str, address: str) -> float:
        return self._scores.get(address.lower(), self._default_score)
