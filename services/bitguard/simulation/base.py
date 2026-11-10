"""Abstract transaction simulation interface (Milestone S28 / F5)."""

from abc import ABC, abstractmethod

from services.bitguard.decoders.evm import DecodedTx
from services.bitguard.ledger.models import LedgerIntent
from services.bitguard.simulation.models import SimulationResult


class TransactionSimulator(ABC):
    """Abstract interface for pre-signing EVM transaction state simulation."""

    @abstractmethod
    def simulate(
        self,
        decoded_tx: DecodedTx,
        raw_tx: str,
        intent: LedgerIntent | None = None,
        watched_addresses: list[str] | None = None,
        timeout_ms: float = 300.0,
    ) -> SimulationResult:
        """Simulates raw transaction on a chain fork and computes balance deltas.

        Args:
            decoded_tx: Canonical decoded transaction fields.
            raw_tx: Hex string of raw unsigned transaction bytes.
            intent: Optional matching custody intent from the exchange ledger.
            watched_addresses: Additional monitored hot/cold addresses to track balance deltas for.
            timeout_ms: Maximum simulation deadline (default 300 ms on async path).

        Returns:
            SimulationResult containing balance deltas, revert status, and diagnostic flags.
        """
        ...
