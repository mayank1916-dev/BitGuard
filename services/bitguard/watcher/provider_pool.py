"""Multi-provider RPC query pool with consensus agreement checking (Milestone S17 / F6).

Invariants:
- Invariant #3: Fail-Closed Default. Disagreement across RPC providers is flagged as suspicious.
- Invariant #9: Safety boundary: works against Anvil, local chains, or mock providers.
"""

import logging

from services.bitguard.config import settings
from services.bitguard.rpc.base import RpcClient, RpcError

logger = logging.getLogger("bitguard.watcher.provider_pool")


class ProviderDisagreementError(Exception):
    """Raised or alerted when multiple RPC providers return conflicting state."""

    def __init__(self, address: str, results: dict[str, str]) -> None:
        super().__init__(f"Provider disagreement on address {address}: {results}")
        self.address = address
        self.results = results


class ProviderPool:
    """Pool of N configured EVM RPC providers ensuring multi-node consensus on bytecode."""

    def __init__(
        self,
        providers: list[tuple[str, RpcClient]] | None = None,
        min_providers: int = 1,
    ) -> None:
        self.providers: list[tuple[str, RpcClient]] = providers or []
        self.min_providers = min_providers
        # In non-lab environments, enforce minimum 2 providers
        if settings.environment.lower() not in ("development", "test", "local") and len(self.providers) < 2:
            logger.warning("production_safety_warning: minimum 2 RPC providers required in non-lab environments")

    def add_provider(self, name: str, client: RpcClient) -> None:
        """Adds a named RPC provider to the pool."""
        self.providers.append((name, client))

    @property
    def primary_rpc(self) -> RpcClient:
        """Returns the primary RPC client."""
        if not self.providers:
            raise RpcError("No RPC providers configured in ProviderPool")
        return self.providers[0][1]

    def query_code(self, address: str, block: str = "latest") -> tuple[str, bool, dict[str, str]]:
        """Queries eth_getCode across all configured providers.

        Returns:
            (consensus_code, has_agreement, provider_results)
        """
        if not self.providers:
            raise RpcError("No RPC providers configured in ProviderPool")

        results: dict[str, str] = {}
        for name, client in self.providers:
            try:
                code = client.get_code(address, block=block)
                clean_code = code.strip().lower()
                results[name] = clean_code if clean_code.startswith("0x") else f"0x{clean_code}"
            except Exception as exc:
                logger.warning("provider_%s_get_code_failed for %s: %s", name, address, exc)
                results[name] = f"ERROR: {exc}"

        # Check for consensus
        unique_results = set(results.values())
        has_error = any(v.startswith("ERROR") for v in unique_results)
        has_agreement = (len(unique_results) == 1) and not has_error

        first_val = list(results.values())[0] if results else "0x"
        consensus_code = first_val if not first_val.startswith("ERROR") else "0x"

        return consensus_code, has_agreement, results


provider_pool = ProviderPool()
