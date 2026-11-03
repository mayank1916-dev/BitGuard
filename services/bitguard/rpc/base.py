"""Abstract RPC client interface for querying EVM chain state (Milestone S09)."""

from abc import ABC, abstractmethod


class RpcError(Exception):
    """Raised when an RPC request fails, times out, or returns an error."""

    pass


class RpcClient(ABC):
    """Abstract EVM JSON-RPC client."""

    @abstractmethod
    def get_code(self, address: str, block: str = "latest") -> str:
        """Retrieves bytecode deployed at the specified contract address.

        Returns hex string with '0x' prefix (e.g. '0x6080...').
        Returns '0x' if the address is an EOA or not deployed.
        Raises RpcError on connection or node errors.
        """
        ...

    @abstractmethod
    def get_storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        """Retrieves 32-byte storage value at the given slot for the specified address.

        Returns 32-byte hex string with '0x' prefix.
        Raises RpcError on connection or node errors.
        """
        ...

    @abstractmethod
    def get_block_number(self) -> int:
        """Retrieves current block number from the chain node."""
        ...

    @abstractmethod
    def get_block_by_number(self, block_number: int | str, full_transactions: bool = True) -> dict[str, object]:
        """Retrieves block payload including transactions."""
        ...

    @abstractmethod
    def get_transaction_count(self, address: str, block: str = "latest") -> int:
        """Retrieves the transaction count (nonce) of the specified address."""
        ...
