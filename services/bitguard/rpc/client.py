"""HTTP and mock implementations of RpcClient (Milestone S09)."""

import logging
from typing import Any

import httpx

from services.bitguard.rpc.base import RpcClient, RpcError

logger = logging.getLogger("bitguard.rpc")


class HttpRpcClient(RpcClient):
    """Production JSON-RPC client querying EVM nodes (e.g. Foundry Anvil or public RPCs)."""

    def __init__(self, rpc_url: str, timeout: float = 3.0) -> None:
        self.rpc_url = rpc_url
        self.timeout = timeout

    def _call(self, method: str, params: list[Any]) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(self.rpc_url, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.warning("rpc_call_failed method=%s url=%s: %s", method, self.rpc_url, exc)
            raise RpcError(f"RPC call to {self.rpc_url} failed: {exc}") from exc

        if "error" in data:
            err = data["error"]
            raise RpcError(f"RPC returned error: {err}")

        return data.get("result", "0x")

    def get_code(self, address: str, block: str = "latest") -> str:
        """Calls eth_getCode."""
        result = self._call("eth_getCode", [address, block])
        if not isinstance(result, str):
            raise RpcError(f"Expected string result from eth_getCode, got {type(result)}")
        return result

    def get_storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        """Calls eth_getStorageAt."""
        # Ensure slot is 32-byte hex string
        clean_slot = slot if slot.startswith("0x") else f"0x{slot}"
        result = self._call("eth_getStorageAt", [address, clean_slot, block])
        if not isinstance(result, str):
            raise RpcError(f"Expected string result from eth_getStorageAt, got {type(result)}")
        return result

    def get_block_number(self) -> int:
        """Calls eth_blockNumber."""
        result = self._call("eth_blockNumber", [])
        if not isinstance(result, str):
            raise RpcError(f"Expected hex string result from eth_blockNumber, got {type(result)}")
        return int(result, 16)

    def get_block_by_number(self, block_number: int | str, full_transactions: bool = True) -> dict[str, Any]:
        """Calls eth_getBlockByNumber."""
        tag = hex(block_number) if isinstance(block_number, int) else block_number
        result = self._call("eth_getBlockByNumber", [tag, full_transactions])
        if not isinstance(result, dict):
            raise RpcError(f"Expected dict result from eth_getBlockByNumber, got {type(result)}")
        return result

    def get_transaction_count(self, address: str, block: str = "latest") -> int:
        """Calls eth_getTransactionCount."""
        result = self._call("eth_getTransactionCount", [address, block])
        if not isinstance(result, str):
            raise RpcError(f"Expected hex string result from eth_getTransactionCount, got {type(result)}")
        return int(result, 16)

    def get_balance(self, address: str, block: str = "latest") -> int:
        """Calls eth_getBalance."""
        result = self._call("eth_getBalance", [address, block])
        if not isinstance(result, str):
            raise RpcError(f"Expected hex string result from eth_getBalance, got {type(result)}")
        return int(result, 16)

    def call(self, method: str, params: list[Any]) -> Any:
        """Executes generic JSON-RPC call."""
        return self._call(method, params)


class MockRpcClient(RpcClient):
    """In-memory mock RPC client for isolated unit testing and lab simulations."""

    def __init__(self) -> None:
        # address.lower() -> {"code": "0x...", "storage": {slot: "0x..."}}
        self._contracts: dict[str, dict[str, Any]] = {}
        self._blocks: dict[int, dict[str, Any]] = {}
        self._nonces: dict[str, int] = {}
        self._balances: dict[str, int] = {}
        self._call_handlers: dict[str, Any] = {}
        self._latest_block: int = 100
        self._should_fail: bool = False
        self._fail_message: str = "Simulated RPC failure"

    def set_balance(self, address: str, balance_wei: int) -> None:
        """Configures mock native balance for an address."""
        self._balances[address.lower()] = balance_wei

    def set_call_handler(self, method: str, handler: Any) -> None:
        """Registers a custom handler for JSON-RPC methods."""
        self._call_handlers[method] = handler

    def set_contract(
        self,
        address: str,
        code: str,
        storage: dict[str, str] | None = None,
    ) -> None:
        """Registers bytecode and storage for a contract address."""
        self._contracts[address.lower()] = {
            "code": code if code.startswith("0x") else f"0x{code}",
            "storage": {
                k.lower(): v if v.startswith("0x") else f"0x{v}"
                for k, v in (storage or {}).items()
            },
        }

    def set_nonce(self, address: str, nonce: int) -> None:
        """Sets the current transaction count for an address."""
        self._nonces[address.lower()] = nonce

    def set_latest_block(self, number: int) -> None:
        """Updates the mock node's latest block height."""
        self._latest_block = number

    def add_block(
        self,
        number: int,
        timestamp: float,
        transactions: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Adds a block with optional transactions to the mock node."""
        block_data = {
            "number": hex(number),
            "timestamp": hex(int(timestamp)),
            "transactions": transactions or [],
        }
        self._blocks[number] = block_data
        if number > self._latest_block:
            self._latest_block = number
        return block_data

    def set_fail_rpc(self, should_fail: bool = True, error_msg: str = "Simulated RPC failure") -> None:
        """Forces the mock client to simulate RPC failure (fail-closed testing)."""
        self._should_fail = should_fail
        self._fail_message = error_msg

    def get_code(self, address: str, block: str = "latest") -> str:
        if self._should_fail:
            raise RpcError(self._fail_message)

        contract = self._contracts.get(address.lower())
        if contract is not None:
            return contract["code"]
        return "0x"

    def get_storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        if self._should_fail:
            raise RpcError(self._fail_message)

        contract = self._contracts.get(address.lower())
        if contract is not None:
            clean_slot = slot.lower() if slot.startswith("0x") else f"0x{slot.lower()}"
            return contract["storage"].get(
                clean_slot,
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
        return "0x0000000000000000000000000000000000000000000000000000000000000000"

    def get_block_number(self) -> int:
        if self._should_fail:
            raise RpcError(self._fail_message)
        return self._latest_block

    def get_block_by_number(self, block_number: int | str, full_transactions: bool = True) -> dict[str, Any]:
        if self._should_fail:
            raise RpcError(self._fail_message)

        num = (
            self._latest_block
            if block_number == "latest"
            else int(block_number, 16)
            if isinstance(block_number, str) and block_number.startswith("0x")
            else int(block_number)
        )
        if num in self._blocks:
            return self._blocks[num]
        return {
            "number": hex(num),
            "timestamp": hex(1730000000 + num * 12),
            "transactions": [],
        }

    def get_transaction_count(self, address: str, block: str = "latest") -> int:
        if self._should_fail:
            raise RpcError(self._fail_message)
        return self._nonces.get(address.lower(), 0)

    def get_balance(self, address: str, block: str = "latest") -> int:
        if self._should_fail:
            raise RpcError(self._fail_message)
        return self._balances.get(address.lower(), 10**18)  # Default 1 ETH

    def call(self, method: str, params: list[Any]) -> Any:
        if self._should_fail:
            raise RpcError(self._fail_message)
        if method in self._call_handlers:
            return self._call_handlers[method](params)
        if method == "eth_call":
            return "0x"
        if method == "eth_getBalance":
            addr = str(params[0]) if params else ""
            return hex(self.get_balance(addr))
        if method in ("anvil_dumpState", "evm_snapshot"):
            return "0x1"
        if method in ("anvil_loadState", "evm_revert"):
            return True
        return "0x"

    def reset(self) -> None:
        """Clears all mock contracts and resets failure state."""
        self._contracts.clear()
        self._blocks.clear()
        self._nonces.clear()
        self._balances.clear()
        self._call_handlers.clear()
        self._latest_block = 100
        self._should_fail = False
