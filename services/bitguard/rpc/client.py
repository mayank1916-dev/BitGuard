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


class MockRpcClient(RpcClient):
    """In-memory mock RPC client for isolated unit testing and lab simulations."""

    def __init__(self) -> None:
        # address.lower() -> {"code": "0x...", "storage": {slot: "0x..."}}
        self._contracts: dict[str, dict[str, Any]] = {}
        self._should_fail: bool = False
        self._fail_message: str = "Simulated RPC failure"

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

    def reset(self) -> None:
        """Clears all mock contracts and resets failure state."""
        self._contracts.clear()
        self._should_fail = False
