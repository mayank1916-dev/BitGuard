"""Demo Custody Workload Client interacting with BitGuard JSON-RPC Gateway (Milestone S12).

Simulates an exchange custody service or automated withdrawal bot sending
unsigned transactions to BitGuard for firewall evaluation and signing.
"""

import logging
import uuid
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("lab.demo_custody")


class CustodyClientRpcError(Exception):
    """Exception raised when BitGuard JSON-RPC gateway returns an error response."""

    def __init__(self, code: int, message: str, data: dict[str, Any] | None = None) -> None:
        super().__init__(f"JSON-RPC Error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data or {}


class DemoCustodyClient:
    """Lightweight client for submitting transaction signing requests to BitGuard."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        cert_file: str | None = None,
        key_file: str | None = None,
        san: str = "spiffe://exchange.internal/workload/custody",
        timeout: float = 5.0,
        transport: httpx.BaseTransport | httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.cert_file = cert_file
        self.key_file = key_file
        self.san = san
        self.timeout = timeout
        self.transport = transport

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "X-Client-Cert-SAN": self.san,
        }
        if self.cert_file and Path(self.cert_file).exists():
            cert_pem = Path(self.cert_file).read_text(encoding="utf-8")
            headers["X-Client-Cert-Pem"] = cert_pem
        return headers

    def sign_transaction(
        self,
        chain: str,
        raw_tx: str,
        intent_id: str | None = None,
        amount_usd: float | None = None,
        wallet_group: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Synchronously submits a transaction signing request via JSON-RPC 2.0."""
        if isinstance(self.transport, httpx.ASGITransport):
            import asyncio
            return asyncio.run(
                self.sign_transaction_async(
                    chain=chain,
                    raw_tx=raw_tx,
                    intent_id=intent_id,
                    amount_usd=amount_usd,
                    wallet_group=wallet_group,
                    metadata=metadata,
                )
            )

        url = f"{self.base_url}/rpc"
        req_id = f"demo-{uuid.uuid4().hex[:8]}"

        payload = {
            "jsonrpc": "2.0",
            "method": "bitguard_signTransaction",
            "params": {
                "chain": chain,
                "raw_tx": raw_tx,
                "intent_id": intent_id,
                "amount_usd": amount_usd,
                "wallet_group": wallet_group,
                "metadata": metadata or {},
            },
            "id": req_id,
        }

        sync_transport = self.transport if isinstance(self.transport, httpx.BaseTransport) else None
        with httpx.Client(transport=sync_transport, timeout=self.timeout) as client:
            resp = client.post(url, json=payload, headers=self._build_headers())

        resp.raise_for_status()
        data = resp.json()

        if "error" in data and data["error"]:
            err = data["error"]
            raise CustodyClientRpcError(
                code=err.get("code", -32000),
                message=err.get("message", "Unknown RPC error"),
                data=err.get("data"),
            )

        return data.get("result", {})

    async def sign_transaction_async(
        self,
        chain: str,
        raw_tx: str,
        intent_id: str | None = None,
        amount_usd: float | None = None,
        wallet_group: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Asynchronously submits a transaction signing request via JSON-RPC 2.0."""
        url = f"{self.base_url}/rpc"
        req_id = f"demo-async-{uuid.uuid4().hex[:8]}"

        payload = {
            "jsonrpc": "2.0",
            "method": "bitguard_signTransaction",
            "params": {
                "chain": chain,
                "raw_tx": raw_tx,
                "intent_id": intent_id,
                "amount_usd": amount_usd,
                "wallet_group": wallet_group,
                "metadata": metadata or {},
            },
            "id": req_id,
        }

        async_transport = self.transport if isinstance(self.transport, httpx.AsyncBaseTransport) else None
        async with httpx.AsyncClient(transport=async_transport, timeout=self.timeout) as client:
            resp = await client.post(url, json=payload, headers=self._build_headers())

        resp.raise_for_status()
        data = resp.json()

        if "error" in data and data["error"]:
            err = data["error"]
            raise CustodyClientRpcError(
                code=err.get("code", -32000),
                message=err.get("message", "Unknown RPC error"),
                data=err.get("data"),
            )

        return data.get("result", {})
