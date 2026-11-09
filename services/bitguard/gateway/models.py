"""Pydantic data models for JSON-RPC 2.0 Signing Gateway (Milestone S12).

Defines JSON-RPC envelopes, request parameters, success results, and
error structures adhering to JSON-RPC 2.0 specifications.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class JsonRpcRequest(BaseModel):
    """JSON-RPC 2.0 incoming request payload."""

    model_config = ConfigDict(extra="ignore")

    jsonrpc: str = Field(default="2.0", description="JSON-RPC protocol version")
    method: str = Field(description="Remote procedure method name")
    params: dict[str, Any] | list[Any] | None = Field(default=None, description="Method invocation parameters")
    id: str | int | None = Field(default=1, description="Client-assigned correlation identifier")


class SignTransactionParams(BaseModel):
    """Parameters for the 'bitguard_signTransaction' JSON-RPC method."""

    model_config = ConfigDict(extra="ignore")

    chain: str = Field(description="Target blockchain (e.g. ethereum-sepolia, base, optimism)")
    raw_tx: str = Field(description="Raw unsigned transaction payload hex string")
    intent_id: str | None = Field(default=None, description="Pre-registered custody withdrawal intent ID")
    amount_usd: float | None = Field(default=None, description="Optional USD equivalent transfer value")
    wallet_group: str | None = Field(default=None, description="Target wallet group (defaults to group mapped to wallet)")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Supplementary auditing metadata")


class JsonRpcError(BaseModel):
    """Standardized JSON-RPC 2.0 error object."""

    model_config = ConfigDict(extra="ignore")

    code: int = Field(description="Standard or application error code")
    message: str = Field(description="Short human-readable summary of the error")
    data: dict[str, Any] | None = Field(default=None, description="Structured diagnostics, decision reasons, or hold details")


class JsonRpcResponse(BaseModel):
    """Standardized JSON-RPC 2.0 response envelope."""

    model_config = ConfigDict(extra="ignore")

    jsonrpc: str = Field(default="2.0", description="JSON-RPC protocol version")
    result: Any | None = Field(default=None, description="Successful procedure result payload")
    error: JsonRpcError | None = Field(default=None, description="Error payload if procedure failed or denied")
    id: str | int | None = Field(default=None, description="Client-assigned correlation identifier echoed back")


class SignTransactionResult(BaseModel):
    """Successful signing result returned to the authorized caller."""

    model_config = ConfigDict(extra="ignore")

    signature: str = Field(description="Serialized ECDSA signature or signed raw transaction")
    tx_hash: str | None = Field(default=None, description="Computed transaction keccak256 hash")
    decision_id: str = Field(description="BitGuard decision request ID for auditing")
    status: str = Field(default="SIGNED", description="Signing execution status")
    timings: dict[str, float] = Field(default_factory=dict, description="Pipeline stage latency timings in milliseconds")
