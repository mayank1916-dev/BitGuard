"""FastAPI router exposing JSON-RPC 2.0 endpoints for BitGuard Gateway (Milestone S12)."""

import json
import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from services.bitguard.gateway.handler import gateway_handler
from services.bitguard.gateway.models import (
    JsonRpcError,
    JsonRpcResponse,
)

logger = logging.getLogger("bitguard.gateway.router")

router = APIRouter(tags=["JSON-RPC Gateway"])


@router.post(
    "/rpc",
    response_model=JsonRpcResponse,
    summary="JSON-RPC 2.0 Transaction Signing Gateway",
    description=(
        "Production JSON-RPC 2.0 interface for custodial signing requests. "
        "Method 'bitguard_signTransaction' executes the 6-stage policy pipeline "
        "(decode -> intent -> delegation -> limits -> enrichment -> decide) under mTLS caller authentication. "
        "ALLOW returns the signature; HOLD returns error -32004; DENY returns error -32003."
    ),
)
async def json_rpc_endpoint(request: Request) -> Any:
    """Primary JSON-RPC 2.0 entrypoint handling 'bitguard_signTransaction'."""
    try:
        raw_body = await request.body()
        if not raw_body:
            return JSONResponse(
                status_code=200,
                content=JsonRpcResponse(
                    jsonrpc="2.0",
                    error=JsonRpcError(code=-32700, message="Parse error: request body is empty"),
                    id=None,
                ).model_dump(),
            )
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception as exc:
        logger.warning("json_rpc_parse_error: %s", exc)
        return JSONResponse(
            status_code=200,
            content=JsonRpcResponse(
                jsonrpc="2.0",
                error=JsonRpcError(code=-32700, message=f"Parse error: invalid JSON payload: {exc}"),
                id=None,
            ).model_dump(),
        )

    if not isinstance(payload, dict):
        return JSONResponse(
            status_code=200,
            content=JsonRpcResponse(
                jsonrpc="2.0",
                error=JsonRpcError(code=-32600, message="Invalid Request: JSON-RPC root must be an object"),
                id=None,
            ).model_dump(),
        )

    response = await gateway_handler.handle_rpc_request(request, payload)
    return JSONResponse(status_code=200, content=response.model_dump())
