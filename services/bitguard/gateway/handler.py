"""Request lifecycle handler for JSON-RPC 2.0 Signing Gateway (Milestone S12).

Invariants:
- Invariant #1: Key Isolation: BitGuard never stores signing keys.
- Invariant #2: Approval Binding: The signer signs only when given a one-time
  BitGuard approval token bound to tx digest, wallet, chain, expiry (~60 s), and nonce.
- Invariant #3: Fail-Closed Default: Unknown format, missing intent, store outage,
  unknown caller => DENY (-32003). Any internal error => DENY (ENGINE_ERROR).
- Invariant #4: Raw Byte Source of Truth: Always decode from raw transaction bytes.
- Invariant #7: Immutable Audit Trail: Every decision, approval, and rejection is recorded.
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request

from services.bitguard.audit_service import audit_service
from services.bitguard.engine.pipeline import decision_engine
from services.bitguard.gateway.client_shim import ShimRefusalError, signer_shim_client
from services.bitguard.gateway.models import (
    JsonRpcError,
    JsonRpcResponse,
    SignTransactionParams,
    SignTransactionResult,
)
from services.bitguard.gateway.mtls import extract_workload_identity
from services.bitguard.limits.store import limit_store
from services.bitguard.mode_service import mode_service
from services.bitguard.models import (
    HoldTicket,
    SigningRequest,
    Verdict,
)
from services.bitguard.tokens import token_manager

logger = logging.getLogger("bitguard.gateway.handler")

# In-memory quarantine store placeholder for HOLD tickets (Milestone S12 placeholder, expanded in S14)
quarantine_store: dict[str, HoldTicket] = {}


class GatewayHandler:
    """Coordinates the full 8-step lifecycle of signing gateway requests."""

    def __init__(self, shim_client=None) -> None:
        self.shim_client = shim_client or signer_shim_client

    async def handle_rpc_request(self, request: Request, payload: dict[str, Any]) -> JsonRpcResponse:
        """Processes an incoming JSON-RPC 2.0 request."""
        rpc_id: str | int | None = payload.get("id")

        # Step 1: Validate JSON-RPC 2.0 method
        method = payload.get("method")
        if method != "bitguard_signTransaction":
            return JsonRpcResponse(
                jsonrpc="2.0",
                error=JsonRpcError(
                    code=-32601,
                    message=f"Method '{method}' not found. Supported methods: ['bitguard_signTransaction']",
                ),
                id=rpc_id,
            )

        # Step 2: Validate method parameters
        raw_params = payload.get("params")
        if not isinstance(raw_params, dict):
            return JsonRpcResponse(
                jsonrpc="2.0",
                error=JsonRpcError(
                    code=-32602,
                    message="Invalid params: object with 'chain' and 'raw_tx' is required",
                ),
                id=rpc_id,
            )

        try:
            params = SignTransactionParams.model_validate(raw_params)
        except Exception as exc:
            return JsonRpcResponse(
                jsonrpc="2.0",
                error=JsonRpcError(
                    code=-32602,
                    message=f"Invalid params: {exc}",
                ),
                id=rpc_id,
            )

        # Step 3: Authenticate caller by mTLS client certificate / SAN
        workload_identity = extract_workload_identity(request)
        if workload_identity is None:
            unauth_id = f"unauth-{uuid.uuid4().hex[:12]}"
            logger.warning("signing_gateway_unauthenticated_caller_denied: id=%s", unauth_id)
            return JsonRpcResponse(
                jsonrpc="2.0",
                error=JsonRpcError(
                    code=-32003,
                    message="Signing request DENIED: unauthenticated caller",
                    data={
                        "decision_id": unauth_id,
                        "reasons": [
                            {
                                "code": "INVALID_CALLER_IDENTITY",
                                "weight": 100,
                                "detail": "Missing, invalid, or unauthorized mTLS client certificate workload identity",
                            }
                        ],
                        "risk_score": 100,
                    },
                ),
                id=rpc_id,
            )

        request_id = f"req-{uuid.uuid4().hex[:12]}"
        reservation_id: str | None = None

        try:
            # Step 4: Resolve wallet group
            wallet_group = mode_service.get_wallet_group(params.wallet_group or "default")

            # Step 5: Construct SigningRequest
            signing_req = SigningRequest(
                id=request_id,
                chain=params.chain,
                raw_tx=params.raw_tx,
                wallet="0x0000000000000000000000000000000000000000",  # Decoded from raw bytes in Stage 1
                wallet_group=wallet_group.id,
                intent_id=params.intent_id,
                metadata={
                    "amount_usd": params.amount_usd or 0.0,
                    "caller_identity": workload_identity.san,
                    **(params.metadata or {}),
                },
            )

            # Step 6: Execute 6-stage decision engine (decode -> intent -> delegation -> limits -> enrichment -> decide)
            decision = decision_engine.evaluate(
                request=signing_req,
                is_dry_run=False,
                wallet_group_mode=wallet_group.mode,
                wallet_group_id=wallet_group.id,
            )
            reservation_id = decision.reservation_id

            # Step 7: Handle verdict branches
            # ---------------------------------------------------------
            # Branch A: ALLOW
            # ---------------------------------------------------------
            if decision.verdict == Verdict.ALLOW:
                if decision.decoded_tx is None:
                    raise RuntimeError("Decoded transaction missing on ALLOW decision")

                # Issue one-time Ed25519 approval token
                wallet = decision.decoded_tx.from_address
                chain = decision.decoded_tx.chain
                token = token_manager.issue(
                    decoded_tx=decision.decoded_tx,
                    wallet=wallet,
                    chain=chain,
                )

                # Invoke Signer Shim enforcement point
                shim_res = await self.shim_client.sign(
                    raw_tx_bytes=params.raw_tx,
                    token=token,
                    wallet=wallet,
                    chain=chain,
                )

                # Commit atomic limit reservation upon confirmed signing
                if reservation_id:
                    try:
                        limit_store.commit(reservation_id)
                    except Exception as exc:
                        logger.warning("failed_committing_limit_reservation: %s", exc)

                # Record decision and signing in audit trail
                audit_service.append_entry(
                    event_type="TRANSACTION_SIGNED",
                    request_id=decision.request_id,
                    verdict="ALLOW",
                    data_label=decision.data_label,
                )

                result_data = SignTransactionResult(
                    signature=shim_res["signature"],
                    tx_hash=shim_res.get("tx_hash"),
                    decision_id=decision.request_id,
                    status="SIGNED",
                )
                return JsonRpcResponse(
                    jsonrpc="2.0",
                    result=result_data.model_dump(),
                    id=rpc_id,
                )

            # ---------------------------------------------------------
            # Branch B: HOLD (Quarantine placeholder for S14)
            # ---------------------------------------------------------
            if decision.verdict == Verdict.HOLD:
                if reservation_id:
                    limit_store.release(reservation_id)

                hold_id = f"ht-{decision.request_id}"
                digest = decision.decoded_tx.digest if decision.decoded_tx else "0x" + "0" * 64
                hold_ticket = HoldTicket(
                    id=hold_id,
                    request_id=decision.request_id,
                    tx_digest=digest,
                    reasons=decision.reasons,
                    status="PENDING",
                    expires_at=datetime.now(UTC) + timedelta(minutes=15),
                    created_at=datetime.now(UTC),
                )
                quarantine_store[hold_id] = hold_ticket

                audit_service.append_entry(
                    event_type="QUARANTINE_HOLD",
                    request_id=decision.request_id,
                    verdict="HOLD",
                    data_label=decision.data_label,
                )

                return JsonRpcResponse(
                    jsonrpc="2.0",
                    error=JsonRpcError(
                        code=-32004,
                        message="Transaction placed on quarantine HOLD",
                        data={
                            "hold_id": hold_id,
                            "decision_id": decision.request_id,
                            "reasons": [r.model_dump() for r in decision.reasons],
                            "risk_score": decision.risk_score,
                        },
                    ),
                    id=rpc_id,
                )

            # ---------------------------------------------------------
            # Branch C: DENY
            # ---------------------------------------------------------
            if reservation_id:
                limit_store.release(reservation_id)

            return JsonRpcResponse(
                jsonrpc="2.0",
                error=JsonRpcError(
                    code=-32003,
                    message="Signing request DENIED by policy firewall",
                    data={
                        "decision_id": decision.request_id,
                        "reasons": [r.model_dump() for r in decision.reasons],
                        "risk_score": decision.risk_score,
                    },
                ),
                id=rpc_id,
            )

        except ShimRefusalError as exc:
            # Signer shim refused signing
            if reservation_id:
                try:
                    limit_store.release(reservation_id)
                except Exception:
                    pass
            logger.warning("shim_refusal_handled: reason=%s detail=%s", exc.reason_code, exc.detail)
            return JsonRpcResponse(
                jsonrpc="2.0",
                error=JsonRpcError(
                    code=-32003,
                    message=f"Signing refused by enforcement point: {exc.reason_code}",
                    data={
                        "decision_id": request_id,
                        "reasons": [
                            {
                                "code": exc.reason_code,
                                "weight": 100,
                                "detail": exc.detail,
                            }
                        ],
                        "risk_score": 100,
                    },
                ),
                id=rpc_id,
            )

        except Exception as exc:
            # Invariant #3 & Invariant #8: Any internal error => DENY (-32003, ENGINE_ERROR)
            # Never return a signature on error.
            if reservation_id:
                try:
                    limit_store.release(reservation_id)
                except Exception:
                    pass

            logger.exception("gateway_internal_engine_error: %s", exc)
            return JsonRpcResponse(
                jsonrpc="2.0",
                error=JsonRpcError(
                    code=-32003,
                    message="Signing request DENIED: internal engine error",
                    data={
                        "decision_id": request_id,
                        "reasons": [
                            {
                                "code": "ENGINE_ERROR",
                                "weight": 100,
                                "detail": f"Engine execution failure: {exc}",
                            }
                        ],
                        "risk_score": 100,
                    },
                ),
                id=rpc_id,
            )


# Global singleton handler
gateway_handler = GatewayHandler()
