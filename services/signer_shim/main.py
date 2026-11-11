"""Signer Shim Service (Enforcement Point) — Milestone S11 / F1.

Invariants:
- Invariant #1: Key Isolation: BitGuard never stores or uses signing keys.
  Only the signer shim holds a disposable TESTNET key.
- Invariant #2: Approval Binding & Verification: The signer signs only when given
  a one-time BitGuard approval token bound to tx digest, wallet, chain, expiry
  (~60s) and nonce. The shim independently recomputes the digest from raw bytes.
- Invariant #3: Fail-Closed Default: Fail closed on unknown format, parse error,
  store outage, replay, or missing token.
- Invariant #4: Raw Byte Source of Truth: Always decode from raw transaction bytes.
- Invariant #9: Environment & Safety Boundary: Local chains and public testnets
  with disposable keys ONLY. No mainnet. No real funds.
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, status
from fastapi.responses import JSONResponse

from services.bitguard.breaker.epoch_store import token_epoch_store
from services.bitguard.breaker.key_hook import key_policy_hook
from services.bitguard.decoders.base import DecodeError
from services.bitguard.decoders.evm import evm_decoder
from services.bitguard.decoders.psbt import psbt_decoder
from services.bitguard.tokens import (
    KeySet,
    token_manager,
    verify_token,
)
from services.signer_shim.acl import verify_internal_caller
from services.signer_shim.config import settings
from services.signer_shim.heartbeat import HeartbeatMessage, heartbeat_tracker
from services.signer_shim.models import RefusalResponse, SignRequest, SignResponse
from services.signer_shim.nonce_store import nonce_store
from services.signer_shim.signer import testnet_signer

logger = logging.getLogger("signer_shim")

# Configured BitGuard public key set for token verification
public_key_set = KeySet()


def set_public_key_set(ks: KeySet) -> None:
    """Configures the active BitGuard public key set for the signer shim."""
    global public_key_set
    public_key_set = ks


def init_public_key_set() -> None:
    """Initializes the BitGuard public key set from config or defaults."""
    global public_key_set
    pub_dict = settings.get_public_key_dict()
    if pub_dict:
        public_key_set = KeySet.from_public_key_dict(pub_dict)
    else:
        # Development / lab fallback: sync with active token manager keys
        public_key_set = KeySet.from_public_key_dict(token_manager.key_set.export_public_key_set())


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context initializing key sets and resources."""
    init_public_key_set()
    logger.info("Signer Shim enforcement point initialized successfully")
    yield
    logger.info("Signer Shim shutting down")


app = FastAPI(
    title="BitGuard Signer Shim (Enforcement Point)",
    description="Isolated signing enforcement point with disposable testnet key custody",
    version="0.2.0",
    lifespan=lifespan,
)


@app.get("/healthz", tags=["Health"])
def healthz() -> dict[str, str]:
    """Health check endpoint for the signer shim service."""
    return {
        "status": "ok",
        "service": "signer_shim",
        "environment": settings.environment,
        "disposable_address": testnet_signer.address,
        "heartbeat_healthy": str(heartbeat_tracker.is_healthy()),
        "heartbeat_age_seconds": f"{heartbeat_tracker.get_heartbeat_age():.1f}",
    }


@app.post("/heartbeat", tags=["Health"])
async def receive_heartbeat(msg: HeartbeatMessage) -> JSONResponse:
    """Receives and verifies a signed periodic heartbeat from BitGuard."""
    ok, detail = heartbeat_tracker.record_heartbeat(msg)
    if not ok:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"status": "rejected", "detail": detail},
        )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "accepted",
            "instance_id": msg.instance_id,
            "age_seconds": heartbeat_tracker.get_heartbeat_age(),
        },
    )


@app.post(
    "/sign",
    response_model=SignResponse,
    responses={
        400: {"model": RefusalResponse, "description": "Signing refused due to policy, token, or digest mismatch"},
        403: {"model": RefusalResponse, "description": "Signing refused due to ACL or authorization failure"},
        500: {"model": RefusalResponse, "description": "Internal store or signing failure"},
    },
    summary="Enforce policy verification and sign raw transaction",
    description=(
        "Enforces the 6 invariants: (1) verify Ed25519 token signature, (2) check exp, wallet, chain, "
        "(3) independently recompute digest from raw_tx_bytes, (4) consume nonce atomically via Redis SET NX, "
        "(5) sign with disposable testnet key, (6) log outcome."
    ),
    dependencies=[Depends(verify_internal_caller)],
)
async def sign_transaction(payload: SignRequest) -> Any:
    """Primary signing enforcement entrypoint."""
    # -----------------------------------------------------------------
    # Step 0: Enforce Dead-Man Heartbeat Freshness (Milestone S24 / F17)
    # -----------------------------------------------------------------
    if not heartbeat_tracker.is_healthy():
        age = heartbeat_tracker.get_heartbeat_age()
        logger.error(
            "signing_refusal: reason=DEADMAN_HEARTBEAT_EXPIRED age=%.1fs threshold=%.1fs",
            age,
            heartbeat_tracker.timeout_seconds,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=RefusalResponse(
                status="REFUSED",
                reason_code="DEADMAN_HEARTBEAT_EXPIRED",
                detail=(
                    f"Dead-man heartbeat expired ({age:.1f}s since last heartbeat, threshold "
                    f"{heartbeat_tracker.timeout_seconds:.1f}s). All token signing refused."
                ),
            ).model_dump(),
        )

    # -----------------------------------------------------------------
    # Step 1: Verify token signature against configured public key set
    # -----------------------------------------------------------------
    token_str = payload.token.strip() if payload.token else ""
    if not token_str:
        logger.warning("signing_refusal: reason=MISSING_APPROVAL_TOKEN")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=RefusalResponse(
                status="REFUSED",
                reason_code="MISSING_APPROVAL_TOKEN",
                detail="Approval token is required to execute transaction signing",
            ).model_dump(),
        )

    v_res = verify_token(token_str, public_key_set)
    if not v_res.valid or v_res.claims is None:
        reason_code = v_res.error_code or "INVALID_APPROVAL_TOKEN"
        detail = v_res.error_detail or "Approval token verification failed"
        logger.warning("signing_refusal: reason=%s detail=%s", reason_code, detail)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=RefusalResponse(
                status="REFUSED",
                reason_code=reason_code,
                detail=detail,
            ).model_dump(),
        )

    claims = v_res.claims

    # -----------------------------------------------------------------
    # Step 1b: Verify Token Epoch (Revocation on Circuit Breaker Trip)
    # -----------------------------------------------------------------
    current_epoch = token_epoch_store.get_current_epoch()
    token_epoch = getattr(claims, "epoch", 1)
    if token_epoch < current_epoch:
        logger.warning(
            "signing_refusal: reason=REVOKED_TOKEN_EPOCH token_epoch=%d current_epoch=%d",
            token_epoch,
            current_epoch,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=RefusalResponse(
                status="REFUSED",
                reason_code="REVOKED_TOKEN_EPOCH",
                detail=(
                    f"Approval token epoch {token_epoch} is older than current active epoch {current_epoch} "
                    "(token revoked by circuit breaker)"
                ),
            ).model_dump(),
        )

    # -----------------------------------------------------------------
    # Step 1c: Check KeyUsePolicyHook at KMS/HSM level
    # -----------------------------------------------------------------
    if not key_policy_hook.is_key_enabled(claims.kid):
        logger.warning("signing_refusal: reason=KEY_DISABLED_AT_KMS key=%s", claims.kid)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=RefusalResponse(
                status="REFUSED",
                reason_code="KEY_DISABLED_AT_KMS",
                detail=f"Signing key '{claims.kid}' has been disabled by circuit breaker policy hook at KMS/HSM level",
            ).model_dump(),
        )

    # -----------------------------------------------------------------
    # Step 2: Check exp, and wallet and chain
    # -----------------------------------------------------------------
    if payload.wallet and payload.wallet.strip().lower() != claims.wallet.lower():
        logger.warning(
            "signing_refusal: reason=WALLET_MISMATCH payload_wallet=%s token_wallet=%s",
            payload.wallet,
            claims.wallet,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=RefusalResponse(
                status="REFUSED",
                reason_code="WALLET_MISMATCH",
                detail=f"Requested wallet '{payload.wallet}' does not match approval token wallet '{claims.wallet}'",
            ).model_dump(),
        )

    if payload.chain and payload.chain.strip().lower() != claims.chain.lower():
        logger.warning(
            "signing_refusal: reason=CHAIN_MISMATCH payload_chain=%s token_chain=%s",
            payload.chain,
            claims.chain,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=RefusalResponse(
                status="REFUSED",
                reason_code="CHAIN_MISMATCH",
                detail=f"Requested chain '{payload.chain}' does not match approval token chain '{claims.chain}'",
            ).model_dump(),
        )

    # -----------------------------------------------------------------
    # Step 3: RECOMPUTE digest from raw_tx_bytes (reuse decoder)
    # -----------------------------------------------------------------
    raw_tx = payload.raw_tx_bytes.strip() if payload.raw_tx_bytes else ""
    if not raw_tx:
        logger.warning("signing_refusal: reason=EMPTY_RAW_TX")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=RefusalResponse(
                status="REFUSED",
                reason_code="EMPTY_RAW_TX",
                detail="Raw transaction bytes must not be empty",
            ).model_dump(),
        )

    is_btc = (
        claims.chain.lower() in ["bitcoin", "btc", "bitcoin_regtest", "bitcoin_testnet"]
        or raw_tx.lower().startswith("70736274ff")
        or raw_tx.startswith("cHNidP8")
    )

    try:
        if is_btc:
            decoded_tx = psbt_decoder.decode(raw_tx, chain=claims.chain)
        else:
            decoded_tx = evm_decoder.decode(raw_tx)
    except DecodeError as exc:
        logger.warning("signing_refusal: reason=RAW_TX_DECODE_FAILED detail=%s", exc)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=RefusalResponse(
                status="REFUSED",
                reason_code="RAW_TX_DECODE_FAILED",
                detail=f"Failed to decode raw transaction bytes: {exc}",
            ).model_dump(),
        )

    recomputed_digest = decoded_tx.digest.lower()
    token_digest = claims.digest.lower()

    if recomputed_digest != token_digest:
        logger.warning(
            "signing_refusal: reason=DIGEST_MISMATCH recomputed=%s token=%s",
            recomputed_digest,
            token_digest,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=RefusalResponse(
                status="REFUSED",
                reason_code="DIGEST_MISMATCH",
                detail=(
                    f"Recomputed digest '{recomputed_digest}' from raw transaction bytes "
                    f"does not match token digest '{token_digest}'"
                ),
            ).model_dump(),
        )

    # Validate decoded transaction chain matches token chain
    decoded_chain = decoded_tx.chain.lower()
    token_chain = claims.chain.lower()
    is_chain_match = (
        (decoded_chain == token_chain)
        or (decoded_chain in ["ethereum", "eip155:1"] and token_chain in ["ethereum", "eip155:1"])
        or (decoded_chain in ["bitcoin", "btc"] and token_chain in ["bitcoin", "btc"])
    )
    if not is_chain_match:
        logger.warning(
            "signing_refusal: reason=CHAIN_MISMATCH decoded_chain=%s token_chain=%s",
            decoded_chain,
            token_chain,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=RefusalResponse(
                status="REFUSED",
                reason_code="CHAIN_MISMATCH",
                detail=f"Decoded transaction chain '{decoded_chain}' does not match token chain '{token_chain}'",
            ).model_dump(),
        )

    # -----------------------------------------------------------------
    # Step 4: Consume nonce atomically (Redis SET NX with TTL); reject replays
    # -----------------------------------------------------------------
    try:
        nonce_consumed = nonce_store.consume_nonce(claims.nonce)
    except Exception as exc:
        logger.error("signing_refusal: reason=NONCE_STORE_UNAVAILABLE detail=%s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=RefusalResponse(
                status="REFUSED",
                reason_code="NONCE_STORE_UNAVAILABLE",
                detail=f"Nonce tracking store outage; failing closed: {exc}",
            ).model_dump(),
        )

    if not nonce_consumed:
        logger.warning(
            "signing_refusal: reason=NONCE_ALREADY_CONSUMED nonce=%s",
            claims.nonce,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=RefusalResponse(
                status="REFUSED",
                reason_code="NONCE_ALREADY_CONSUMED",
                detail=f"Approval token nonce '{claims.nonce}' has already been consumed (replay attack rejected)",
            ).model_dump(),
        )

    # -----------------------------------------------------------------
    # Step 5: Sign with DISPOSABLE TESTNET key
    # -----------------------------------------------------------------
    try:
        sign_result = testnet_signer.sign_digest(recomputed_digest)
    except Exception as exc:
        logger.error("signing_refusal: reason=SIGNING_ERROR detail=%s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=RefusalResponse(
                status="REFUSED",
                reason_code="SIGNING_ERROR",
                detail=f"Cryptographic signing failure: {exc}",
            ).model_dump(),
        )

    # -----------------------------------------------------------------
    # Step 6: Log successful sign
    # -----------------------------------------------------------------
    logger.info(
        "signing_approved: tx_hash=%s digest=%s wallet=%s chain=%s kid=%s nonce=%s",
        sign_result["tx_hash"],
        recomputed_digest,
        claims.wallet,
        claims.chain,
        claims.kid,
        claims.nonce,
    )

    return SignResponse(
        status="SIGNED",
        signature=sign_result["signature"],
        tx_hash=sign_result["tx_hash"],
        digest=recomputed_digest,
        chain=claims.chain,
        wallet=claims.wallet,
        r=sign_result["r"],
        s=sign_result["s"],
        v=sign_result["v"],
    )
