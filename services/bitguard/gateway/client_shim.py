"""Client for communicating with the isolated Signer Shim service (Milestone S12).

Invariants:
- Invariant #1: BitGuard never holds signing keys; only the shim does.
- Invariant #2: Passes the one-time Ed25519 approval token bound to digest, wallet, chain.
- Invariant #3: Fail closed on shim connection errors, timeouts, or refusals.
- Authenticated via internal network ACL token (X-BitGuard-Internal-Auth).
"""

import logging
from typing import Any

import httpx

from services.bitguard.config import settings

logger = logging.getLogger("bitguard.gateway.client_shim")


class ShimRefusalError(Exception):
    """Raised when the signer shim refuses or fails to sign the transaction."""

    def __init__(self, status_code: int, reason_code: str, detail: str) -> None:
        super().__init__(f"Signer shim refused ({status_code} {reason_code}): {detail}")
        self.status_code = status_code
        self.reason_code = reason_code
        self.detail = detail


class SignerShimClient:
    """HTTP client communicating with the Signer Shim enforcement point."""

    def __init__(
        self,
        base_url: str | None = None,
        auth_token: str | None = None,
        timeout: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = (base_url or settings.signer_shim_url).rstrip("/")
        self.auth_token = auth_token or settings.signer_shim_internal_auth_token
        self.timeout = timeout
        self.transport = transport

    async def sign(
        self,
        raw_tx_bytes: str,
        token: str,
        wallet: str | None = None,
        chain: str | None = None,
    ) -> dict[str, Any]:
        """Submits an unsigned raw transaction and approval token to the Signer Shim."""
        url = f"{self.base_url}/sign"
        headers = {
            "Content-Type": "application/json",
            "X-BitGuard-Internal-Auth": self.auth_token,
        }
        payload = {
            "raw_tx_bytes": raw_tx_bytes,
            "token": token,
            "wallet": wallet,
            "chain": chain,
        }

        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=self.timeout) as client:
                resp = await client.post(url, headers=headers, json=payload)
        except Exception as exc:
            logger.warning("signer_shim_connection_error url=%s: %s", url, exc)
            raise ShimRefusalError(
                status_code=503,
                reason_code="SHIM_UNAVAILABLE",
                detail=f"Failed connecting to Signer Shim service: {exc}",
            ) from exc

        if resp.status_code == 200:
            return resp.json()

        # Handle refusal / error responses
        try:
            error_body = resp.json()
            reason_code = error_body.get("reason_code") or error_body.get("detail", {}).get("reason_code", "SIGNING_REFUSED")
            detail = error_body.get("detail") or "Signing refused by enforcement point"
            if isinstance(detail, dict):
                detail = detail.get("detail", str(detail))
        except Exception:
            reason_code = "SHIM_ERROR"
            detail = resp.text

        logger.warning(
            "signer_shim_refusal: status=%d reason=%s detail=%s",
            resp.status_code,
            reason_code,
            detail,
        )
        raise ShimRefusalError(
            status_code=resp.status_code,
            reason_code=reason_code,
            detail=str(detail),
        )


# Global singleton instance
signer_shim_client = SignerShimClient()
