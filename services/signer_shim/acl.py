"""Internal network Access Control Layer (ACL) for Signer Shim (Milestone S11).

Invariants:
- The signer shim must never be accessible from public networks or unverified callers.
- Only the BitGuard decision firewall container on 'signer_internal' may invoke the shim.
- Shared-secret mTLS authentication layer ensures defense-in-depth within Docker networks.
"""

import logging

from fastapi import Header, HTTPException, status

from services.signer_shim.config import settings

logger = logging.getLogger("signer_shim.acl")


async def verify_internal_caller(
    x_bitguard_internal_auth: str | None = Header(default=None, alias="X-BitGuard-Internal-Auth"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> None:
    """FastAPI security dependency validating that requests originate from authorized BitGuard firewall."""
    # Check custom header
    caller_token = x_bitguard_internal_auth

    # Or standard Bearer token
    if not caller_token and authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            caller_token = parts[1]

    expected_secret = settings.internal_auth_token

    if not caller_token or caller_token != expected_secret:
        logger.warning(
            "unauthorized_internal_caller_rejected: token_supplied=%s",
            bool(caller_token),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "status": "REFUSED",
                "reason_code": "UNAUTHORIZED_INTERNAL_CALLER",
                "detail": "Direct or unauthorized invocation of Signer Shim forbidden by network ACL",
            },
        )
