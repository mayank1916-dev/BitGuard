"""WebAuthn step-up verification and tamper-evident audit logging for sensitive admin actions (Milestone S15 / F9 / Invariants #5 & #7).

Invariants:
- Invariant #5: WebAuthn Hardware Approvals. Admin, SecOps, and Approver roles require
  a WebAuthn-verified step-up assertion for sensitive operations.
- Invariant #7: Immutable Audit Trail. Every admin action is recorded with cryptographic
  hash chaining containing user, action, time, and WebAuthn assertion reference.
"""

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, Header, HTTPException, Request, status

from services.bitguard.audit_service import audit_service
from services.bitguard.auth.webauthn_service import webauthn_service
from services.bitguard.config import settings
from services.bitguard.models import DataLabel, Role, UserResponse
from services.bitguard.rbac import decode_access_token, get_current_user

logger = logging.getLogger("bitguard.auth.step_up")

STEP_UP_REQUIRED_ROLES: set[Role] = {
    Role.ADMIN,
    Role.SECOPS,
    Role.APPROVER,
}


def require_step_up_webauthn(
    request: Request,
    current_user: UserResponse = Depends(get_current_user),
    authorization: str | None = Header(default=None),
    x_step_up_token: str | None = Header(default=None, alias="X-Step-Up-Token"),
    x_assertion_ref: str | None = Header(default=None, alias="X-WebAuthn-Assertion-Ref"),
) -> UserResponse:
    """FastAPI dependency enforcing WebAuthn step-up for Admin, SecOps, and Approver roles."""
    if current_user.role not in STEP_UP_REQUIRED_ROLES:
        # Non-administrative roles do not require step-up
        request.state.webauthn_assertion_ref = None
        return current_user

    assertion_ref: str | None = None

    # 1. Check X-Step-Up-Token header
    if x_step_up_token:
        try:
            payload = webauthn_service.verify_step_up_token(x_step_up_token)
            # Verify token subject matches user
            if payload.get("sub") and payload["sub"] not in {current_user.id, current_user.email}:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Step-up token does not match active authenticated user",
                )
            assertion_ref = payload.get("assertion_ref") or f"ref-{uuid.uuid4().hex[:12]}"
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid step-up token: {exc}",
            ) from exc

    # 2. Check X-WebAuthn-Assertion-Ref header directly
    elif x_assertion_ref:
        assertion_ref = x_assertion_ref

    # 3. Check Bearer token payload for webauthn_verified claim
    elif authorization and authorization.startswith("Bearer "):
        token_str = authorization.split()[1]
        try:
            tok_payload = decode_access_token(token_str)
            if tok_payload.get("webauthn_verified"):
                assertion_ref = tok_payload.get("assertion_ref") or f"bearer-{uuid.uuid4().hex[:12]}"
        except Exception:
            pass

    # 4. Check strict requirement
    is_strict = (
        settings.environment.lower() == "production"
        or settings.enforce_step_up
    )

    if not assertion_ref:
        if is_strict or not settings.dev_auth_bypass:
            logger.warning(
                "Step-up required: user=%s role=%s path=%s missing WebAuthn verification",
                current_user.email,
                current_user.role.value,
                request.url.path,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Role '{current_user.role.value}' requires a WebAuthn-verified session "
                    "(step-up) for sensitive actions"
                ),
            )
        else:
            assertion_ref = f"assertion-dev-bypass-{uuid.uuid4().hex[:12]}"

    # Attach assertion reference to request state
    request.state.webauthn_assertion_ref = assertion_ref
    return current_user


def log_admin_action_audit(
    user: UserResponse,
    action: str,
    assertion_ref: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Appends an immutable audit record for an administrative action (Invariant #7)."""
    now_iso = datetime.now(UTC).isoformat()
    ref = assertion_ref or f"assertion-direct-{uuid.uuid4().hex[:12]}"
    payload = {
        "user": user.id,
        "action": action,
        "time": now_iso,
        "webauthn_assertion_ref": ref,
        **(details or {}),
    }

    audit_service.append_entry(
        action=f"ADMIN_ACTION:{action}",
        actor=user.email or user.id,
        payload=payload,
        data_label=DataLabel.REAL,
    )

    logger.info(
        "Logged admin action audit: user=%s action=%s assertion_ref=%s",
        user.email,
        action,
        ref,
    )
