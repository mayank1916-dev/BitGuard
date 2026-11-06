"""FastAPI Router for OIDC SSO, WebAuthn hardware authentication, and credential management (Milestone S15 / F9)."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from services.bitguard.auth.models import (
    OIDCLoginRequest,
    OIDCLoginResponse,
    WebAuthnAuthenticateOptionsRequest,
    WebAuthnAuthenticateOptionsResponse,
    WebAuthnAuthenticateVerifyRequest,
    WebAuthnAuthenticateVerifyResponse,
    WebAuthnCredentialSummary,
    WebAuthnRegisterOptionsResponse,
    WebAuthnRegisterVerifyRequest,
    WebAuthnRegisterVerifyResponse,
)
from services.bitguard.auth.oidc import oidc_auth_service
from services.bitguard.auth.step_up import log_admin_action_audit, require_step_up_webauthn
from services.bitguard.auth.webauthn_service import webauthn_service
from services.bitguard.auth.webauthn_store import webauthn_credential_store
from services.bitguard.config import settings
from services.bitguard.models import (
    DevLoginRequest,
    DevLoginResponse,
    UserResponse,
)
from services.bitguard.rbac import (
    ALL_TEST_USERS,
    SEEDED_USERS,
    create_access_token,
    get_current_user,
)

logger = logging.getLogger("bitguard.auth.router")

router = APIRouter(prefix="/auth", tags=["Authentication & Identity"])


@router.post(
    "/oidc-login",
    response_model=OIDCLoginResponse,
    summary="Login via Keycloak OpenID Connect SSO",
    description="Exchanges an OIDC ID token for a signed BitGuard session token with mapped realm roles.",
)
async def oidc_login(payload: OIDCLoginRequest) -> OIDCLoginResponse:
    """Verifies Keycloak OIDC ID token and returns authenticated BitGuard session."""
    return oidc_auth_service.login_with_oidc(payload)


@router.post(
    "/webauthn/register/options",
    response_model=WebAuthnRegisterOptionsResponse,
    summary="Generate WebAuthn registration options",
    description="Generates challenge and creation options for registering a hardware security key (navigator.credentials.create).",
)
async def webauthn_register_options(
    current_user: UserResponse = Depends(get_current_user),
) -> WebAuthnRegisterOptionsResponse:
    """Initiates WebAuthn registration ceremony for current user."""
    return webauthn_service.generate_registration_options(
        user_id=current_user.id,
        user_name=current_user.email,
        user_display_name=current_user.name,
    )


@router.post(
    "/webauthn/register/verify",
    response_model=WebAuthnRegisterVerifyResponse,
    summary="Verify WebAuthn credential registration",
    description="Cryptographically verifies client registration response and stores public key credentials.",
)
async def webauthn_register_verify(
    payload: WebAuthnRegisterVerifyRequest,
    current_user: UserResponse = Depends(get_current_user),
) -> WebAuthnRegisterVerifyResponse:
    """Completes WebAuthn registration ceremony and records credential."""
    return webauthn_service.verify_registration(
        credential=payload.credential,
        user_id=current_user.id,
        challenge_id=payload.challenge_id,
    )


@router.post(
    "/webauthn/authenticate/options",
    response_model=WebAuthnAuthenticateOptionsResponse,
    summary="Generate WebAuthn authentication options",
    description="Generates challenge and assertion options for hardware key authentication (navigator.credentials.get).",
)
async def webauthn_authenticate_options(
    payload: WebAuthnAuthenticateOptionsRequest = WebAuthnAuthenticateOptionsRequest(),
) -> WebAuthnAuthenticateOptionsResponse:
    """Initiates WebAuthn authentication / step-up ceremony."""
    return webauthn_service.generate_authentication_options(
        user_id=payload.user_id,
    )


@router.post(
    "/webauthn/authenticate/verify",
    response_model=WebAuthnAuthenticateVerifyResponse,
    summary="Verify WebAuthn authentication assertion",
    description="Verifies hardware key signature, checks monotonic sign count, and issues short-lived step-up token.",
)
async def webauthn_authenticate_verify(
    payload: WebAuthnAuthenticateVerifyRequest,
) -> WebAuthnAuthenticateVerifyResponse:
    """Completes WebAuthn authentication and returns verified step-up session token."""
    return webauthn_service.verify_authentication(
        credential=payload.credential,
        user_id=payload.user_id,
        challenge_id=payload.challenge_id,
    )


@router.get(
    "/webauthn/credentials",
    response_model=list[WebAuthnCredentialSummary],
    summary="List registered WebAuthn credentials for current user",
)
async def list_user_credentials(
    current_user: UserResponse = Depends(get_current_user),
) -> list[WebAuthnCredentialSummary]:
    """Retrieves all registered hardware keys for authenticated user."""
    creds = webauthn_credential_store.list_user_credentials(current_user.id)
    return [
        WebAuthnCredentialSummary(
            id=c["id"],
            credential_id=c["credential_id"],
            user_id=c["user_id"],
            sign_count=c["sign_count"],
            transports=c.get("transports", []),
            aaguid=c.get("aaguid"),
            backup_eligible=c.get("backup_eligible", False),
            backed_up=c.get("backed_up", False),
            created_at=c["created_at"],
            last_used_at=c.get("last_used_at"),
        )
        for c in creds
    ]


@router.post(
    "/dev-token",
    response_model=DevLoginResponse,
    summary="Issue signed development JWT for seeded test users (DEV ONLY)",
    description="Strictly disabled when ENV=production. Returns 403 Forbidden in production.",
)
@router.post(
    "/dev-login",
    response_model=DevLoginResponse,
    summary="Issue signed development JWT (alias for dev-token)",
    description="Strictly disabled when ENV=production. Returns 403 Forbidden in production.",
)
async def issue_dev_token(
    payload: DevLoginRequest = DevLoginRequest(),
) -> DevLoginResponse:
    """Development login endpoint issuing signed JWTs. Disabled in production."""
    if settings.environment.lower() == "production":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dev login endpoint is disabled in production environment (DEV ONLY)",
        )

    user: UserResponse | None = None
    if payload.user_id and payload.user_id in ALL_TEST_USERS:
        user = ALL_TEST_USERS[payload.user_id]
    else:
        user = SEEDED_USERS.get(payload.role)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid seeded role or user_id: {payload.role}",
        )

    token = create_access_token(user)
    return DevLoginResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.jwt_expiration_seconds,
        user=user,
    )


@router.post(
    "/admin/action",
    response_model=dict[str, Any],
    summary="Execute sensitive administrative action requiring WebAuthn step-up",
    description=(
        "Invariant #5 & Invariant #7: Admin, SecOps, and Approver roles require a WebAuthn-verified "
        "session (step-up) for sensitive actions. Every admin action appends a signed audit record."
    ),
    dependencies=[Depends(require_step_up_webauthn)],
)
async def execute_admin_action(
    request: Request,
    payload: dict[str, Any],
    current_user: UserResponse = Depends(require_step_up_webauthn),
) -> dict[str, Any]:
    action_name = payload.get("action", "ADMIN_SENSITIVE_OPERATION")
    assertion_ref = getattr(request.state, "webauthn_assertion_ref", None)
    log_admin_action_audit(
        user=current_user,
        action=action_name,
        assertion_ref=assertion_ref,
        details=payload.get("details", {}),
    )
    return {
        "status": "SUCCESS",
        "action": action_name,
        "user": current_user.id,
        "webauthn_assertion_ref": assertion_ref,
    }
