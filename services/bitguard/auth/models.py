"""Pydantic schemas for OIDC, WebAuthn, step-up authentication, and credential management."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from services.bitguard.models import UserResponse


class OIDCLoginRequest(BaseModel):
    """Payload to exchange OIDC identity tokens for BitGuard access tokens."""

    id_token: str = Field(description="OIDC OpenID Connect ID token JWT issued by Keycloak")
    access_token: str | None = Field(default=None, description="Optional Keycloak access token JWT")


class OIDCLoginResponse(BaseModel):
    """Authenticated session response from OIDC login."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class WebAuthnRegisterOptionsResponse(BaseModel):
    """Registration challenge and options returned to client for navigator.credentials.create()."""

    options: dict[str, Any]
    challenge_id: str


class WebAuthnRegisterVerifyRequest(BaseModel):
    """Registration response payload from navigator.credentials.create()."""

    credential: dict[str, Any] = Field(description="JSON-serialized PublicKeyCredential from client")
    challenge_id: str | None = Field(default=None, description="Optional challenge correlation ID")


class WebAuthnRegisterVerifyResponse(BaseModel):
    """Outcome of WebAuthn credential registration."""

    verified: bool
    credential_id: str
    sign_count: int
    user_id: str
    message: str = "Credential successfully registered"


class WebAuthnAuthenticateOptionsRequest(BaseModel):
    """Request options for WebAuthn authentication ceremony."""

    user_id: str | None = Field(default=None, description="User ID to authenticate (optional if authenticated)")
    email: str | None = Field(default=None, description="User email (optional)")


class WebAuthnAuthenticateOptionsResponse(BaseModel):
    """Authentication challenge and options returned to client for navigator.credentials.get()."""

    options: dict[str, Any]
    challenge_id: str


class WebAuthnAuthenticateVerifyRequest(BaseModel):
    """Authentication assertion response from navigator.credentials.get()."""

    credential: dict[str, Any] = Field(description="JSON-serialized PublicKeyCredential assertion from client")
    challenge_id: str | None = Field(default=None, description="Optional challenge correlation ID")
    user_id: str | None = Field(default=None, description="User ID asserting the authentication")


class WebAuthnAuthenticateVerifyResponse(BaseModel):
    """Verified WebAuthn authentication with short-lived step-up token and assertion reference."""

    verified: bool
    step_up_token: str
    assertion_ref: str
    user_id: str
    new_sign_count: int
    expires_in: int


class WebAuthnCredentialSummary(BaseModel):
    """Registered WebAuthn credential metadata for user profile."""

    id: str
    credential_id: str
    user_id: str
    sign_count: int
    transports: list[str] = Field(default_factory=list)
    aaguid: str | None = None
    backup_eligible: bool = False
    backed_up: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_used_at: datetime | None = None
