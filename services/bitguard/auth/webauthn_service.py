"""WebAuthn hardware key service using py_webauthn (Milestone S15 / F9 / Invariant #5).

Invariants:
- Invariant #5: WebAuthn Hardware Approvals. Human approvals and sensitive administrative
  operations require hardware key signatures with monotonic sign-count verification.
- Invariant #3: Fail-Closed Default. Unknown credentials, decreased sign count (cloned key),
  or mismatched origin/RP-ID fails closed immediately.
"""

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import webauthn
from fastapi import HTTPException, status
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    options_to_json,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from services.bitguard.auth.models import (
    WebAuthnAuthenticateOptionsResponse,
    WebAuthnAuthenticateVerifyResponse,
    WebAuthnRegisterOptionsResponse,
    WebAuthnRegisterVerifyResponse,
)
from services.bitguard.auth.webauthn_store import (
    challenge_store,
    webauthn_credential_store,
)
from services.bitguard.config import settings

logger = logging.getLogger("bitguard.auth.webauthn_service")


class WebAuthnService:
    """Core domain service for WebAuthn credential registration and step-up authentication."""

    def __init__(self) -> None:
        self.cred_store = webauthn_credential_store
        self.challenges = challenge_store

    def generate_registration_options(
        self,
        user_id: str,
        user_name: str,
        user_display_name: str | None = None,
    ) -> WebAuthnRegisterOptionsResponse:
        """Generates PublicKeyCredentialCreationOptions for registration."""
        existing_creds = self.cred_store.list_user_credentials(user_id)
        exclude_credentials = [
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(c["credential_id"]),
            )
            for c in existing_creds
        ]

        options = webauthn.generate_registration_options(
            rp_id=settings.webauthn_rp_id,
            rp_name=settings.webauthn_rp_name,
            user_id=user_id.encode("utf-8"),
            user_name=user_name,
            user_display_name=user_display_name or user_name,
            attestation=webauthn.helpers.structs.AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            exclude_credentials=exclude_credentials,
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.EDDSA,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
        )

        challenge_id = f"chal-reg-{uuid.uuid4().hex[:12]}"
        self.challenges.save_challenge(
            challenge_id=challenge_id,
            challenge=options.challenge,
            user_id=user_id,
        )

        options_dict = json.loads(options_to_json(options))
        return WebAuthnRegisterOptionsResponse(
            options=options_dict,
            challenge_id=challenge_id,
        )

    def verify_registration(
        self,
        credential: dict[str, Any],
        user_id: str,
        challenge_id: str | None = None,
    ) -> WebAuthnRegisterVerifyResponse:
        """Cryptographically verifies WebAuthn registration response and registers credential."""
        # 1. Resolve challenge
        challenge_entry = None
        if challenge_id:
            challenge_entry = self.challenges.pop_challenge(challenge_id)
        if not challenge_entry:
            # Fallback to pop by user_id if challenge_id wasn't passed directly
            with self.challenges._lock:
                for cid, entry in list(self.challenges._challenges.items()):
                    if entry["user_id"] == user_id:
                        challenge_entry = self.challenges.pop_challenge(cid)
                        break

        if not challenge_entry:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="WebAuthn registration challenge expired or not found. Please restart registration.",
            )

        expected_challenge = challenge_entry["challenge"]

        # 2. Cryptographic verification using py_webauthn
        try:
            verified = webauthn.verify_registration_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_rp_id=settings.webauthn_rp_id,
                expected_origin=settings.webauthn_allowed_origins,
                require_user_verification=False,
            )
        except Exception as exc:
            logger.warning("WebAuthn registration failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"WebAuthn registration verification failed: {exc}",
            ) from exc

        # 3. Persist credential
        cred_id_b64 = bytes_to_base64url(verified.credential_id)
        cose_b64 = bytes_to_base64url(verified.credential_public_key)

        transports: list[str] = []
        if isinstance(credential.get("response"), dict):
            raw_trans = credential["response"].get("transports")
            if isinstance(raw_trans, list):
                transports = [str(t) for t in raw_trans]

        self.cred_store.save_credential(
            user_id=user_id,
            credential_id=cred_id_b64,
            public_key_cose_b64=cose_b64,
            sign_count=verified.sign_count,
            transports=transports,
            aaguid=str(verified.aaguid) if verified.aaguid else None,
            backup_eligible=bool(verified.credential_device_type),
            backed_up=bool(verified.credential_backed_up),
        )

        logger.info(
            "Registered WebAuthn credential %s for user %s (initial sign_count=%d)",
            cred_id_b64[:16],
            user_id,
            verified.sign_count,
        )

        return WebAuthnRegisterVerifyResponse(
            verified=True,
            credential_id=cred_id_b64,
            sign_count=verified.sign_count,
            user_id=user_id,
            message="Hardware credential registered successfully",
        )

    def generate_authentication_options(
        self,
        user_id: str | None = None,
    ) -> WebAuthnAuthenticateOptionsResponse:
        """Generates PublicKeyCredentialRequestOptions for authentication ceremony."""
        allow_credentials = None
        if user_id:
            creds = self.cred_store.list_user_credentials(user_id)
            if creds:
                allow_credentials = [
                    PublicKeyCredentialDescriptor(
                        id=base64url_to_bytes(c["credential_id"]),
                    )
                    for c in creds
                ]

        options = webauthn.generate_authentication_options(
            rp_id=settings.webauthn_rp_id,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        challenge_id = f"chal-auth-{uuid.uuid4().hex[:12]}"
        self.challenges.save_challenge(
            challenge_id=challenge_id,
            challenge=options.challenge,
            user_id=user_id or "",
        )

        options_dict = json.loads(options_to_json(options))
        return WebAuthnAuthenticateOptionsResponse(
            options=options_dict,
            challenge_id=challenge_id,
        )

    def verify_authentication(
        self,
        credential: dict[str, Any],
        user_id: str | None = None,
        challenge_id: str | None = None,
    ) -> WebAuthnAuthenticateVerifyResponse:
        """Verifies WebAuthn assertion signature, checks monotonic sign count, and issues step-up token."""
        # 1. Resolve challenge
        challenge_entry = None
        if challenge_id:
            challenge_entry = self.challenges.pop_challenge(challenge_id)
        if not challenge_entry and user_id:
            with self.challenges._lock:
                for cid, entry in list(self.challenges._challenges.items()):
                    if entry["user_id"] == user_id:
                        challenge_entry = self.challenges.pop_challenge(cid)
                        break
        if not challenge_entry:
            # Fallback to any active authentication challenge
            with self.challenges._lock:
                for cid in list(self.challenges._challenges.keys()):
                    if cid.startswith("chal-auth-"):
                        challenge_entry = self.challenges.pop_challenge(cid)
                        break

        if not challenge_entry:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="WebAuthn authentication challenge expired or not found. Please restart ceremony.",
            )

        expected_challenge = challenge_entry["challenge"]

        # 2. Resolve registered credential
        cred_id_str = credential.get("id") or credential.get("rawId") or ""
        registered = self.cred_store.get_credential(cred_id_str)
        if not registered:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"WebAuthn credential '{cred_id_str[:16]}...' is not registered",
            )

        resolved_user_id = user_id or registered["user_id"]
        if registered["user_id"] != resolved_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="WebAuthn credential does not belong to the asserting user",
            )

        # 3. Cryptographic assertion verification using py_webauthn
        cose_bytes = base64url_to_bytes(registered["public_key_cose"])
        current_sign_count = registered["sign_count"]

        try:
            verified = webauthn.verify_authentication_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_rp_id=settings.webauthn_rp_id,
                expected_origin=settings.webauthn_allowed_origins,
                credential_public_key=cose_bytes,
                credential_current_sign_count=current_sign_count,
                require_user_verification=False,
            )
        except Exception as exc:
            logger.warning(
                "WebAuthn authentication verification failed for user %s: %s",
                resolved_user_id,
                exc,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"WebAuthn authentication failed: {exc}",
            ) from exc

        # 4. Monotonic sign count update
        self.cred_store.update_sign_count(cred_id_str, verified.new_sign_count)

        # 5. Issue Step-Up Token and Assertion Reference
        assertion_ref = f"assertion-{uuid.uuid4().hex[:16]}"
        step_up_token = self.create_step_up_token(
            user_id=resolved_user_id,
            assertion_ref=assertion_ref,
            expires_in_seconds=settings.step_up_token_ttl_seconds,
        )

        logger.info(
            "WebAuthn step-up authentication succeeded for user %s (sign_count %d -> %d, assertion_ref=%s)",
            resolved_user_id,
            current_sign_count,
            verified.new_sign_count,
            assertion_ref,
        )

        return WebAuthnAuthenticateVerifyResponse(
            verified=True,
            step_up_token=step_up_token,
            assertion_ref=assertion_ref,
            user_id=resolved_user_id,
            new_sign_count=verified.new_sign_count,
            expires_in=settings.step_up_token_ttl_seconds,
        )

    def create_step_up_token(
        self,
        user_id: str,
        assertion_ref: str,
        expires_in_seconds: int = 900,
    ) -> str:
        """Signs a short-lived step-up token certifying WebAuthn hardware verification."""
        now = datetime.now(UTC)
        expire = now + timedelta(seconds=expires_in_seconds)
        payload = {
            "sub": user_id,
            "assertion_ref": assertion_ref,
            "webauthn_verified": True,
            "token_type": "step_up",
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp()),
        }
        return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

    def verify_step_up_token(self, token: str) -> dict[str, Any]:
        """Validates step-up token signature, expiration, and claims."""
        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=[settings.jwt_algorithm],
            )
            if not payload.get("webauthn_verified"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Token missing WebAuthn verification assertion claim",
                )
            return payload
        except jwt.ExpiredSignatureError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="WebAuthn step-up token has expired. Please re-authenticate.",
            ) from exc
        except jwt.PyJWTError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid step-up token signature: {exc}",
            ) from exc


webauthn_service = WebAuthnService()
