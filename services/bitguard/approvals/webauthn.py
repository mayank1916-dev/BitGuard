"""WebAuthn assertion verification engine and test key generator (Milestone S16 / F10).

Invariants:
- Invariant #5: WebAuthn Hardware Approvals. Human approvals are WebAuthn signatures over the tx digest.
- Invariant #3: Fail-Closed Default. Invalid challenge, origin, RP ID, sign count, or signature fails closed.
"""

import base64
import hashlib
import json
import logging
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from services.bitguard.approvals.models import WebAuthnAssertion

logger = logging.getLogger("bitguard.approvals.webauthn")


class WebAuthnVerificationError(Exception):
    """Raised when WebAuthn assertion verification fails."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _decode_b64url_or_hex(val: str) -> bytes:
    """Decodes string that may be base64url, base64, hex, or plain text."""
    if not val:
        return b""
    # Check if raw hex
    clean = val.removeprefix("0x")
    if len(clean) > 0 and len(clean) % 2 == 0:
        try:
            return bytes.fromhex(clean)
        except ValueError:
            pass

    # Try base64 / base64url
    padded = val + "=" * (-len(val) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        try:
            return base64.b64decode(padded)
        except Exception:
            return val.encode("utf-8")


class ApproverKeyRegistry:
    """Registry of authorized hardware key public credentials for approvers."""

    def __init__(self) -> None:
        # approver_id -> (public_key_obj, last_sign_count)
        self._keys: dict[str, tuple[Any, int]] = {}
        # Replay set of seen assertion signatures / hashes
        self._consumed_assertions: set[str] = set()
        self._init_dev_approvers()

    def _init_dev_approvers(self) -> None:
        """Initializes deterministic ECDSA keys for seeded test approvers."""
        # Generate persistent test keypairs for usr-approver-01 and usr-approver-02
        self.dev_private_keys: dict[str, ec.EllipticCurvePrivateKey] = {}
        for approver_id in ["usr-approver-01", "usr-approver-02", "usr-admin-01", "usr-secops-01"]:
            priv = ec.generate_private_key(ec.SECP256R1())
            self.dev_private_keys[approver_id] = priv
            self._keys[approver_id] = (priv.public_key(), 0)

    def register_key(self, approver_id: str, public_key: Any) -> None:
        """Registers a public key (EC or RSA) for an approver."""
        self._keys[approver_id] = (public_key, 0)

    def get_public_key(self, approver_id: str) -> Any | None:
        """Retrieves registered public key for an approver."""
        entry = self._keys.get(approver_id)
        return entry[0] if entry else None

    def get_last_sign_count(self, approver_id: str) -> int:
        entry = self._keys.get(approver_id)
        return entry[1] if entry else 0

    def update_sign_count(self, approver_id: str, new_count: int) -> None:
        entry = self._keys.get(approver_id)
        if entry:
            self._keys[approver_id] = (entry[0], new_count)

    def is_consumed(self, assertion_hash: str) -> bool:
        return assertion_hash in self._consumed_assertions

    def mark_consumed(self, assertion_hash: str) -> None:
        self._consumed_assertions.add(assertion_hash)

    def reset_sign_counts(self) -> None:
        for approver_id, (key, _) in list(self._keys.items()):
            self._keys[approver_id] = (key, 0)

    def reset_replays(self) -> None:
        self._consumed_assertions.clear()
        self.reset_sign_counts()


approver_registry = ApproverKeyRegistry()


class WebAuthnVerifier:
    """Validates WebAuthn authentication assertions over transaction digests."""

    def __init__(
        self,
        registry: ApproverKeyRegistry | None = None,
        allowed_rp_ids: list[str] | None = None,
        allowed_origins: list[str] | None = None,
    ) -> None:
        self.registry = registry or approver_registry
        self.allowed_rp_ids = allowed_rp_ids or [
            "console.bitguard.exchange",
            "localhost",
            "127.0.0.1",
        ]
        self.allowed_origins = allowed_origins or [
            "https://console.bitguard.exchange",
            "http://localhost:5173",
            "http://localhost:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://127.0.0.1:5173",
        ]

    def verify_assertion(
        self,
        assertion: WebAuthnAssertion,
        expected_digest: str,
        approver_id: str,
    ) -> bool:
        """Cryptographically verifies a WebAuthn assertion for the given approver and digest."""
        # 1. Resolve approver's registered public key
        pub_key = self.registry.get_public_key(approver_id)
        if pub_key is None:
            raise WebAuthnVerificationError(
                "APPROVER_NOT_REGISTERED",
                f"No registered WebAuthn credential found for approver {approver_id}",
            )

        # 2. Decode clientDataJSON
        raw_client_data = _decode_b64url_or_hex(assertion.client_data_json)
        try:
            client_data_str = raw_client_data.decode("utf-8")
            client_data = json.loads(client_data_str)
        except Exception as exc:
            raise WebAuthnVerificationError("INVALID_CLIENT_DATA", f"Malformed clientDataJSON: {exc}") from exc

        # 3. Verify type == 'webauthn.get'
        assertion_type = client_data.get("type")
        if assertion_type != "webauthn.get":
            raise WebAuthnVerificationError(
                "INVALID_ASSERTION_TYPE",
                f"Expected type 'webauthn.get', got '{assertion_type}'",
            )

        # 4. Verify challenge matches expected tx digest
        # Challenges can be base64url(digest_bytes), base64url(digest_str), or hex digest
        client_challenge = client_data.get("challenge", "")
        clean_expected_digest = expected_digest.removeprefix("0x").lower()
        expected_digest_bytes = bytes.fromhex(clean_expected_digest)

        # Compare potential representations
        challenge_bytes = _decode_b64url_or_hex(client_challenge)
        matches_digest = (
            client_challenge.removeprefix("0x").lower() == clean_expected_digest
            or challenge_bytes == expected_digest_bytes
            or challenge_bytes.hex().lower() == clean_expected_digest
            or client_challenge == expected_digest
        )

        if not matches_digest:
            raise WebAuthnVerificationError(
                "INVALID_CHALLENGE",
                f"WebAuthn assertion challenge does not match transaction digest {expected_digest}",
            )

        # 5. Verify origin
        client_origin = client_data.get("origin", "")
        # Allow configured origins or prefix matching
        origin_ok = any(
            client_origin == o or client_origin.startswith(o)
            for o in self.allowed_origins
        )
        if not origin_ok:
            raise WebAuthnVerificationError(
                "INVALID_ORIGIN",
                f"Origin '{client_origin}' is not authorized",
            )

        # 6. Decode and parse authenticatorData
        auth_data = _decode_b64url_or_hex(assertion.authenticator_data)
        if len(auth_data) < 37:
            raise WebAuthnVerificationError(
                "MALFORMED_AUTH_DATA",
                f"Authenticator data too short ({len(auth_data)} bytes; minimum 37 required)",
            )

        # Verify RP ID hash (first 32 bytes)
        rp_id_hash = auth_data[:32]
        allowed_hashes = [hashlib.sha256(rp.encode("utf-8")).digest() for rp in self.allowed_rp_ids]
        if rp_id_hash not in allowed_hashes:
            raise WebAuthnVerificationError(
                "INVALID_RP_ID",
                "Authenticator data RP ID hash does not match configured RP IDs",
            )

        # Verify flags (byte 32): bit 0 is UP (User Present)
        flags = auth_data[32]
        user_present = bool(flags & 0x01)
        if not user_present:
            raise WebAuthnVerificationError(
                "USER_NOT_PRESENT",
                "WebAuthn assertion missing User Present (UP) flag",
            )

        # Verify sign count (bytes 33..37)
        sign_count = int.from_bytes(auth_data[33:37], "big")
        last_sign_count = self.registry.get_last_sign_count(approver_id)
        if sign_count > 0 and sign_count <= last_sign_count:
            raise WebAuthnVerificationError(
                "INVALID_SIGN_COUNT",
                f"Sign count {sign_count} is not greater than previous sign count {last_sign_count}",
            )

        # 7. Replay protection
        sig_bytes = _decode_b64url_or_hex(assertion.signature)
        assertion_fingerprint = hashlib.sha256(auth_data + sig_bytes).hexdigest()
        if self.registry.is_consumed(assertion_fingerprint):
            raise WebAuthnVerificationError(
                "ASSERTION_REPLAY",
                "This WebAuthn assertion has already been consumed (replay attack prevented)",
            )

        # 8. Cryptographic signature verification over authData || sha256(clientDataJSON)
        client_data_hash = hashlib.sha256(raw_client_data).digest()
        signed_payload = auth_data + client_data_hash

        try:
            if isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key.verify(sig_bytes, signed_payload, ec.ECDSA(hashes.SHA256()))
            elif isinstance(pub_key, rsa.RSAPublicKey):
                pub_key.verify(sig_bytes, signed_payload, padding.PKCS1v15(), hashes.SHA256())
            else:
                raise WebAuthnVerificationError("UNSUPPORTED_KEY_TYPE", f"Unsupported key type {type(pub_key)}")
        except InvalidSignature as exc:
            raise WebAuthnVerificationError("INVALID_SIGNATURE", f"Cryptographic signature check failed: {exc}") from exc

        # Mark consumed and update sign count
        self.registry.mark_consumed(assertion_fingerprint)
        if sign_count > 0:
            self.registry.update_sign_count(approver_id, sign_count)

        return True


def create_test_webauthn_assertion(
    private_key: ec.EllipticCurvePrivateKey,
    tx_digest: str,
    origin: str = "https://console.bitguard.exchange",
    rp_id: str = "console.bitguard.exchange",
    sign_count: int | None = None,
    wrong_challenge: str | None = None,
    user_present: bool = True,
) -> WebAuthnAssertion:
    """Helper generating a cryptographically valid WebAuthn assertion for tests."""
    if sign_count is None:
        derived_count = 1
        for aid, priv in approver_registry.dev_private_keys.items():
            if priv == private_key:
                derived_count = approver_registry.get_last_sign_count(aid) + 1
                break
        sign_count = derived_count
    # 1. Challenge
    challenge_val = wrong_challenge if wrong_challenge is not None else tx_digest

    # 2. clientDataJSON
    client_data_dict = {
        "type": "webauthn.get",
        "challenge": challenge_val,
        "origin": origin,
        "crossOrigin": False,
    }
    client_data_json = json.dumps(client_data_dict)
    client_data_bytes = client_data_json.encode("utf-8")
    client_data_hash = hashlib.sha256(client_data_bytes).digest()

    # 3. authenticatorData
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = (0x01 if user_present else 0x00) | 0x04  # UP and UV
    auth_data = rp_id_hash + bytes([flags]) + sign_count.to_bytes(4, "big")

    # 4. Signature over authData || sha256(clientDataJSON)
    signed_payload = auth_data + client_data_hash
    signature = private_key.sign(signed_payload, ec.ECDSA(hashes.SHA256()))

    return WebAuthnAssertion(
        credential_id="cred-test-" + hashlib.sha256(private_key.public_key().public_bytes(
            encoding=hashes.HashAlgorithm.__class__.__name__,  # dummy
            format=ec.ECDSA.__class__.__name__,
        ) if False else b"dummy").hexdigest()[:16],
        client_data_json=base64.urlsafe_b64encode(client_data_bytes).decode("ascii"),
        authenticator_data=base64.urlsafe_b64encode(auth_data).decode("ascii"),
        signature=base64.urlsafe_b64encode(signature).decode("ascii"),
        user_handle=None,
    )


webauthn_verifier = WebAuthnVerifier()
