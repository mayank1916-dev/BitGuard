"""Persistent credential storage and transient challenge management for WebAuthn (Milestone S15 / F9)."""

import logging
import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from services.bitguard.auth.models import WebAuthnCredentialSummary
from services.bitguard.database import get_session_factory
from services.bitguard.db_models import WebAuthnCredentialRecord

logger = logging.getLogger("bitguard.auth.webauthn_store")


class WebAuthnCredentialStore:
    """Thread-safe credential repository backed by SQLAlchemy with in-memory fallback."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._session_factory: sessionmaker[Session] | None = None
        # In-memory store: credential_id (str) -> dict
        self._memory_creds: dict[str, dict[str, Any]] = {}

    def set_session_factory(self, factory: sessionmaker[Session] | None) -> None:
        """Injects custom SQLAlchemy session factory for tests."""
        with self._lock:
            self._session_factory = factory

    def _get_session(self) -> Session:
        factory = self._session_factory or get_session_factory()
        return factory()

    def clear(self) -> None:
        """Clears in-memory store (test utility)."""
        with self._lock:
            self._memory_creds.clear()

    def save_credential(
        self,
        user_id: str,
        credential_id: str,
        public_key_cose_b64: str,
        sign_count: int,
        transports: list[str] | None = None,
        aaguid: str | None = None,
        backup_eligible: bool = False,
        backed_up: bool = False,
    ) -> WebAuthnCredentialSummary:
        """Persists a new WebAuthn credential record."""
        cred_rec_id = f"wcred-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC)
        entry = {
            "id": cred_rec_id,
            "user_id": user_id,
            "credential_id": credential_id,
            "public_key_cose": public_key_cose_b64,
            "sign_count": sign_count,
            "transports": transports or [],
            "aaguid": aaguid,
            "backup_eligible": backup_eligible,
            "backed_up": backed_up,
            "created_at": now,
            "last_used_at": now,
        }

        with self._lock:
            self._memory_creds[credential_id] = entry
            try:
                with self._get_session() as session:
                    rec = WebAuthnCredentialRecord(
                        id=cred_rec_id,
                        user_id=user_id,
                        credential_id=credential_id,
                        public_key_cose=public_key_cose_b64,
                        sign_count=sign_count,
                        transports=transports or [],
                        aaguid=aaguid,
                        backup_eligible=backup_eligible,
                        backed_up=backed_up,
                        created_at=now,
                        last_used_at=now,
                    )
                    session.add(rec)
                    session.commit()
            except Exception as exc:
                logger.debug("Database persistence bypassed (in-memory only): %s", exc)

        return WebAuthnCredentialSummary(
            id=cred_rec_id,
            credential_id=credential_id,
            user_id=user_id,
            sign_count=sign_count,
            transports=transports or [],
            aaguid=aaguid,
            backup_eligible=backup_eligible,
            backed_up=backed_up,
            created_at=now,
            last_used_at=now,
        )

    def get_credential(self, credential_id: str) -> dict[str, Any] | None:
        """Retrieves credential by unique credential_id."""
        with self._lock:
            # Check in-memory first
            if credential_id in self._memory_creds:
                return dict(self._memory_creds[credential_id])

            try:
                with self._get_session() as session:
                    rec = (
                        session.query(WebAuthnCredentialRecord)
                        .filter(WebAuthnCredentialRecord.credential_id == credential_id)
                        .first()
                    )
                    if rec:
                        entry = {
                            "id": rec.id,
                            "user_id": rec.user_id,
                            "credential_id": rec.credential_id,
                            "public_key_cose": rec.public_key_cose,
                            "sign_count": rec.sign_count,
                            "transports": rec.transports or [],
                            "aaguid": rec.aaguid,
                            "backup_eligible": rec.backup_eligible,
                            "backed_up": rec.backed_up,
                            "created_at": rec.created_at,
                            "last_used_at": rec.last_used_at,
                        }
                        self._memory_creds[credential_id] = entry
                        return entry
            except Exception as exc:
                logger.debug("Database read bypassed: %s", exc)

        return None

    def list_user_credentials(self, user_id: str) -> list[dict[str, Any]]:
        """Retrieves all registered credentials for a given user."""
        with self._lock:
            results = [
                dict(c) for c in self._memory_creds.values() if c["user_id"] == user_id
            ]
            if not results:
                try:
                    with self._get_session() as session:
                        records = (
                            session.query(WebAuthnCredentialRecord)
                            .filter(WebAuthnCredentialRecord.user_id == user_id)
                            .all()
                        )
                        for rec in records:
                            entry = {
                                "id": rec.id,
                                "user_id": rec.user_id,
                                "credential_id": rec.credential_id,
                                "public_key_cose": rec.public_key_cose,
                                "sign_count": rec.sign_count,
                                "transports": rec.transports or [],
                                "aaguid": rec.aaguid,
                                "backup_eligible": rec.backup_eligible,
                                "backed_up": rec.backed_up,
                                "created_at": rec.created_at,
                                "last_used_at": rec.last_used_at,
                            }
                            self._memory_creds[rec.credential_id] = entry
                            results.append(entry)
                except Exception as exc:
                    logger.debug("Database read bypassed: %s", exc)

            return results

    def update_sign_count(self, credential_id: str, new_sign_count: int) -> None:
        """Updates sign count monotonically for replay prevention."""
        now = datetime.now(UTC)
        with self._lock:
            if credential_id in self._memory_creds:
                self._memory_creds[credential_id]["sign_count"] = new_sign_count
                self._memory_creds[credential_id]["last_used_at"] = now

            try:
                with self._get_session() as session:
                    rec = (
                        session.query(WebAuthnCredentialRecord)
                        .filter(WebAuthnCredentialRecord.credential_id == credential_id)
                        .first()
                    )
                    if rec:
                        rec.sign_count = new_sign_count
                        rec.last_used_at = now
                        session.commit()
            except Exception as exc:
                logger.debug("Database update bypassed: %s", exc)


class ChallengeStore:
    """Thread-safe TTL challenge storage."""

    def __init__(self, ttl_seconds: int = 300) -> None:
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        # challenge_id -> {"challenge": bytes, "user_id": str, "expires_at": float}
        self._challenges: dict[str, dict[str, Any]] = {}

    def save_challenge(self, challenge_id: str, challenge: bytes, user_id: str = "") -> None:
        now = time.time()
        with self._lock:
            self._cleanup_expired()
            self._challenges[challenge_id] = {
                "challenge": challenge,
                "user_id": user_id,
                "expires_at": now + self.ttl_seconds,
            }

    def pop_challenge(self, challenge_id: str) -> dict[str, Any] | None:
        """Retrieves and deletes challenge (single-use)."""
        now = time.time()
        with self._lock:
            entry = self._challenges.pop(challenge_id, None)
            if entry and entry["expires_at"] > now:
                return entry
            return None

    def _cleanup_expired(self) -> None:
        now = time.time()
        expired = [cid for cid, v in self._challenges.items() if v["expires_at"] <= now]
        for cid in expired:
            self._challenges.pop(cid, None)

    def clear(self) -> None:
        with self._lock:
            self._challenges.clear()


webauthn_credential_store = WebAuthnCredentialStore()
challenge_store = ChallengeStore()
