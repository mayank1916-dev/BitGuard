"""Config and state integrity verification for BitGuard (Milestone S24 / F17).

Checks at startup and every minute:
1. Active policy content hash matches stored hash and Ed25519 release signature.
2. Token key set active key integrity and non-tampered status.
3. Feature flags and production invariants.

Mismatch => Fail closed: trips circuit breaker to HOLD, sets integrity status unhealthy,
and raises an alert.
"""

import asyncio
import logging
import time

from services.bitguard.breaker.store import distributed_breaker_store
from services.bitguard.config import settings
from services.bitguard.models import BreakerStateEnum
from services.bitguard.policy.crypto import compute_content_hash, verify_ed25519_signature
from services.bitguard.policy.store import policy_store
from services.bitguard.tokens.keys import KeyStatus
from services.bitguard.tokens.manager import token_manager

logger = logging.getLogger("bitguard.integrity")


class ConfigIntegrityChecker:
    """Performs cryptographic and invariant checks across configuration and active state."""

    def __init__(self, interval_seconds: int | None = None) -> None:
        self.interval_seconds: int = int(
            interval_seconds
            if interval_seconds is not None
            else getattr(settings, "config_integrity_check_interval_seconds", 60)
        )
        self.is_healthy: bool = True
        self.last_checked_at: float = 0.0
        self.last_errors: list[str] = []
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()

    def check_policy_integrity(self) -> tuple[bool, str]:
        """Verifies active policy content matches hash and Ed25519 signature."""
        active_pv = policy_store.get_active()
        if not active_pv:
            return True, "No active policy version set"

        # 1. Recompute SHA-256 hash of content
        content_to_hash = getattr(active_pv, "content", None)
        if content_to_hash is None and hasattr(active_pv, "rules"):
            content_to_hash = active_pv.rules

        if content_to_hash is not None and getattr(active_pv, "content_hash", None):
            computed = compute_content_hash(content_to_hash)
            if computed != active_pv.content_hash:
                return (
                    False,
                    f"Policy hash mismatch: computed '{computed[:12]}' vs recorded '{active_pv.content_hash[:12]}'",
                )

        # 2. Verify Ed25519 signature if present
        if active_pv.signatures:
            sig = active_pv.signatures[0]
            sig_hex = sig.get("signature") if isinstance(sig, dict) else getattr(sig, "signature", str(sig))
            if sig_hex and not verify_ed25519_signature(active_pv.content_hash, sig_hex):
                return False, f"Policy signature verification failed for version {active_pv.version}"

        return True, "Policy integrity verified"

    def check_token_keys_integrity(self) -> tuple[bool, str]:
        """Verifies token manager has an active, valid signing key."""
        try:
            active_key = token_manager.key_set.get_active_key()
            if active_key.status != KeyStatus.ACTIVE:
                return False, f"Active token key {active_key.kid} is not in ACTIVE status"
            if not active_key.kid:
                return False, "Active token key is missing kid"
            return True, f"Token key integrity verified (active kid: {active_key.kid})"
        except Exception as exc:
            return False, f"Token key integrity check failure: {exc}"

    def check_feature_flags_integrity(self) -> tuple[bool, str]:
        """Verifies environment security invariants and feature flag boundaries."""
        # Invariant: Never allow dev auth bypass in production
        if settings.environment.lower() == "production" and settings.dev_auth_bypass:
            return False, "Production environment violation: dev_auth_bypass is enabled"

        # Invariant: Token TTL must be within tight defensive bounds (<= 300s)
        if settings.approval_token_ttl_seconds <= 0 or settings.approval_token_ttl_seconds > 300:
            return (
                False,
                f"Insecure token TTL: {settings.approval_token_ttl_seconds}s (must be between 1 and 300s)",
            )

        return True, "Feature flags and invariants verified"

    def perform_full_check(self) -> tuple[bool, list[str]]:
        """Executes all integrity checks and trips circuit breaker on failure."""
        errors: list[str] = []

        ok_pol, msg_pol = self.check_policy_integrity()
        if not ok_pol:
            errors.append(msg_pol)

        ok_tok, msg_tok = self.check_token_keys_integrity()
        if not ok_tok:
            errors.append(msg_tok)

        ok_flags, msg_flags = self.check_feature_flags_integrity()
        if not ok_flags:
            errors.append(msg_flags)

        self.last_checked_at = time.time()
        if errors:
            self.is_healthy = False
            self.last_errors = errors
            logger.critical(
                "CONFIG_INTEGRITY_MISMATCH: Trip breaker to HOLD! Fail closed immediately. Errors: %s",
                errors,
            )
            # Trip breaker fail closed
            try:
                distributed_breaker_store.escalate(
                    target_state=BreakerStateEnum.HOLD,
                    reason=f"Config integrity check failure: {'; '.join(errors)}",
                    updated_by="system:integrity_checker",
                )
            except Exception as exc:
                logger.error("breaker_escalate_integrity_failed: %s", exc)
            return False, errors

        self.is_healthy = True
        self.last_errors = []
        logger.debug("Config integrity check passed")
        return True, []

    async def _monitor_loop(self) -> None:
        """Periodic background integrity verification loop."""
        logger.info(
            "Config integrity monitor started (interval: %ds)",
            self.interval_seconds,
        )
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(float(self.interval_seconds))
                if not self._stop_event.is_set():
                    self.perform_full_check()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("integrity_monitor_unexpected_error: %s", exc)

    def start(self) -> None:
        """Starts periodic integrity monitor and runs initial check."""
        # Initial check at startup
        self.perform_full_check()
        if self._task is None or self._task.done():
            self._stop_event.clear()
            self._task = asyncio.create_task(self._monitor_loop())

    def stop(self) -> None:
        """Stops the periodic integrity monitor."""
        self._stop_event.set()
        if self._task and not self._task.done():
            self._task.cancel()
            self._task = None
        logger.info("Config integrity monitor stopped")


# Global singleton instance
config_integrity_checker = ConfigIntegrityChecker()
