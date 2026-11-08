"""Dead-man heartbeat receiver and freshness verification for Signer Shim (Milestone S24 / F17).

If no valid signed heartbeat is received from BitGuard within the configurable timeout
(default 20 s), the shim refuses all signing requests and raises an alert.
"""

import logging
import time

from pydantic import BaseModel, Field

from services.bitguard.policy.crypto import compute_content_hash, verify_ed25519_signature
from services.signer_shim.config import settings

logger = logging.getLogger("signer_shim.heartbeat")


class HeartbeatMessage(BaseModel):
    """Signed heartbeat message sent periodically by BitGuard instances."""

    timestamp: float = Field(description="Heartbeat generation Unix timestamp in seconds")
    instance_id: str = Field(description="Originating BitGuard instance identifier (e.g. bitguard-1)")
    policy_hash: str = Field(description="Current active policy hash running on BitGuard")
    signature: str = Field(description="Cryptographic signature over the canonical heartbeat digest")


class HeartbeatTracker:
    """Tracks heartbeat arrival, validates cryptographic signatures, and checks freshness."""

    def __init__(self, timeout_seconds: float | None = None) -> None:
        self.timeout_seconds: float = float(timeout_seconds if timeout_seconds is not None else getattr(settings, 'heartbeat_timeout_seconds', 20.0))
        self.last_heartbeat_time: float = 0.0
        self.last_instance_id: str = ""
        self.last_policy_hash: str = ""
        self.consecutive_failures: int = 0

    def compute_digest(self, timestamp: float, instance_id: str, policy_hash: str) -> str:
        """Computes deterministic digest for signature verification."""
        canonical_str = f"{timestamp:.3f}:{instance_id}:{policy_hash}"
        return compute_content_hash({"heartbeat": canonical_str})

    def record_heartbeat(self, msg: HeartbeatMessage, now: float | None = None) -> tuple[bool, str]:
        """Validates and records an incoming heartbeat.

        Checks:
        1. Clock skew within acceptable window (+-60 seconds)
        2. Cryptographic signature over the heartbeat payload
        """
        current_time = now if now is not None else time.time()

        # Check timestamp freshness to reject replays or severe skew
        if abs(current_time - msg.timestamp) > 60.0:
            logger.warning(
                "heartbeat_rejected: clock_skew_exceeded msg_ts=%.2f now=%.2f diff=%.2f",
                msg.timestamp,
                current_time,
                abs(current_time - msg.timestamp),
            )
            return False, "Heartbeat timestamp is outside acceptable clock skew window"

        digest = self.compute_digest(msg.timestamp, msg.instance_id, msg.policy_hash)
        if not verify_ed25519_signature(digest, msg.signature):
            logger.error("heartbeat_rejected: invalid_ed25519_signature instance=%s", msg.instance_id)
            self.consecutive_failures += 1
            return False, "Invalid heartbeat cryptographic signature"

        self.last_heartbeat_time = current_time
        self.last_instance_id = msg.instance_id
        self.last_policy_hash = msg.policy_hash
        self.consecutive_failures = 0
        logger.debug(
            "heartbeat_accepted: instance=%s policy_hash=%s",
            msg.instance_id,
            msg.policy_hash[:12],
        )
        return True, "Heartbeat accepted"

    def is_healthy(self, now: float | None = None) -> bool:
        """Returns True if a valid heartbeat has been observed within the timeout window."""
        if self.last_heartbeat_time <= 0:
            return False
        current_time = now if now is not None else time.time()
        age = current_time - self.last_heartbeat_time
        return age <= self.timeout_seconds

    def get_heartbeat_age(self, now: float | None = None) -> float:
        """Returns seconds elapsed since last valid heartbeat."""
        if self.last_heartbeat_time <= 0:
            return 999999.0
        current_time = now if now is not None else time.time()
        return max(0.0, current_time - self.last_heartbeat_time)

    def reset(self) -> None:
        """Resets tracker state for test isolation."""
        self.last_heartbeat_time = 0.0
        self.last_instance_id = ""
        self.last_policy_hash = ""
        self.consecutive_failures = 0


# Global singleton tracker for signer shim
heartbeat_tracker = HeartbeatTracker()
