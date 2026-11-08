"""Dead-man heartbeat sender for BitGuard (Milestone S24 / F17).

Sends a signed heartbeat to the Signer Shim every 5 seconds.
If the shim stops receiving valid heartbeats for 20 seconds, it rejects all tokens
and raises an alert, contained until heartbeats resume.
"""

import asyncio
import logging
import time
from typing import Any

import httpx

from services.bitguard.config import settings
from services.bitguard.policy.crypto import compute_content_hash, sign_content_hash
from services.bitguard.policy.store import policy_store

logger = logging.getLogger("bitguard.heartbeat")


class HeartbeatSender:
    """Manages periodic cryptographic heartbeats sent to the Signer Shim."""

    def __init__(
        self,
        shim_url: str | None = None,
        interval_seconds: float | None = None,
        instance_id: str | None = None,
    ) -> None:
        self.shim_url: str = shim_url or settings.signer_shim_url
        self.interval_seconds: float = (
            interval_seconds
            if interval_seconds is not None
            else settings.heartbeat_interval_seconds
        )
        self.instance_id: str = instance_id or settings.instance_id
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self.last_sent_at: float = 0.0
        self.consecutive_failures: int = 0
        self.last_error: str | None = None

    def get_active_policy_hash(self) -> str:
        """Retrieves active policy content hash or fallback hash."""
        active_pv = policy_store.get_active()
        if active_pv and active_pv.content_hash:
            return active_pv.content_hash
        return "genesis-default-policy-hash"

    def build_heartbeat_payload(
        self,
        timestamp: float | None = None,
        instance_id: str | None = None,
        policy_hash: str | None = None,
    ) -> dict[str, Any]:
        """Constructs and signs a canonical heartbeat payload."""
        ts = timestamp if timestamp is not None else time.time()
        inst = instance_id or self.instance_id
        pol_hash = policy_hash or self.get_active_policy_hash()

        canonical_str = f"{ts:.3f}:{inst}:{pol_hash}"
        digest = compute_content_hash({"heartbeat": canonical_str})
        signature = sign_content_hash(digest)

        return {
            "timestamp": ts,
            "instance_id": inst,
            "policy_hash": pol_hash,
            "signature": signature,
        }

    async def send_heartbeat_now(
        self,
        instance_id: str | None = None,
        policy_hash: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> tuple[bool, str]:
        """Sends a single signed heartbeat immediately to the Signer Shim."""
        payload = self.build_heartbeat_payload(
            instance_id=instance_id,
            policy_hash=policy_hash,
        )
        target_url = f"{self.shim_url.rstrip('/')}/heartbeat"

        try:
            if client is not None:
                resp = await client.post(target_url, json=payload, timeout=3.0)
            else:
                async with httpx.AsyncClient() as default_client:
                    resp = await default_client.post(target_url, json=payload, timeout=3.0)

            if resp.status_code == 200:
                self.last_sent_at = payload["timestamp"]
                self.consecutive_failures = 0
                self.last_error = None
                try:
                    from services.bitguard.metrics import update_heartbeat_age_metric
                    update_heartbeat_age_metric(0.0)
                except Exception:
                    pass
                logger.debug("heartbeat_sent_successfully: instance=%s", payload["instance_id"])
                return True, "Heartbeat accepted"
            else:
                self.consecutive_failures += 1
                self.last_error = f"Status {resp.status_code}: {resp.text}"
                logger.warning(
                    "heartbeat_send_rejected: status=%d error=%s",
                    resp.status_code,
                    self.last_error,
                )
                return False, self.last_error
        except Exception as exc:
            self.consecutive_failures += 1
            self.last_error = str(exc)
            logger.warning("heartbeat_send_failed: error=%s", exc)
            return False, str(exc)

    async def _heartbeat_loop(self) -> None:
        """Periodic background sender loop."""
        logger.info(
            "Heartbeat sender started for %s -> %s (interval: %.1fs)",
            self.instance_id,
            self.shim_url,
            self.interval_seconds,
        )
        # Send initial heartbeat immediately
        await self.send_heartbeat_now()

        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(self.interval_seconds)
                if not self._stop_event.is_set():
                    await self.send_heartbeat_now()
                    if self.last_sent_at > 0:
                        try:
                            from services.bitguard.metrics import update_heartbeat_age_metric
                            update_heartbeat_age_metric(time.time() - self.last_sent_at)
                        except Exception:
                            pass
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("heartbeat_loop_unexpected_error: %s", exc)

    def start(self) -> None:
        """Starts the background heartbeat sender."""
        if not settings.heartbeat_sender_enabled:
            logger.info("Heartbeat sender disabled via configuration")
            return
        if self._task is None or self._task.done():
            self._stop_event.clear()
            self._task = asyncio.create_task(self._heartbeat_loop())

    def stop(self) -> None:
        """Stops the background heartbeat sender."""
        self._stop_event.set()
        if self._task and not self._task.done():
            self._task.cancel()
            self._task = None
        logger.info("Heartbeat sender stopped")


# Global singleton instance
heartbeat_sender = HeartbeatSender()
