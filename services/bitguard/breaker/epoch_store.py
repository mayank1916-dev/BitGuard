"""Token epoch store tracking circuit breaker global token revocation (Milestone S18 / F1, F9).

Invariants:
- Invariant #1: Key Isolation (signing shim isolates signing keys).
- Invariant #2: Approval Binding & Verification (tokens bound to current epoch; older epochs are instantly revoked).
- Invariant #3: Fail-Closed Default (outage preserves the highest/strictest epoch seen).
"""

import logging
import threading

import redis

from services.bitguard.config import settings

logger = logging.getLogger("bitguard.breaker.epoch_store")


class TokenEpochStore:
    """Atomic token epoch tracker backed by Redis INCR with local fail-safe memory cache."""

    def __init__(
        self,
        redis_client: redis.Redis | None = None,
        key: str = "bitguard:token_epoch",
    ) -> None:
        self._key = key
        self._lock = threading.Lock()
        self._last_known_epoch: int = 1
        self._custom_redis = redis_client
        self._redis_instance: redis.Redis | None = redis_client

    def _get_redis(self) -> redis.Redis:
        if self._redis_instance is None:
            self._redis_instance = redis.Redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=0.2,
                socket_timeout=0.2,
            )
        return self._redis_instance

    def set_redis_client(self, client: redis.Redis | None) -> None:
        """Injects custom Redis client for testing."""
        with self._lock:
            self._redis_instance = client
            self._custom_redis = client

    def get_current_epoch(self) -> int:
        """Retrieves active token epoch from Redis or cached local state."""
        with self._lock:
            try:
                r = self._get_redis()
                val = r.get(self._key)
                if val is not None:
                    epoch = int(val)
                    if epoch > self._last_known_epoch:
                        self._last_known_epoch = epoch
                    return self._last_known_epoch
            except Exception as exc:
                logger.warning("token_epoch_store_redis_read_failure: %s; using last known epoch %d", exc, self._last_known_epoch)
            return self._last_known_epoch

    def increment_epoch(self) -> int:
        """Atomically increments token epoch in Redis and updates local fail-safe cache."""
        with self._lock:
            new_epoch = self._last_known_epoch + 1
            try:
                r = self._get_redis()
                val = r.incr(self._key)
                new_epoch = int(val)
            except Exception as exc:
                logger.warning("token_epoch_store_redis_incr_failure: %s; incrementing local epoch", exc)
            if new_epoch > self._last_known_epoch:
                self._last_known_epoch = new_epoch
            logger.info("token_epoch_incremented: new_epoch=%d", self._last_known_epoch)
            return self._last_known_epoch

    def reset(self, epoch: int = 1) -> None:
        """Resets epoch counter (test utility)."""
        with self._lock:
            self._last_known_epoch = epoch
            try:
                r = self._get_redis()
                r.set(self._key, str(epoch))
            except Exception:
                pass


# Global singleton instance
token_epoch_store = TokenEpochStore()
