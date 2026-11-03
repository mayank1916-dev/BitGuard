"""Atomic single-use token nonce tracking with Redis SET NX (Milestone S11)."""

import logging

import redis

from services.signer_shim.config import settings

logger = logging.getLogger("signer_shim.nonce_store")


class NonceStore:
    """Atomic nonce deduplication store preventing approval token replays."""

    def __init__(self, redis_client: redis.Redis | None = None) -> None:
        self._redis = redis_client or redis.Redis.from_url(
            settings.redis_url,
            decode_responses=True,
        )

    def set_redis_client(self, client: redis.Redis) -> None:
        """Injects or updates the Redis client instance (test utility)."""
        self._redis = client

    def consume_nonce(self, nonce: str, ttl_seconds: int | None = None) -> bool:
        """Atomically checks and consumes a 128-bit approval token nonce using SET NX.

        Returns:
            True if nonce was successfully reserved and marked consumed.
            False if nonce has already been consumed (replay attack).
        Raises:
            redis.exceptions.RedisError if Redis store is unavailable (fail closed).
        """
        if not nonce or not isinstance(nonce, str):
            return False

        ttl = ttl_seconds or settings.nonce_ttl_seconds
        key = f"nonce:{nonce.strip().lower()}"

        try:
            # SET key 1 NX EX ttl
            # Returns True if key was set, None if key already existed
            res = self._redis.set(name=key, value="1", ex=ttl, nx=True)
            return bool(res)
        except Exception as exc:
            logger.error("nonce_store_redis_failure: %s", exc)
            raise


# Singleton instance
nonce_store = NonceStore()
