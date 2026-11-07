"""Atomic distributed limit store with sliding windows and Redis Lua scripting (Milestone S07 / F3)."""

import logging
import threading
import time
import uuid
from typing import Any

import redis
from pydantic import BaseModel, Field
from redis.commands.core import Script

from services.bitguard.config import settings
from services.bitguard.limits.lua_scripts import (
    LUA_COMMIT,
    LUA_GET_USAGE,
    LUA_RELEASE,
    LUA_RESERVE,
)

logger = logging.getLogger("bitguard.limit_store")


class ReservationResult(BaseModel):
    """Result of an atomic limit reservation attempt."""

    ok: bool = Field(description="True if capacity was reserved across all scopes")
    remaining: int = Field(description="Minimum remaining capacity across checked scopes")
    reservation_id: str = Field(default="", description="Unique identifier for committed/release lifecycle")
    error: str | None = Field(default=None, description="Failure reason code if rejected or unavailable")
    source: str = Field(default="REDIS", description="Data store engine: REDIS, LOCAL_FALLBACK, or FAIL_CLOSED")

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)


class ScopeBuilder:
    """Canonical key naming for distributed sliding window scopes."""

    @staticmethod
    def wallet_scope(wallet: str, window_seconds: int = 3600, prefix: str = "") -> str:
        return f"{prefix}limit:scope:wallet:{wallet.lower()}:{window_seconds}"

    @staticmethod
    def asset_scope(asset: str, window_seconds: int = 3600, prefix: str = "") -> str:
        return f"{prefix}limit:scope:asset:{asset.upper()}:{window_seconds}"

    @staticmethod
    def chain_scope(chain: str, window_seconds: int = 3600, prefix: str = "") -> str:
        return f"{prefix}limit:scope:chain:{chain.lower()}:{window_seconds}"

    @staticmethod
    def global_scope(window_seconds: int = 3600, prefix: str = "") -> str:
        return f"{prefix}limit:scope:global:{window_seconds}"

    @classmethod
    def all_scopes(cls, wallet: str, asset: str, chain: str, window_seconds: int = 3600, prefix: str = "") -> list[str]:
        return [
            cls.wallet_scope(wallet, window_seconds, prefix=prefix),
            cls.asset_scope(asset, window_seconds, prefix=prefix),
            cls.chain_scope(chain, window_seconds, prefix=prefix),
            cls.global_scope(window_seconds, prefix=prefix),
        ]


class LocalFallbackStore:
    """Conservative in-memory fallback limit store active during Redis outages.

    Invariant #3: Never return allow-all. Strict conservative local limits apply.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # scope_key -> list of (timestamp, amount, res_id, is_committed)
        self._entries: dict[str, list[dict[str, Any]]] = {}
        # res_id -> dict(amount, scopes, expires_at, status, window)
        self._reservations: dict[str, dict[str, Any]] = {}

    def reserve(
        self,
        scope_keys: list[str],
        amount: int,
        window_seconds: int,
        cap: int | list[int],
        reservation_ttl: int = 120,
        now: int | None = None,
    ) -> ReservationResult:
        current_now = now if now is not None else int(time.time())
        window_start = current_now - window_seconds
        res_id = f"local_{uuid.uuid4().hex}"

        with self._lock:
            # Resolve caps: apply conservative ceiling from settings
            conservative_cap_limit = settings.local_fallback_cap
            caps: list[int] = []
            if isinstance(cap, list):
                caps = [min(c, conservative_cap_limit) for c in cap]
            else:
                caps = [min(cap, conservative_cap_limit) for _ in scope_keys]

            # Phase 1: Prune and check limits across all scopes
            min_remaining = -1
            for idx, k in enumerate(scope_keys):
                k_cap = caps[idx]
                records = self._entries.get(k, [])
                active_records: list[dict[str, Any]] = []
                used = 0

                for r in records:
                    if r["is_committed"]:
                        if r["ts"] >= window_start:
                            active_records.append(r)
                            used += int(r["amount"])
                    else:
                        if r["expires_at"] > current_now:
                            active_records.append(r)
                            used += int(r["amount"])

                self._entries[k] = active_records

                if used + amount > k_cap:
                    remaining = max(0, k_cap - used)
                    logger.warning(
                        "local_fallback_cap_exceeded scope=%s amount=%s used=%s cap=%s",
                        k,
                        amount,
                        used,
                        k_cap,
                    )
                    return ReservationResult(
                        ok=False,
                        remaining=remaining,
                        reservation_id="",
                        error="LIMIT_STORE_UNAVAILABLE",
                        source="LOCAL_FALLBACK",
                    )

                rem = k_cap - (used + amount)
                if min_remaining == -1 or rem < min_remaining:
                    min_remaining = rem

            # Phase 2: Add reservations
            expiry_time = current_now + reservation_ttl
            for k in scope_keys:
                self._entries[k].append(
                    {
                        "ts": current_now,
                        "amount": amount,
                        "res_id": res_id,
                        "is_committed": False,
                        "expires_at": expiry_time,
                    }
                )

            self._reservations[res_id] = {
                "amount": amount,
                "scopes": scope_keys,
                "expires_at": expiry_time,
                "status": "RESERVED",
                "window": window_seconds,
            }

            return ReservationResult(
                ok=True,
                remaining=min_remaining,
                reservation_id=res_id,
                source="LOCAL_FALLBACK",
            )

    def commit(self, reservation_id: str, now: int | None = None) -> bool:
        current_now = now if now is not None else int(time.time())
        with self._lock:
            res = self._reservations.get(reservation_id)
            if not res or res["status"] != "RESERVED":
                return False
            if current_now > res["expires_at"]:
                return False

            res["status"] = "COMMITTED"
            for k in res["scopes"]:
                for r in self._entries.get(k, []):
                    if r["res_id"] == reservation_id:
                        r["is_committed"] = True
                        r["ts"] = current_now
            return True

    def release(self, reservation_id: str) -> bool:
        with self._lock:
            res = self._reservations.get(reservation_id)
            if not res or res["status"] != "RESERVED":
                return False

            res["status"] = "RELEASED"
            for k in res["scopes"]:
                self._entries[k] = [
                    r for r in self._entries.get(k, []) if r["res_id"] != reservation_id
                ]
            return True


class LimitStore:
    """Atomic distributed limit store combining Redis Lua scripts and local fail-closed fallbacks."""

    def __init__(self, redis_client: redis.Redis | None = None, key_prefix: str = "") -> None:
        self.key_prefix = key_prefix
        self._redis = redis_client or redis.Redis.from_url(
            settings.redis_url,
            decode_responses=True,
        )
        self._local_fallback = LocalFallbackStore()
        self._reserve_script: Script | None = None
        self._commit_script: Script | None = None
        self._release_script: Script | None = None
        self._get_usage_script: Script | None = None
        self._register_scripts()

    def _prefix_scope(self, scope_key: str) -> str:
        """Applies store namespace prefix if configured and not already present."""
        if self.key_prefix and not scope_key.startswith(self.key_prefix):
            return f"{self.key_prefix}{scope_key}"
        return scope_key

    def clear_namespace(self) -> int:
        """Deletes all keys belonging to this store's key_prefix namespace."""
        if not self.key_prefix:
            return 0
        try:
            pattern = f"{self.key_prefix}*"
            keys = list(self._redis.scan_iter(match=pattern, count=200))
            if keys:
                return int(self._redis.delete(*keys))
        except Exception as exc:
            logger.warning("limit_store_clear_namespace_failed prefix=%s: %s", self.key_prefix, exc)
        return 0

    def _register_scripts(self) -> None:
        """Loads and pre-compiles Lua scripts on Redis connection."""
        try:
            self._reserve_script = self._redis.register_script(LUA_RESERVE)
            self._commit_script = self._redis.register_script(LUA_COMMIT)
            self._release_script = self._redis.register_script(LUA_RELEASE)
            self._get_usage_script = self._redis.register_script(LUA_GET_USAGE)
        except Exception as exc:
            logger.warning("redis_script_registration_failed: %s", exc)

    def set_redis_client(self, client: redis.Redis) -> None:
        """Allows injecting or re-binding a Redis client instance."""
        self._redis = client
        self._register_scripts()

    def reserve(
        self,
        scope_keys: list[str],
        amount: int,
        window_seconds: int = 3600,
        cap: int | list[int] = 100_000,
        reservation_ttl: int | None = None,
        now: int | None = None,
    ) -> ReservationResult:
        """Atomically checks and reserves volume across multiple scopes in smallest integer units."""
        if amount <= 0:
            raise ValueError(f"Reservation amount must be positive, got {amount}")
        if not isinstance(amount, int):
            raise TypeError(f"Amount must be an integer, got {type(amount).__name__}")

        current_ttl = reservation_ttl or settings.limit_reservation_ttl_seconds
        current_now = now if now is not None else int(time.time())
        res_id = uuid.uuid4().hex

        # Format cap argument: integer or comma-separated list
        raw_cap_str: str
        if isinstance(cap, list):
            raw_cap_str = ",".join(str(int(c)) for c in cap)
        else:
            raw_cap_str = str(int(cap))

        prefixed_keys = [self._prefix_scope(k) for k in scope_keys]

        try:
            if self._reserve_script is None:
                self._register_scripts()
            if self._reserve_script is None:
                raise redis.exceptions.ConnectionError("Script not loaded")

            result = self._reserve_script(
                keys=prefixed_keys,
                args=[amount, window_seconds, raw_cap_str, res_id, current_now, current_ttl],
            )
            ok_flag, remaining, granted_res_id = result

            if int(ok_flag) == 1:
                return ReservationResult(
                    ok=True,
                    remaining=int(remaining),
                    reservation_id=str(granted_res_id),
                    source="REDIS",
                )
            return ReservationResult(
                ok=False,
                remaining=int(remaining),
                reservation_id="",
                error="LIMIT_EXCEEDED",
                source="REDIS",
            )

        except (redis.exceptions.RedisError, Exception) as exc:
            logger.warning(
                "limit_store_redis_failure: %s (action=falling_back_to_local_caps)",
                exc,
            )
            if not settings.local_caps_enabled:
                return ReservationResult(
                    ok=False,
                    remaining=0,
                    reservation_id="",
                    error="LIMIT_STORE_UNAVAILABLE",
                    source="FAIL_CLOSED",
                )
            # Conservative local fallback
            return self._local_fallback.reserve(
                scope_keys=prefixed_keys,
                amount=amount,
                window_seconds=window_seconds,
                cap=cap,
                reservation_ttl=current_ttl,
                now=current_now,
            )

    def commit(self, reservation_id: str, now: int | None = None) -> bool:
        """Commits a pending reservation turning it into enduring sliding-window volume."""
        if not reservation_id:
            return False

        if reservation_id.startswith("local_"):
            return self._local_fallback.commit(reservation_id, now=now)

        current_now = now if now is not None else int(time.time())
        try:
            if self._commit_script is None:
                self._register_scripts()
            if self._commit_script is None:
                return False

            result = self._commit_script(keys=[], args=[reservation_id, current_now])
            return bool(int(result[0]) == 1)
        except Exception as exc:
            logger.warning("limit_store_commit_failed res_id=%s: %s", reservation_id, exc)
            return False

    def release(self, reservation_id: str) -> bool:
        """Immediately frees an active uncommitted reservation."""
        if not reservation_id:
            return False

        if reservation_id.startswith("local_"):
            return self._local_fallback.release(reservation_id)

        try:
            if self._release_script is None:
                self._register_scripts()
            if self._release_script is None:
                return False

            result = self._release_script(keys=[], args=[reservation_id])
            return bool(int(result[0]) == 1)
        except Exception as exc:
            logger.warning("limit_store_release_failed res_id=%s: %s", reservation_id, exc)
            return False

    def get_usage(
        self,
        scope_key: str,
        window_seconds: int = 3600,
        now: int | None = None,
    ) -> tuple[int, int, int]:
        """Returns (committed_volume, reserved_volume, total_volume) for a scope."""
        current_now = now if now is not None else int(time.time())
        prefixed_scope = self._prefix_scope(scope_key)
        try:
            if self._get_usage_script is None:
                self._register_scripts()
            if self._get_usage_script is None:
                return (0, 0, 0)

            res = self._get_usage_script(keys=[prefixed_scope], args=[window_seconds, current_now])
            return (int(res[0]), int(res[1]), int(res[2]))
        except Exception as exc:
            logger.warning("limit_store_get_usage_failed scope=%s: %s", prefixed_scope, exc)
            return (0, 0, 0)

    def get_remaining(
        self,
        scope_key: str,
        window_seconds: int = 3600,
        cap: int = 100_000,
        now: int | None = None,
    ) -> int:
        """Returns remaining volume capacity for a scope within its sliding window."""
        _, _, total_used = self.get_usage(scope_key, window_seconds, now=now)
        return max(0, cap - total_used)


# Global singleton instance
limit_store = LimitStore()
