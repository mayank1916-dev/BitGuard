"""Rate limiting middleware per caller identity and route category (Milestone S24 / F17).

Enforces strict limits on sensitive admin / policy / breaker endpoints and
standard limits on high-volume evaluation endpoints.
"""

import logging
import time
from collections import defaultdict
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from services.bitguard.config import settings

logger = logging.getLogger("bitguard.rate_limiter")


class RateLimiter:
    """Sliding window / fixed window rate limiter with Redis backend and in-memory fallback."""

    def __init__(self) -> None:
        self._memory_counters: dict[str, list[float]] = defaultdict(list)
        self._sync_redis: Any | None = None

    def set_sync_redis(self, client: Any) -> None:
        """Injects custom sync Redis client for testing."""
        self._sync_redis = client

    def _get_sync_redis(self) -> Any:
        if self._sync_redis is None:
            try:
                import redis
                self._sync_redis = redis.Redis.from_url(
                    settings.redis_url,
                    socket_connect_timeout=0.5,
                    socket_timeout=0.5,
                    decode_responses=True,
                )
            except Exception as exc:
                logger.debug("redis_rate_limit_init_error: %s", exc)
                return None
        return self._sync_redis

    def is_allowed(self, identity: str, route_category: str, limit_per_minute: int) -> tuple[bool, int]:
        """Checks if the request is within rate limits.

        Returns (allowed: bool, current_count: int).
        """
        if not getattr(settings, "rate_limit_enabled", True):
            return True, 0

        current_ts = time.time()
        minute_bucket = int(current_ts // 60)
        redis_key = f"ratelimit:{identity}:{route_category}:{minute_bucket}"

        # Try Redis first
        try:
            r = self._get_sync_redis()
            if r is not None:
                count = r.incr(redis_key)
                if count == 1:
                    r.expire(redis_key, 65)
                if count > limit_per_minute:
                    return False, count
                return True, count
        except Exception as exc:
            logger.debug("redis_rate_limit_bypassed_to_memory: %s", exc)

        # In-memory sliding window fallback
        cutoff = current_ts - 60.0
        window = [t for t in self._memory_counters[redis_key] if t > cutoff]
        window.append(current_ts)
        self._memory_counters[redis_key] = window

        count = len(window)
        if count > limit_per_minute:
            return False, count
        return True, count

    def reset(self) -> None:
        """Resets in-memory counters for test isolation."""
        self._memory_counters.clear()


rate_limiter = RateLimiter()


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """Enforces per-caller and per-route rate limits."""

    EXEMPT_PATHS = {
        "/healthz",
        "/metrics",
        "/docs",
        "/openapi.json",
        "/redoc",
    }

    def _resolve_identity(self, request: Request) -> str:
        """Resolves caller identity from Bearer token, client cert, or remote address."""
        # Check mTLS SAN header
        client_san = request.headers.get("X-Client-Cert-SAN") or request.headers.get("X-Caller-ID")
        if client_san:
            return client_san.strip()

        # Check Authorization Bearer header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.removeprefix("Bearer ").strip()
            # Simple payload decode without verification to identify caller bucket
            parts = token.split(".")
            if len(parts) == 3:
                try:
                    import base64
                    import json
                    padding = "=" * (-len(parts[1]) % 4)
                    claims_json = base64.urlsafe_b64decode(parts[1] + padding)
                    claims = json.loads(claims_json)
                    sub = claims.get("sub") or claims.get("preferred_username") or claims.get("email")
                    if sub:
                        return f"user:{sub}"
                except Exception:
                    pass

        # Fall back to client IP address
        if request.client and request.client.host:
            return f"ip:{request.client.host}"
        return "ip:unknown"

    def _categorize_route(self, path: str) -> tuple[str, int]:
        """Categorizes route into admin (strict) or standard (normal) with limits."""
        admin_indicators = [
            "/v1/breaker",
            "/v1/policies",
            "/v1/break-glass",
            "/v1/incidents",
            "/v1/admin",
        ]
        for ind in admin_indicators:
            if path.startswith(ind):
                return "admin", settings.rate_limit_admin_per_minute

        if path.startswith("/v1/holds/") and ("/cancel" in path or "/approve" in path):
            return "admin", settings.rate_limit_admin_per_minute

        return "standard", settings.rate_limit_standard_per_minute

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        # Exempt paths
        if path in self.EXEMPT_PATHS or path.startswith("/v1/stream"):
            return await call_next(request)

        identity = self._resolve_identity(request)
        category, limit = self._categorize_route(path)

        allowed, count = rate_limiter.is_allowed(identity, category, limit)
        if not allowed:
            logger.warning(
                "rate_limit_exceeded: caller=%s path=%s category=%s count=%d limit=%d",
                identity,
                path,
                category,
                count,
                limit,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "detail": f"Rate limit exceeded for '{identity}' on {category} endpoints. Limit: {limit}/min.",
                },
                headers={"Retry-After": "60"},
            )

        return await call_next(request)
