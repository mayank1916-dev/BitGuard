"""Out-of-band asynchronous address profile worker and cache (Milestone S27).

Invariants:
- Invariant #1: Never on the hot path (profiles are cached with TTL).
- Invariant #3: Fail-Closed Default. Missing profile adds ELEVATED_RISK_UNPROFILED weight.
"""

import hashlib
import json
import logging
import threading
import time
from datetime import UTC, datetime
from typing import Any

from services.bitguard.profiler.lists import SanctionListStore, sanction_store
from services.bitguard.profiler.models import AddressProfile
from services.bitguard.profiler.provider import MockTaintProvider, TaintProvider
from services.bitguard.rpc.client import MockRpcClient, RpcClient

logger = logging.getLogger("bitguard.profiler.worker")


class ProfileWorker:
    """Asynchronous background worker collecting on-chain metadata and compliance profiles.

    Results are stored in Redis (or in-memory cache) with TTL.
    """

    def __init__(
        self,
        rpc_client: RpcClient | None = None,
        taint_provider: TaintProvider | None = None,
        list_store: SanctionListStore | None = None,
        ttl_seconds: int = 3600,
    ) -> None:
        self.rpc_client: RpcClient = rpc_client or MockRpcClient()
        self.taint_provider: TaintProvider = taint_provider or MockTaintProvider()
        self.list_store: SanctionListStore = list_store or sanction_store
        self.ttl_seconds = ttl_seconds

        self._redis: Any = None
        self._memory_cache: dict[str, tuple[AddressProfile, float]] = {}
        self._wallet_destinations: dict[str, set[str]] = {}
        self._contract_age_overrides: dict[str, tuple[int, float]] = {}
        self._lock = threading.RLock()

    def set_redis_client(self, redis_client: Any) -> None:
        self._redis = redis_client

    def set_contract_age(self, address: str, age_blocks: int, age_days: float) -> None:
        """Helper for test environments to set contract age."""
        self._contract_age_overrides[address.lower()] = (age_blocks, age_days)

    # -----------------------------------------------------------------
    # Fast Path Cache Read (Microseconds, Non-Blocking)
    # -----------------------------------------------------------------

    def get_cached_profile(self, chain: str, address: str) -> AddressProfile | None:
        """Reads profile from local memory or Redis cache.

        Returns None on cache miss (invoking caller will apply ELEVATED_RISK_UNPROFILED).
        """
        if not address:
            return None
        clean_addr = address.strip().lower()
        cache_key = f"profile:{chain.lower()}:{clean_addr}"
        now = time.time()

        # 1. In-memory read
        with self._lock:
            entry = self._memory_cache.get(cache_key)
            if entry is not None:
                profile, expires_at = entry
                if now < expires_at:
                    return profile
                del self._memory_cache[cache_key]

        # 2. Redis read if available
        if self._redis is not None:
            try:
                raw_json = self._redis.get(cache_key)
                if raw_json:
                    profile_dict = json.loads(raw_json)
                    profile = AddressProfile.model_validate(profile_dict)
                    with self._lock:
                        self._memory_cache[cache_key] = (profile, profile.expires_at)
                    return profile
            except Exception as exc:
                logger.warning("profile_redis_read_failure: %s", exc)

        return None

    # -----------------------------------------------------------------
    # Destination First-Seen Tracking
    # -----------------------------------------------------------------

    def is_first_time_destination(self, wallet: str, destination: str) -> bool:
        """Checks whether destination is first-seen for the given wallet."""
        if not wallet or not destination:
            return True
        w = wallet.strip().lower()
        d = destination.strip().lower()

        if self._redis is not None:
            try:
                return not bool(self._redis.sismember(f"wallet_dests:{w}", d))
            except Exception:
                pass

        with self._lock:
            dests = self._wallet_destinations.get(w, set())
            return d not in dests

    def record_wallet_destination(self, wallet: str, destination: str) -> None:
        """Records that a wallet has sent to destination address."""
        if not wallet or not destination:
            return
        w = wallet.strip().lower()
        d = destination.strip().lower()

        if self._redis is not None:
            try:
                self._redis.sadd(f"wallet_dests:{w}", d)
            except Exception:
                pass

        with self._lock:
            if w not in self._wallet_destinations:
                self._wallet_destinations[w] = set()
            self._wallet_destinations[w].add(d)

    # -----------------------------------------------------------------
    # Out-of-Band Profiling Worker (Invoked Async / In Background)
    # -----------------------------------------------------------------

    def profile_address(
        self,
        chain: str,
        address: str,
        wallet: str | None = None,
        force_refresh: bool = False,
    ) -> AddressProfile:
        """Performs deep profiling of an address out-of-band and caches the result."""
        clean_addr = address.strip().lower()
        cache_key = f"profile:{chain.lower()}:{clean_addr}"

        if not force_refresh:
            cached = self.get_cached_profile(chain, address)
            if cached is not None:
                return cached

        now = time.time()
        expires_at = now + self.ttl_seconds

        # 1. On-chain contract inspection via RPC
        code = ""
        try:
            if hasattr(self.rpc_client, "get_code"):
                code = self.rpc_client.get_code(address)
            elif hasattr(self.rpc_client, "eth_get_code"):
                code = self.rpc_client.eth_get_code(address)
        except Exception as exc:
            logger.warning("profiler_get_code_error for %s: %s", address, exc)

        is_contract = bool(code and len(code) > 2 and code != "0x" and code != "0x0")
        code_hash: str | None = None
        is_known_bad_code = False
        age_blocks: int | None = None
        age_days: float | None = None

        if is_contract:
            try:
                raw_bytes = bytes.fromhex(code.removeprefix("0x"))
                code_hash = "0x" + hashlib.sha256(raw_bytes).hexdigest().lower()
                is_known_bad_code = self.list_store.is_known_bad_code(code_hash)
            except Exception:
                pass

            # Check override or estimate age
            if clean_addr in self._contract_age_overrides:
                age_blocks, age_days = self._contract_age_overrides[clean_addr]
            else:
                # Default mock contract age: 100 days / 720,000 blocks unless newly deployed
                age_blocks = 720_000
                age_days = 100.0

        # 2. Sanction and blocklist local match (microsecond lookups)
        is_sanctioned = self.list_store.is_sanctioned(clean_addr)
        is_blocked = self.list_store.is_blocked(clean_addr)

        # 3. Taint provider scoring (vendor API call made here, out-of-band)
        taint_score = 0.0
        try:
            taint_score = self.taint_provider.get_taint_score(chain, address)
        except Exception as exc:
            logger.warning("profiler_taint_provider_error for %s: %s", address, exc)

        # 4. Construct AddressProfile
        known_wallets = []
        if wallet:
            w_clean = wallet.strip().lower()
            if not self.is_first_time_destination(w_clean, clean_addr):
                known_wallets.append(w_clean)

        profile = AddressProfile(
            address=clean_addr,
            chain=chain.lower(),
            is_contract=is_contract,
            contract_age_blocks=age_blocks,
            contract_age_days=age_days,
            code_hash=code_hash,
            first_seen_at=datetime.now(UTC),
            known_wallets_sent=known_wallets,
            taint_exposure_score=taint_score,
            taint_provider=self.taint_provider.name,
            is_sanctioned=is_sanctioned,
            is_blocked=is_blocked,
            is_known_bad_code=is_known_bad_code,
            updated_at=now,
            expires_at=expires_at,
        )

        # 5. Save to cache
        self._save_to_cache(cache_key, profile, expires_at)
        return profile

    def _save_to_cache(self, cache_key: str, profile: AddressProfile, expires_at: float) -> None:
        with self._lock:
            self._memory_cache[cache_key] = (profile, expires_at)

        if self._redis is not None:
            try:
                self._redis.set(
                    cache_key,
                    profile.model_dump_json(),
                    ex=int(self.ttl_seconds),
                )
            except Exception as exc:
                logger.warning("profile_redis_save_failure: %s", exc)

    def clear_cache(self) -> None:
        with self._lock:
            self._memory_cache.clear()
            self._wallet_destinations.clear()
            self._contract_age_overrides.clear()


# Global default instance
profile_worker = ProfileWorker()
