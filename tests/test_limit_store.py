"""Unit and concurrency tests for atomic distributed limit store (Milestone S07 / F3)."""

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import fakeredis
import pytest
import redis

from services.bitguard.config import settings
from services.bitguard.limits.store import (
    LimitStore,
    ReservationResult,
    ScopeBuilder,
)


@pytest.fixture
def fake_redis_store():
    """Provides a LimitStore backed by an isolated in-memory FakeRedis instance."""
    server = fakeredis.FakeServer()
    client = fakeredis.FakeRedis(server=server, decode_responses=True)
    store = LimitStore(redis_client=client)
    return store, server


def test_200_concurrent_reserves_against_cap_fits_10(fake_redis_store):
    """Test 1: 200 concurrent reserve calls against a cap that fits 10 -> exactly 10 succeed, total never exceeds cap."""
    store, _ = fake_redis_store
    scope_key = ScopeBuilder.wallet_scope("0xconcurrenthot01", window_seconds=3600)
    cap = 1000
    amount = 100  # Exactly 10 will fit: 10 * 100 = 1000

    results: list[ReservationResult] = []

    def make_reservation(_idx: int) -> ReservationResult:
        return store.reserve(
            scope_keys=[scope_key],
            amount=amount,
            window_seconds=3600,
            cap=cap,
            reservation_ttl=120,
        )

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(make_reservation, i) for i in range(200)]
        for f in futures:
            results.append(f.result())

    successes = [r for r in results if r.ok]
    failures = [r for r in results if not r.ok]

    assert len(successes) == 10, f"Expected exactly 10 successes, got {len(successes)}"
    assert len(failures) == 190, f"Expected exactly 190 rejections, got {len(failures)}"

    # Check remaining capacity is 0
    rem = store.get_remaining(scope_key, window_seconds=3600, cap=cap)
    assert rem == 0

    # Total reserved volume must never exceed cap
    _, used_r, total = store.get_usage(scope_key, window_seconds=3600)
    assert used_r == 1000
    assert total == 1000

    # A subsequent reservation attempt must fail closed
    extra_res = store.reserve(
        scope_keys=[scope_key],
        amount=1,
        window_seconds=3600,
        cap=cap,
    )
    assert not extra_res.ok
    assert extra_res.remaining == 0


def test_restart_redis_committed_volume_survives():
    """Test 2: Restart Redis -> committed volume survives (persistence)."""
    server = fakeredis.FakeServer()
    r1 = fakeredis.FakeRedis(server=server, decode_responses=True)
    store1 = LimitStore(redis_client=r1)

    scope_key = ScopeBuilder.wallet_scope("0xpersisthot02", window_seconds=3600)
    cap = 1000
    amount = 400

    # Step 1: Reserve and commit
    res = store1.reserve(
        scope_keys=[scope_key],
        amount=amount,
        window_seconds=3600,
        cap=cap,
    )
    assert res.ok
    commit_ok = store1.commit(res.reservation_id)
    assert commit_ok

    committed_1, reserved_1, total_1 = store1.get_usage(scope_key, window_seconds=3600)
    assert committed_1 == 400
    assert reserved_1 == 0
    assert total_1 == 400

    # Step 2: Simulate Redis restart / reconnection using same persisted server storage
    r1.close()
    r2 = fakeredis.FakeRedis(server=server, decode_responses=True)
    store2 = LimitStore(redis_client=r2)

    # Verify committed volume survived restart
    committed_2, reserved_2, total_2 = store2.get_usage(scope_key, window_seconds=3600)
    assert committed_2 == 400, "Committed volume must survive restart"
    assert reserved_2 == 0
    assert total_2 == 400

    # Attempt to reserve 700 -> must fail (400 + 700 > 1000)
    res_fail = store2.reserve(
        scope_keys=[scope_key],
        amount=700,
        window_seconds=3600,
        cap=cap,
    )
    assert not res_fail.ok
    assert res_fail.remaining == 600

    # Attempt to reserve 600 -> must succeed (400 + 600 == 1000)
    res_ok = store2.reserve(
        scope_keys=[scope_key],
        amount=600,
        window_seconds=3600,
        cap=cap,
    )
    assert res_ok.ok


def test_kill_redis_denies_or_local_cap_limited_never_unlimited():
    """Test 3: Kill Redis -> verdict is DENY or local-cap limited, never unlimited."""
    # Create mock Redis client that raises ConnectionError (simulating killed Redis)
    mock_redis = MagicMock(spec=redis.Redis)
    mock_redis.register_script.side_effect = redis.exceptions.ConnectionError("Redis connection refused")

    store = LimitStore(redis_client=mock_redis)

    scope_key = ScopeBuilder.wallet_scope("0xkilledredis03", window_seconds=3600)
    saved_cap = settings.local_fallback_cap
    try:
        # Configure conservative local cap
        settings.local_fallback_cap = 5000
        settings.local_caps_enabled = True

        # Scenario A: Requested amount exceeds conservative local cap
        res_exceed = store.reserve(
            scope_keys=[scope_key],
            amount=6000,
            window_seconds=3600,
            cap=100_000,  # Caller requested higher cap, but local fallback clamps to 5000
        )
        assert not res_exceed.ok
        assert res_exceed.error == "LIMIT_STORE_UNAVAILABLE"
        assert res_exceed.source == "LOCAL_FALLBACK"

        # Scenario B: Requested amount fits in conservative local cap
        res_ok_1 = store.reserve(
            scope_keys=[scope_key],
            amount=2000,
            window_seconds=3600,
            cap=100_000,
        )
        assert res_ok_1.ok
        assert res_ok_1.source == "LOCAL_FALLBACK"

        res_ok_2 = store.reserve(
            scope_keys=[scope_key],
            amount=3000,
            window_seconds=3600,
            cap=100_000,
        )
        assert res_ok_2.ok

        # Now local cap (5000) is fully saturated (2000 + 3000 = 5000). Next call must fail!
        res_fail = store.reserve(
            scope_keys=[scope_key],
            amount=1,
            window_seconds=3600,
            cap=100_000,
        )
        assert not res_fail.ok
        assert res_fail.error == "LIMIT_STORE_UNAVAILABLE"

        # Scenario C: If local fallback is explicitly disabled, fails closed immediately
        settings.local_caps_enabled = False
        res_closed = store.reserve(
            scope_keys=[scope_key],
            amount=10,
            window_seconds=3600,
            cap=100_000,
        )
        assert not res_closed.ok
        assert res_closed.error == "LIMIT_STORE_UNAVAILABLE"
        assert res_closed.source == "FAIL_CLOSED"

    finally:
        settings.local_fallback_cap = saved_cap
        settings.local_caps_enabled = True


def test_reservation_expiry_releases_budget(fake_redis_store):
    """Test 4: Reservation expiry releases budget."""
    store, _ = fake_redis_store
    scope_key = ScopeBuilder.wallet_scope("0xexpirytest04", window_seconds=3600)
    cap = 100
    now_t0 = 1700000000
    ttl = 5  # 5-second reservation TTL

    # 1. Reserve 100 at t0 -> saturates cap
    res = store.reserve(
        scope_keys=[scope_key],
        amount=100,
        window_seconds=3600,
        cap=cap,
        reservation_ttl=ttl,
        now=now_t0,
    )
    assert res.ok
    assert res.remaining == 0

    # 2. Try reserving at t0 + 2 (within TTL) -> must fail
    res_in_flight = store.reserve(
        scope_keys=[scope_key],
        amount=1,
        window_seconds=3600,
        cap=cap,
        now=now_t0 + 2,
    )
    assert not res_in_flight.ok
    assert res_in_flight.remaining == 0

    # 3. Advance clock past TTL to t0 + 6 -> reservation expires, budget restored
    now_expired = now_t0 + 6
    res_after_expiry = store.reserve(
        scope_keys=[scope_key],
        amount=100,
        window_seconds=3600,
        cap=cap,
        reservation_ttl=ttl,
        now=now_expired,
    )
    assert res_after_expiry.ok
    assert res_after_expiry.remaining == 0

    # 4. Attempting to commit the expired reservation must return False
    commit_expired = store.commit(res.reservation_id, now=now_expired)
    assert not commit_expired


def test_release_frees_budget_immediately(fake_redis_store):
    """Releasing an active reservation immediately frees budget."""
    store, _ = fake_redis_store
    scope_key = ScopeBuilder.wallet_scope("0xreleasetest05", window_seconds=3600)
    cap = 500

    # Reserve 500
    res = store.reserve(scope_keys=[scope_key], amount=500, window_seconds=3600, cap=cap)
    assert res.ok

    # Next reservation fails
    assert not store.reserve(scope_keys=[scope_key], amount=1, window_seconds=3600, cap=cap).ok

    # Release it
    assert store.release(res.reservation_id)

    # Budget is freed immediately
    res_again = store.reserve(scope_keys=[scope_key], amount=500, window_seconds=3600, cap=cap)
    assert res_again.ok


def test_multi_scope_atomicity_and_partial_failure(fake_redis_store):
    """Atomic multi-scope check ensures that if one scope fails, no reservations are created."""
    store, _ = fake_redis_store
    wallet_scope = ScopeBuilder.wallet_scope("0xmultiscope06", window_seconds=3600)
    asset_scope = ScopeBuilder.asset_scope("USDC", window_seconds=3600)
    chain_scope = ScopeBuilder.chain_scope("ethereum", window_seconds=3600)
    global_scope = ScopeBuilder.global_scope(window_seconds=3600)

    all_scopes = [wallet_scope, asset_scope, chain_scope, global_scope]
    # Chain scope has tight cap of 50, others have 1000
    caps = [1000, 1000, 50, 1000]

    # Amount 60 exceeds chain cap (50), but fits other 3
    res_rejected = store.reserve(
        scope_keys=all_scopes,
        amount=60,
        window_seconds=3600,
        cap=caps,
    )
    assert not res_rejected.ok

    # None of the scopes must have any reserved volume
    for s in all_scopes:
        _, used_r, _ = store.get_usage(s, window_seconds=3600)
        assert used_r == 0, f"Scope {s} should have 0 usage after rejected multi-scope reserve"

    # Amount 40 fits all 4 scopes
    res_ok = store.reserve(
        scope_keys=all_scopes,
        amount=40,
        window_seconds=3600,
        cap=caps,
    )
    assert res_ok.ok
    assert res_ok.remaining == 10  # 50 - 40 = 10 on chain scope


def test_type_and_value_validation(fake_redis_store):
    """Enforce strict integer amounts in smallest units (never floats or negative)."""
    store, _ = fake_redis_store
    scope_key = ScopeBuilder.wallet_scope("0xvalidation07", window_seconds=3600)

    # Float amount raises TypeError
    with pytest.raises(TypeError, match="Amount must be an integer"):
        store.reserve(scope_keys=[scope_key], amount=10.5, window_seconds=3600, cap=100)

    # Non-positive amount raises ValueError
    with pytest.raises(ValueError, match="Reservation amount must be positive"):
        store.reserve(scope_keys=[scope_key], amount=0, window_seconds=3600, cap=100)

    with pytest.raises(ValueError, match="Reservation amount must be positive"):
        store.reserve(scope_keys=[scope_key], amount=-50, window_seconds=3600, cap=100)

