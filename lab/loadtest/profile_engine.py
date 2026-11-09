"""CPU profiling utility for BitGuard Decision Engine and Fast Path (Milestone S25).

Uses cProfile and pstats to profile the 6-stage decision pipeline:
1. EVM Decoding (RLP, call dissection)
2. Ledger Intent Check
3. Delegation Guard (EIP-7702, bytecode hashing)
4. Sliding-window Limit Reservations
5. Cached Enrichment Hooks
6. Mode Resolution & Decision Persistence

Outputs function-level hotspots ranked by cumulative and total execution time.
"""

import cProfile
import io
import pstats
import sys
import time
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import fakeredis
import rlp
import sqlalchemy as sa

from services.bitguard.breaker.epoch_store import token_epoch_store
from services.bitguard.breaker.store import distributed_breaker_store
from services.bitguard.database import set_engine
from services.bitguard.db_models import Base
from services.bitguard.engine.pipeline import decision_engine
from services.bitguard.ledger.mock import mock_ledger_connector
from services.bitguard.limits.store import limit_store
from services.bitguard.models import OperationMode, SigningRequest
from services.bitguard.rate_limiter import rate_limiter
from services.bitguard.stream.broadcaster import stream_broadcaster
from services.signer_shim.nonce_store import nonce_store

BENIGN_DEST_RAW = "1111111111111111111111111111111111111111"
OWNED_WALLET = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"


def build_raw_legacy_tx(to_hex: str = BENIGN_DEST_RAW, value: int = 1000, nonce: int = 0) -> str:
    clean_hex = to_hex[2:] if to_hex.startswith("0x") else to_hex
    payload = [nonce, 20_000_000_000, 21000, bytes.fromhex(clean_hex), value, b""]
    return "0x" + rlp.encode(payload).hex()


def setup_profiling_environment() -> None:
    server = fakeredis.FakeServer()
    client = fakeredis.FakeRedis(server=server, decode_responses=True)

    limit_store.set_redis_client(client)
    distributed_breaker_store.set_redis_client(client)
    token_epoch_store.set_redis_client(client)
    nonce_store.set_redis_client(client)
    stream_broadcaster.set_sync_redis(client)
    rate_limiter.set_sync_redis(client)
    from services.bitguard.break_glass import break_glass_store
    break_glass_store.set_sync_redis(client)
    mock_ledger_connector._ledger_url = ""

    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=sa.pool.StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    set_engine(engine)


def run_profile_evaluations(iterations: int = 1000) -> None:
    setup_profiling_environment()
    raw_tx = build_raw_legacy_tx(value=1000)

    request = SigningRequest(
        id="profile-req-001",
        chain="ethereum",
        raw_tx=raw_tx,
        wallet=OWNED_WALLET,
        wallet_group="default",
        mode=OperationMode.SIMULATION,
        metadata={"amount_usd": 100.0},
    )

    # Warmup
    for _ in range(20):
        decision_engine.evaluate(request, is_dry_run=True)

    print(f"\n--- Profiling {iterations} Decision Engine Evaluations ---")
    profiler = cProfile.Profile()
    profiler.enable()

    t0 = time.perf_counter()
    for i in range(iterations):
        request.id = f"profile-req-{i}"
        decision_engine.evaluate(request, is_dry_run=True)
    total_time = time.perf_counter() - t0

    profiler.disable()

    print(f"Total time for {iterations} iterations: {total_time:.3f} s ({total_time / iterations * 1000.0:.3f} ms / req)")

    s = io.StringIO()
    ps = pstats.Stats(profiler, stream=s).sort_stats("cumtime")
    ps.print_stats(30)
    print("\nTop 30 Hotspots by Cumulative Time:")
    print(s.getvalue())

    s2 = io.StringIO()
    ps2 = pstats.Stats(profiler, stream=s2).sort_stats("tottime")
    ps2.print_stats(20)
    print("\nTop 20 Hotspots by Self/Total Time:")
    print(s2.getvalue())


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    run_profile_evaluations(count)
