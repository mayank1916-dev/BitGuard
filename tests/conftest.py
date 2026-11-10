"""Pytest configuration and test isolation fixtures."""

import time

import fakeredis
import pytest
import sqlalchemy as sa

from services.bitguard.approvals.webauthn import approver_registry
from services.bitguard.audit import audit_service
from services.bitguard.backtest.service import backtest_service
from services.bitguard.breaker.epoch_store import token_epoch_store
from services.bitguard.breaker.store import distributed_breaker_store
from services.bitguard.database import set_engine
from services.bitguard.db_models import Base
from services.bitguard.ledger.mock import mock_ledger_connector
from services.bitguard.limits.store import limit_store
from services.bitguard.policy.store import policy_store
from services.bitguard.rate_limiter import rate_limiter
from services.bitguard.stream.broadcaster import stream_broadcaster
from services.signer_shim.nonce_store import nonce_store


@pytest.fixture(autouse=True)
def configure_test_redis_and_db():
    """Provides a clean in-memory FakeRedis client and in-memory SQLite for tests."""
    server = fakeredis.FakeServer()
    client = fakeredis.FakeRedis(server=server, decode_responses=True)
    limit_store.set_redis_client(client)
    distributed_breaker_store.set_redis_client(client)
    token_epoch_store.set_redis_client(client)
    nonce_store.set_redis_client(client)
    backtest_service.set_redis_client(client)
    stream_broadcaster.set_sync_redis(client)
    rate_limiter.set_sync_redis(client)
    from services.bitguard.profiler.worker import profile_worker
    profile_worker.set_redis_client(client)
    profile_worker.clear_cache()
    from services.bitguard.break_glass import break_glass_store
    from services.signer_shim.heartbeat import heartbeat_tracker
    break_glass_store.set_sync_redis(client)
    heartbeat_tracker.last_heartbeat_time = time.time()
    mock_ledger_connector._ledger_url = ""
    audit_service.clear()
    approver_registry.reset_replays()

    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=sa.pool.StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sa.orm.sessionmaker(autocommit=False, autoflush=False, bind=engine)
    set_engine(engine)
    distributed_breaker_store.set_session_factory(session_factory)
    policy_store.set_session_factory(session_factory)
    backtest_service.set_session_factory(session_factory)

    yield

    distributed_breaker_store.reset()
    audit_service.clear()
    approver_registry.reset_replays()
    from services.bitguard.profiler.worker import profile_worker
    profile_worker.clear_cache()
