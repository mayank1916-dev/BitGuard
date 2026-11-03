"""Pytest configuration and test isolation fixtures."""

import fakeredis
import pytest
import sqlalchemy as sa

from services.bitguard.breaker.epoch_store import token_epoch_store
from services.bitguard.breaker.store import distributed_breaker_store
from services.bitguard.database import set_engine
from services.bitguard.db_models import Base
from services.bitguard.limits.store import limit_store
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

    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=sa.pool.StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    set_engine(engine)

    yield

    distributed_breaker_store.reset()
