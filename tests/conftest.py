"""Pytest configuration and test isolation fixtures."""

import fakeredis
import pytest

from services.bitguard.limits.store import limit_store


@pytest.fixture(autouse=True)
def configure_test_redis():
    """Provides a clean in-memory FakeRedis client to the global limit store for tests."""
    server = fakeredis.FakeServer()
    client = fakeredis.FakeRedis(server=server, decode_responses=True)
    limit_store.set_redis_client(client)
    yield
