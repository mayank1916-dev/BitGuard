"""Database connection and session management for Ledger Mock."""

import logging
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from services.ledger_mock.config import settings
from services.ledger_mock.models import Base

logger = logging.getLogger("ledger_mock.db")

# Create engine with resilient fallback
try:
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
    )
    # Test connection
    with engine.connect():
        pass
except Exception:
    logger.info("Postgres unavailable; using SQLite in-memory database for Ledger Mock")
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Initializes tables in database."""
    Base.metadata.create_all(bind=engine)


# Eagerly ensure tables are initialized
init_db()


def get_db() -> Generator[Session, None, None]:
    """FastAPI database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
