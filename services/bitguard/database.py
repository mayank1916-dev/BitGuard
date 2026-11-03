"""Database connection management and session factory for BitGuard Firewall (Milestone S13)."""

import logging
from collections.abc import Generator
from typing import Any

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from services.bitguard.config import settings
from services.bitguard.db_models import Base

logger = logging.getLogger("bitguard.database")

# Primary SQLAlchemy engine
_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """Returns or lazily initializes the active SQLAlchemy engine."""
    global _engine
    if _engine is None:
        db_url = settings.database_url
        connect_args: dict[str, Any] = {}
        if db_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        _engine = create_engine(
            db_url,
            connect_args=connect_args,
            pool_pre_ping=True,
        )
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Returns or lazily initializes the session factory."""
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(
            bind=get_engine(),
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )
    return _SessionFactory


def set_engine(engine: Engine) -> None:
    """Configures a custom SQLAlchemy engine (e.g. for testing with SQLite)."""
    global _engine, _SessionFactory
    _engine = engine
    _SessionFactory = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    # Ensure tables exist
    Base.metadata.create_all(bind=engine)


def init_db(engine: Engine | None = None) -> None:
    """Initializes tables in database."""
    target_engine = engine or get_engine()
    Base.metadata.create_all(bind=target_engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a managed database session."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()
