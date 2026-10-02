"""Engine / session management. The only place that reads DATABASE_URL."""
from __future__ import annotations

import os
from collections.abc import Iterator
from functools import lru_cache

from dotenv import load_dotenv
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from database.models import Base

load_dotenv()


class DatabaseConfigError(RuntimeError):
    pass


def _database_url() -> str:
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        raise DatabaseConfigError(
            "DATABASE_URL is not set. Copy .env.example to .env (or export DATABASE_URL)."
        )
    return url


def safe_url() -> str:
    """Connection URL with the password hidden, for log and error messages."""
    return make_url(_database_url()).render_as_string(hide_password=True)


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    return create_engine(_database_url(), pool_pre_ping=True)


@lru_cache(maxsize=1)
def _session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def new_session() -> Session:
    return _session_factory()()


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request."""
    session = new_session()
    try:
        yield session
    finally:
        session.close()


def init_db() -> None:
    """Enable pgvector and create tables if they do not exist. Safe to call repeatedly."""
    engine = get_engine()
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    except OperationalError as exc:
        raise DatabaseConfigError(
            f"Cannot connect to PostgreSQL at {safe_url()}.\n"
            "Is the database running? Start it with: docker compose up -d db\n"
            f"Driver said: {str(exc.orig).strip()}"
        ) from exc
    Base.metadata.create_all(engine)


def check_connection() -> bool:
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def reset_engine_cache() -> None:
    """Used by tests after changing DATABASE_URL."""
    if get_engine.cache_info().currsize:
        get_engine().dispose()
    get_engine.cache_clear()
    _session_factory.cache_clear()
