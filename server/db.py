"""SQLAlchemy engine/session wiring.

One database, chosen entirely by DATABASE_URL (sqlite for local dev,
postgres in production) — no second datastore is introduced. Schema changes
go through Alembic (server/migrations); see server/README_MIGRATIONS.md.
"""
from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

import config

_is_sqlite = config.DATABASE_URL.startswith("sqlite")
_connect_args = {"check_same_thread": False} if _is_sqlite else {}

engine = create_engine(config.DATABASE_URL, connect_args=_connect_args, future=True)

if _is_sqlite:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _record) -> None:
        # WAL + a busy timeout let concurrent usage-counter updates (see
        # usage.py) succeed without spurious "database is locked" errors
        # under light concurrency — good enough for the single-process dev
        # deployment this repo ships; Postgres in production handles
        # concurrent row updates natively.
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Dev convenience: create any missing tables. Never drops/alters existing
    ones — safe to call on every boot. Production relies on Alembic instead."""
    import models  # noqa: F401  (registers models on Base.metadata)

    Base.metadata.create_all(bind=engine)
