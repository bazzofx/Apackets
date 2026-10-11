"""SQLite access layer.

One short-lived connection per call keeps the module thread-safe without a pool.
WAL mode allows concurrent readers while an analysis worker writes.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("apackets.db")

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

_init_lock = threading.Lock()
_initialised = False


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or settings.db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30.0, isolation_level="DEFERRED")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    """Transactional connection: commits on success, rolls back on error."""
    conn = connect()
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    global _initialised
    with _init_lock:
        if _initialised:
            return
        settings.ensure_dirs()
        sql = SCHEMA_PATH.read_text(encoding="utf-8")
        conn = connect()
        try:
            conn.executescript(sql)
            conn.commit()
        finally:
            conn.close()
        _initialised = True
        log.info("database ready at %s", settings.db_path)


def query_all(sql: str, params: Sequence[object] = ()) -> list[sqlite3.Row]:
    conn = connect()
    try:
        return conn.execute(sql, tuple(params)).fetchall()
    finally:
        conn.close()


def query_one(sql: str, params: Sequence[object] = ()) -> sqlite3.Row | None:
    conn = connect()
    try:
        return conn.execute(sql, tuple(params)).fetchone()
    finally:
        conn.close()


def execute(sql: str, params: Sequence[object] = ()) -> int:
    with get_conn() as conn:
        cur = conn.execute(sql, tuple(params))
        return cur.rowcount


def execute_many(sql: str, rows: Sequence[Sequence[object]]) -> int:
    if not rows:
        return 0
    with get_conn() as conn:
        cur = conn.executemany(sql, rows)
        return cur.rowcount


# --- small helpers used across services ------------------------------------

def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


def rows_to_dicts(rows: Sequence[sqlite3.Row]) -> list[dict]:
    return [dict(r) for r in rows]


def count(analysis_id: str, table: str) -> int:
    """Row count for one analysis. ``table`` must be an internal constant."""
    row = query_one(f"SELECT COUNT(*) AS n FROM {table} WHERE analysis_id = ?", (analysis_id,))
    return int(row["n"]) if row else 0
