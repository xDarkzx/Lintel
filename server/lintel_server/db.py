"""The database behind the store: SQLite for a single site or an appliance,
PostgreSQL for larger deployments. The rest of the server writes one SQL
dialect (the common ground of both, with ? placeholders) and calls q, q1 and
x; differences live here.

Choose with LINTEL_DATABASE_URL: unset for SQLite in the data folder, or
postgresql://user:pass@host/db (TLS is required unless sslmode says otherwise).
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

log = logging.getLogger("lintel.db")


class Database:
    dialect = ""
    IntegrityError: tuple[type[Exception], ...] = ()

    def q(self, sql: str, args: tuple | list = ()) -> list[Any]:
        raise NotImplementedError

    def q1(self, sql: str, args: tuple | list = ()) -> Any:
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args: tuple | list = ()) -> int:
        """Runs a statement; returns the new row's id for an INSERT into a
        table with an id, otherwise the number of rows affected."""
        raise NotImplementedError

    def script(self, sql: str) -> None:
        raise NotImplementedError

    @contextmanager
    def transaction(self) -> Iterator["Database"]:
        """Holds the database's write lock for the block: one writer at a
        time, across every server process using the same database."""
        raise NotImplementedError

    def tables(self) -> set[str]:
        raise NotImplementedError

    def claim_server(self, wait_s: float = 5.0) -> bool:
        """Claims this database for one running server; False if another
        server still holds it after wait_s. Two servers would each keep their
        own door message counters and reuse AES-CCM nonces under the same door
        key, and split the keypad lockouts and sign-in throttles between them.
        The wait lets a server that is just exiting (a restart) let go first."""
        deadline = time.monotonic() + wait_s
        while not self._try_claim():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.2)
        return True

    def _try_claim(self) -> bool:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class SQLiteDB(Database):
    dialect = "sqlite"
    IntegrityError = (sqlite3.IntegrityError,)

    def __init__(self, path: Path) -> None:
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        for pragma in ("journal_mode=WAL", "foreign_keys=ON", "secure_delete=ON"):
            self.conn.execute(f"PRAGMA {pragma}")

    def q(self, sql, args=()):
        with self.lock:
            return self.conn.execute(sql, args).fetchall()

    def x(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            # lastrowid keeps the connection's last insert id after any other
            # statement, or an INSERT that inserted nothing, so only trust it
            # for an INSERT that added a row.
            if sql.lstrip()[:6].upper() != "INSERT" or cur.rowcount <= 0:
                return cur.rowcount
            return cur.lastrowid or cur.rowcount

    def script(self, sql):
        # Statement by statement, never executescript(), which commits whatever
        # transaction is open first and would make a migration non-atomic.
        with self.lock:
            # Cut at each semicolon that ends a complete statement; one inside a
            # trigger body leaves the statement incomplete, so it stays whole.
            buf = ""
            for piece in sql.split(";")[:-1] if sql.rstrip().endswith(";") else sql.split(";"):
                buf += piece + ";"
                if sqlite3.complete_statement(buf):
                    if buf.strip(" \n\t;"):
                        self.conn.execute(buf)
                    buf = ""
            buf = buf.rstrip(";")
            if buf.strip():  # a last statement may omit its semicolon
                if not sqlite3.complete_statement(buf + ";"):
                    raise ValueError(f"incomplete SQL statement: {buf[:60]}")
                self.conn.execute(buf)

    @contextmanager
    def transaction(self):
        with self.lock:
            if self.conn.in_transaction:  # nested: part of the enclosing transaction
                yield self
                return
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self
                self.conn.execute("COMMIT")
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise

    def tables(self):
        return {r["name"] for r in self.q("SELECT name FROM sqlite_master WHERE type='table'")}

    def _try_claim(self):
        # An OS lock on a file beside the database, held for the life of the
        # process and released by the OS however the process ends.
        f = open(self.path.with_name("server.lock"), "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            f.close()
            return False
        self._server_lock = f
        return True

    def close(self):
        self.conn.close()


class PostgresDB(Database):
    dialect = "postgres"

    @staticmethod
    def _connection_options(url: str) -> dict[str, Any]:
        from psycopg.conninfo import conninfo_to_dict

        options = conninfo_to_dict(url)
        options.setdefault("sslmode", "require")
        return options

    def __init__(self, url: str) -> None:
        import psycopg
        from psycopg.rows import dict_row
        self._psycopg = psycopg
        self.IntegrityError = (psycopg.errors.IntegrityError,)
        self._options = self._connection_options(url)
        self._row_factory = dict_row
        self.conn = psycopg.connect(**self._options, autocommit=True, row_factory=dict_row)
        self.lock = threading.RLock()
        self._depth = 0
        self._claimed = False

    def _live(self) -> None:
        """Reconnects before the next statement if the connection was lost (a
        database restart or network drop), so the server recovers without a
        restart. A statement that failed is never retried: it may have been
        applied. Called with the lock held, outside any transaction."""
        if self._depth or not (self.conn.closed or self.conn.broken):
            return
        log.warning("database connection lost; reconnecting")
        self.conn = self._psycopg.connect(**self._options, autocommit=True, row_factory=self._row_factory)
        if self._claimed and not self.claim_server():
            # The single-server lock went with the old connection and another
            # server now holds it. Carrying on would reuse door message counters.
            log.critical("another Lintel server took over this database while the connection was down; stopping")
            os._exit(3)

    @staticmethod
    def _sql(sql: str) -> str:
        # One dialect in the code: ? placeholders become %s, and a literal % is escaped.
        return sql.replace("%", "%%").replace("?", "%s")

    def q(self, sql, args=()):
        with self.lock:
            self._live()
            cur = self.conn.execute(self._sql(sql), tuple(args))
            return cur.fetchall() if cur.description else []

    def x(self, sql, args=()):
        with self.lock:
            self._live()
            stmt = sql.strip()
            if stmt[:6].upper() == "INSERT" and " RETURNING " not in stmt.upper():
                cur = self.conn.execute(self._sql(stmt) + " RETURNING *", tuple(args))
                row = cur.fetchone()
                return row["id"] if row and "id" in row and row["id"] is not None else cur.rowcount
            cur = self.conn.execute(self._sql(stmt), tuple(args))
            return cur.rowcount

    def script(self, sql):
        with self.lock:
            self._live()
            self.conn.execute(sql)

    @contextmanager
    def transaction(self):
        with self.lock:
            self._live()
            if self._depth:
                self._depth += 1
                try:
                    yield self
                finally:
                    self._depth -= 1
                return
            self._depth = 1
            try:
                with self.conn.transaction():
                    # Serialises writers across processes, as SQLite's write lock does.
                    self.conn.execute("SELECT pg_advisory_xact_lock(4711)")
                    yield self
            finally:
                self._depth = 0

    def tables(self):
        return {r["table_name"] for r in self.q(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()")}

    SERVER_LOCK_ID = 4712  # distinct from the per-transaction writer lock (4711)

    def _try_claim(self):
        # A session-level advisory lock: held while this connection is open,
        # released by PostgreSQL when it closes or the process dies.
        with self.lock:
            r = self.conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (self.SERVER_LOCK_ID,)).fetchone()
        self._claimed = self._claimed or bool(r and r["ok"])
        return bool(r and r["ok"])

    def close(self):
        self.conn.close()


def connect(data_dir: Path, url: str | None) -> Database:
    if url:
        return PostgresDB(url)
    return SQLiteDB(data_dir / "lintel.db")
