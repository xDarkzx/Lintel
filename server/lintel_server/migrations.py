"""Versioned schema migrations, for SQLite and PostgreSQL.

Each migration runs once, in its own transaction, and is recorded in
schema_migrations. A database newer than this server refuses to open rather
than being half-understood. Add a migration by appending to MIGRATIONS with
the SQL for each dialect; never edit one that has shipped.
"""

from __future__ import annotations

import time
from typing import Callable

from .db import Database

# ---- 1: the schema as it stood when migrations were introduced -----------------------------

SQLITE_BASELINE = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS operators (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    active INTEGER NOT NULL DEFAULT 1,
    created REAL NOT NULL,
    totp_secret TEXT,
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    last_login REAL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    operator_id INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    expires REAL NOT NULL,
    last_seen REAL
);

CREATE TABLE IF NOT EXISTS floors (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    level INTEGER NOT NULL DEFAULT 0,
    plan TEXT,
    width INTEGER,
    height INTEGER,
    created REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS doors (
    id INTEGER PRIMARY KEY CHECK (id BETWEEN 1 AND 31),
    name TEXT NOT NULL,
    area TEXT NOT NULL DEFAULT '',
    key BLOB NOT NULL,
    unlock_ms INTEGER NOT NULL DEFAULT 5000,
    tx_ceiling INTEGER NOT NULL DEFAULT 0,
    rx_highest INTEGER NOT NULL DEFAULT 0,
    last_seen REAL,
    last_ip TEXT,
    rssi INTEGER,
    credential_mode TEXT NOT NULL DEFAULT 'pin',
    diag TEXT,
    diag_ts REAL,
    key_created REAL,
    floor_id INTEGER REFERENCES floors(id) ON DELETE SET NULL,
    map_x REAL,
    map_y REAL,
    map_locked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    observe_holidays INTEGER
);

CREATE TABLE IF NOT EXISTS schedule_windows (
    id INTEGER PRIMARY KEY,
    schedule_id INTEGER NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
    days INTEGER NOT NULL,
    start_min INTEGER NOT NULL,
    end_min INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS access_groups (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    schedule_id INTEGER NOT NULL REFERENCES schedules(id)
);

CREATE TABLE IF NOT EXISTS access_group_doors (
    group_id INTEGER NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
    door_id INTEGER NOT NULL REFERENCES doors(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, door_id)
);

CREATE TABLE IF NOT EXISTS cardholders (
    id INTEGER PRIMARY KEY,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    department TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    pin_tag BLOB UNIQUE,
    duress_tag BLOB UNIQUE,
    override INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    valid_from REAL,
    valid_until REAL,
    notes TEXT NOT NULL DEFAULT '',
    created REAL NOT NULL,
    card_tag BLOB
);
CREATE UNIQUE INDEX IF NOT EXISTS cardholders_card ON cardholders(card_tag);

CREATE TABLE IF NOT EXISTS cardholder_groups (
    cardholder_id INTEGER NOT NULL REFERENCES cardholders(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (cardholder_id, group_id)
);

CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    door_id INTEGER,
    cardholder_id INTEGER,
    operator TEXT,
    decision TEXT,
    reason TEXT,
    detail TEXT NOT NULL DEFAULT '',
    req_ctr INTEGER,
    photo TEXT,
    link TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_door_ctr ON events(door_id, req_ctr);

CREATE TABLE IF NOT EXISTS devices (
    serial TEXT PRIMARY KEY,
    pubkey BLOB NOT NULL,
    mac TEXT NOT NULL DEFAULT '',
    firmware TEXT NOT NULL DEFAULT '',
    controller TEXT NOT NULL DEFAULT '',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    door_id INTEGER UNIQUE REFERENCES doors(id) ON DELETE SET NULL,
    reported_door INTEGER NOT NULL DEFAULT 0,
    adopted_at REAL,
    adopt_seq INTEGER NOT NULL DEFAULT 0,
    pending_blob BLOB,
    pending_door INTEGER
);

CREATE TABLE IF NOT EXISTS holidays (
    id INTEGER PRIMARY KEY,
    day TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS face_templates (
    id INTEGER PRIMARY KEY,
    cardholder_id INTEGER NOT NULL REFERENCES cardholders(id) ON DELETE CASCADE,
    embedding BLOB NOT NULL,
    source TEXT NOT NULL,
    created REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS alarms (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    event_seq INTEGER REFERENCES events(seq),
    priority INTEGER NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    door_id INTEGER,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'acknowledged', 'cleared')),
    ack_by TEXT,
    ack_ts REAL,
    note TEXT NOT NULL DEFAULT ''
);
"""

# Columns older SQLite databases may lack; CREATE TABLE IF NOT EXISTS leaves an
# existing table alone, so they are added one by one.
LEGACY_COLUMNS = (
    ("doors", "credential_mode", "TEXT NOT NULL DEFAULT 'pin'"), ("cardholders", "card_tag", "BLOB"),
    ("doors", "diag", "TEXT"), ("doors", "diag_ts", "REAL"), ("doors", "key_created", "REAL"),
    ("operators", "totp_secret", "TEXT"), ("operators", "totp_last_step", "INTEGER NOT NULL DEFAULT 0"),
    ("operators", "last_login", "REAL"), ("sessions", "last_seen", "REAL"),
    ("schedules", "observe_holidays", "INTEGER"),
    ("doors", "floor_id", "INTEGER REFERENCES floors(id) ON DELETE SET NULL"),
    ("doors", "map_x", "REAL"), ("doors", "map_y", "REAL"), ("doors", "map_locked", "INTEGER NOT NULL DEFAULT 0"),
)


def _sqlite_baseline(db: Database) -> None:
    existing = {t: {r["name"] for r in db.q(f"PRAGMA table_info({t})")} for t in db.tables()}
    # Tables first, then columns older sites lack, then the indexes that use them.
    db.script("\n".join(s + ";" for s in _statements(SQLITE_BASELINE) if not s.lstrip().startswith("CREATE UNIQUE")))
    for table, column, decl in LEGACY_COLUMNS:
        if table in existing and column not in existing[table]:
            db.x(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
    db.x("CREATE UNIQUE INDEX IF NOT EXISTS cardholders_card ON cardholders(card_tag)")


def _statements(sql: str) -> list[str]:
    return [s.strip() for s in sql.split(";") if s.strip()]


# PostgreSQL: the same tables. Whole numbers are 64-bit (keypad counters are
# unsigned 32-bit), times are epoch seconds as double precision, bytes are bytea.
POSTGRES_BASELINE = """
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE operators (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    active BIGINT NOT NULL DEFAULT 1,
    created DOUBLE PRECISION NOT NULL,
    totp_secret TEXT,
    totp_last_step BIGINT NOT NULL DEFAULT 0,
    last_login DOUBLE PRECISION
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    operator_id BIGINT NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    expires DOUBLE PRECISION NOT NULL,
    last_seen DOUBLE PRECISION
);

CREATE TABLE floors (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL,
    level BIGINT NOT NULL DEFAULT 0,
    plan TEXT,
    width BIGINT,
    height BIGINT,
    created DOUBLE PRECISION NOT NULL
);

CREATE TABLE doors (
    id BIGINT PRIMARY KEY CHECK (id BETWEEN 1 AND 31),
    name TEXT NOT NULL,
    area TEXT NOT NULL DEFAULT '',
    key BYTEA NOT NULL,
    unlock_ms BIGINT NOT NULL DEFAULT 5000,
    tx_ceiling BIGINT NOT NULL DEFAULT 0,
    rx_highest BIGINT NOT NULL DEFAULT 0,
    last_seen DOUBLE PRECISION,
    last_ip TEXT,
    rssi BIGINT,
    credential_mode TEXT NOT NULL DEFAULT 'pin',
    diag TEXT,
    diag_ts DOUBLE PRECISION,
    key_created DOUBLE PRECISION,
    floor_id BIGINT REFERENCES floors(id) ON DELETE SET NULL,
    map_x DOUBLE PRECISION,
    map_y DOUBLE PRECISION,
    map_locked BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE schedules (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    observe_holidays BIGINT
);

CREATE TABLE schedule_windows (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    schedule_id BIGINT NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
    days BIGINT NOT NULL,
    start_min BIGINT NOT NULL,
    end_min BIGINT NOT NULL
);

CREATE TABLE access_groups (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    schedule_id BIGINT NOT NULL REFERENCES schedules(id)
);

CREATE TABLE access_group_doors (
    group_id BIGINT NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
    door_id BIGINT NOT NULL REFERENCES doors(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, door_id)
);

CREATE TABLE cardholders (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    department TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    pin_tag BYTEA UNIQUE,
    duress_tag BYTEA UNIQUE,
    override BIGINT NOT NULL DEFAULT 0,
    active BIGINT NOT NULL DEFAULT 1,
    valid_from DOUBLE PRECISION,
    valid_until DOUBLE PRECISION,
    notes TEXT NOT NULL DEFAULT '',
    created DOUBLE PRECISION NOT NULL,
    card_tag BYTEA
);
CREATE UNIQUE INDEX cardholders_card ON cardholders(card_tag);

CREATE TABLE cardholder_groups (
    cardholder_id BIGINT NOT NULL REFERENCES cardholders(id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (cardholder_id, group_id)
);

CREATE TABLE events (
    seq BIGINT PRIMARY KEY,
    ts DOUBLE PRECISION NOT NULL,
    kind TEXT NOT NULL,
    door_id BIGINT,
    cardholder_id BIGINT,
    operator TEXT,
    decision TEXT,
    reason TEXT,
    detail TEXT NOT NULL DEFAULT '',
    req_ctr BIGINT,
    photo TEXT,
    link TEXT NOT NULL
);
CREATE INDEX events_ts ON events(ts);
CREATE INDEX events_door_ctr ON events(door_id, req_ctr);

CREATE TABLE devices (
    serial TEXT PRIMARY KEY,
    pubkey BYTEA NOT NULL,
    mac TEXT NOT NULL DEFAULT '',
    firmware TEXT NOT NULL DEFAULT '',
    controller TEXT NOT NULL DEFAULT '',
    first_seen DOUBLE PRECISION NOT NULL,
    last_seen DOUBLE PRECISION NOT NULL,
    door_id BIGINT UNIQUE REFERENCES doors(id) ON DELETE SET NULL,
    reported_door BIGINT NOT NULL DEFAULT 0,
    adopted_at DOUBLE PRECISION,
    adopt_seq BIGINT NOT NULL DEFAULT 0,
    pending_blob BYTEA,
    pending_door BIGINT
);

CREATE TABLE holidays (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    day TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL
);

CREATE TABLE face_templates (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    cardholder_id BIGINT NOT NULL REFERENCES cardholders(id) ON DELETE CASCADE,
    embedding BYTEA NOT NULL,
    source TEXT NOT NULL,
    created DOUBLE PRECISION NOT NULL
);

CREATE TABLE alarms (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    ts DOUBLE PRECISION NOT NULL,
    event_seq BIGINT REFERENCES events(seq),
    priority BIGINT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    door_id BIGINT,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'acknowledged', 'cleared')),
    ack_by TEXT,
    ack_ts DOUBLE PRECISION,
    note TEXT NOT NULL DEFAULT ''
);
"""

# ---- 2: the audit trail is append-only, enforced by the database itself ----------------------
# The hash chain detects changes; these refuse them, even to code with full
# access to the tables. Only the photo reference may change (retention clears it).

CHAINED = "seq, ts, kind, door_id, cardholder_id, operator, decision, reason, detail, req_ctr, link"

SQLITE_APPEND_ONLY = f"""
CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'audit records cannot be deleted'); END;
CREATE TRIGGER events_no_rewrite BEFORE UPDATE OF {CHAINED} ON events
BEGIN SELECT RAISE(ABORT, 'audit records cannot be changed'); END;
"""

POSTGRES_APPEND_ONLY = f"""
CREATE FUNCTION lintel_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'audit records cannot be deleted';
    END IF;
    IF ({', '.join('NEW.' + c for c in CHAINED.split(', '))})
       IS DISTINCT FROM ({', '.join('OLD.' + c for c in CHAINED.split(', '))}) THEN
        RAISE EXCEPTION 'audit records cannot be changed';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER events_append_only BEFORE UPDATE OR DELETE ON events
    FOR EACH ROW EXECUTE FUNCTION lintel_events_append_only();
CREATE TRIGGER events_no_truncate BEFORE TRUNCATE ON events
    FOR EACH STATEMENT EXECUTE FUNCTION lintel_events_append_only();
"""

Step = str | Callable[[Database], None]
MIGRATIONS: list[tuple[int, str, dict[str, Step]]] = [
    (1, "baseline schema", {"sqlite": _sqlite_baseline, "postgres": POSTGRES_BASELINE}),
    (2, "audit trail is append-only", {"sqlite": SQLITE_APPEND_ONLY, "postgres": POSTGRES_APPEND_ONLY}),
]
LATEST = MIGRATIONS[-1][0]


class SchemaError(Exception):
    pass


def current_version(db: Database) -> int:
    if "schema_migrations" not in db.tables():
        return 0
    r = db.q1("SELECT MAX(version) v FROM schema_migrations")
    return int(r["v"] or 0)


def migrate(db: Database) -> list[int]:
    """Brings the database to LATEST; returns the versions applied."""
    db.script("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, "
              "applied DOUBLE PRECISION NOT NULL)")
    have = current_version(db)
    if have > LATEST:
        raise SchemaError(f"the database is at schema version {have}, newer than this server understands "
                          f"({LATEST}); upgrade the server, or restore a backup taken with this version")
    done = []
    for version, name, steps in MIGRATIONS:
        if version <= have:
            continue
        with db.transaction():
            step = steps[db.dialect]
            if callable(step):
                step(db)
            else:
                db.script(step)
            db.x("INSERT INTO schema_migrations(version, name, applied) VALUES(?, ?, ?)", (version, name, time.time()))
        done.append(version)
    return done
