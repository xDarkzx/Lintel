"""SQLite persistence: cardholders, access groups, schedules, doors, the
hash-chained event journal, alarms and operators.

Every write that matters goes through `journal()`, which appends to a single
HMAC chain, so access decisions and operator actions share one tamper-evident
history.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .vault import TEXT_PREFIX, Vault, is_sealed

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
-- Deleted and overwritten values are zeroed on disk, not left in free pages:
-- a removed cardholder, a changed PIN or a replaced key must not be recoverable.
PRAGMA secure_delete=ON;

CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS operators (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    active INTEGER NOT NULL DEFAULT 1,
    created REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    operator_id INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    expires REAL NOT NULL
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
    rssi INTEGER
);

CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS schedule_windows (
    id INTEGER PRIMARY KEY,
    schedule_id INTEGER NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
    days INTEGER NOT NULL,          -- bit 0 = Monday
    start_min INTEGER NOT NULL,
    end_min INTEGER NOT NULL        -- end < start wraps past midnight
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
    override INTEGER NOT NULL DEFAULT 0,  -- may open doors during lockdown
    active INTEGER NOT NULL DEFAULT 1,
    valid_from REAL,
    valid_until REAL,
    notes TEXT NOT NULL DEFAULT '',
    created REAL NOT NULL
);

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
    day TEXT NOT NULL UNIQUE,   -- YYYY-MM-DD, site local
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS floors (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    level INTEGER NOT NULL DEFAULT 0,   -- display order, lowest first
    plan TEXT,                          -- file in data/plans, re-encoded on upload
    width INTEGER,
    height INTEGER,
    created REAL NOT NULL
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
    priority INTEGER NOT NULL,        -- 1 critical .. 4 low
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    door_id INTEGER,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'acknowledged', 'cleared')),
    ack_by TEXT,
    ack_ts REAL,
    note TEXT NOT NULL DEFAULT ''
);
"""

# Fields that make up an event's hash-chain body, in a fixed order.
_CHAIN_FIELDS = ("seq", "ts", "kind", "door_id", "cardholder_id", "operator", "decision", "reason", "detail", "req_ctr")


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${dk.hex()}"


def check_password(pw: str, stored: str) -> bool:
    try:
        _, salt, dk = stored.split("$")
    except ValueError:
        return False
    got = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
    return hmac.compare_digest(got.hex(), dk)


@dataclass
class Secrets:
    net_id: int
    pepper: bytes      # keys PIN tags; never stored in the database
    audit_key: bytes   # keys the event chain
    controller_token: str = ""  # door controllers present this on every HTTP call

    @staticmethod
    def load_or_create(path: Path, vault: Vault) -> "Secrets":
        """The pepper and audit key are kept wrapped by the master key, so the
        file on its own reveals neither. Older files with them in the clear
        are rewritten wrapped."""
        if path.exists():
            d = json.loads(path.read_text())
            pepper = (vault.open("secrets.pepper", bytes.fromhex(d["pepper_enc"])) if "pepper_enc" in d
                      else bytes.fromhex(d["pepper"]))
            audit = (vault.open("secrets.audit_key", bytes.fromhex(d["audit_key_enc"])) if "audit_key_enc" in d
                     else bytes.fromhex(d["audit_key"]))
            s = Secrets(int(d["net_id"], 16), pepper, audit, d.get("controller_token", ""))
            if s.controller_token and "pepper_enc" in d and "audit_key_enc" in d:
                return s
            s.controller_token = s.controller_token or secrets.token_urlsafe(32)  # upgrade an older secrets file
        else:
            s = Secrets(secrets.randbits(32), secrets.token_bytes(32), secrets.token_bytes(32),
                        secrets.token_urlsafe(32))
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"net_id": f"{s.net_id:08x}",
                                   "pepper_enc": vault.seal("secrets.pepper", s.pepper).hex(),
                                   "audit_key_enc": vault.seal("secrets.audit_key", s.audit_key).hex(),
                                   "controller_token": s.controller_token}, indent=2))
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return s


class Store:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "photos").mkdir(exist_ok=True)
        self.vault = Vault(data_dir)
        self.secrets = Secrets.load_or_create(data_dir / "secrets.json", self.vault)
        self._db = sqlite3.connect(data_dir / "lintel.db", check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(SCHEMA)
        self._lock = threading.RLock()
        self._migrate()
        self._seed()
        self._encrypt_at_rest()
        # Round-the-clock schedules ignore holidays; everything else closes on them.
        self.x("UPDATE schedules SET observe_holidays = CASE WHEN name='24/7' THEN 0 ELSE 1 END "
               "WHERE observe_holidays IS NULL")

    # ---- low level ---------------------------------------------------------

    def q(self, sql: str, args: tuple | list = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def q1(self, sql: str, args: tuple | list = ()) -> sqlite3.Row | None:
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args: tuple | list = ()) -> int:
        with self._lock:
            cur = self._db.execute(sql, args)
            return cur.lastrowid or cur.rowcount

    def backup_to(self, dst: sqlite3.Connection) -> None:
        with self._lock:
            self._db.backup(dst)

    @staticmethod
    def _secret_setting(key: str) -> bool:
        # Webhook URLs carry their own access token; pending TOTP secrets are second factors.
        return key == "alarm_webhook" or key.startswith("pending_totp:")

    def setting(self, key: str, default: str = "") -> str:
        r = self.q1("SELECT value FROM settings WHERE key=?", (key,))
        if r is None:
            return default
        if self._secret_setting(key) and r["value"]:
            return self.vault.open_text(f"settings.{key}", r["value"])
        return r["value"]

    def set_setting(self, key: str, value: str) -> None:
        if self._secret_setting(key) and value:
            value = self.vault.seal_text(f"settings.{key}", value)
        self.x("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (key, value))

    # ---- secrets at rest -------------------------------------------------------------------
    # Each value is bound to its row, so it cannot be moved to another record.

    def seal_door_key(self, door_id: int, key: bytes) -> bytes:
        return self.vault.seal(f"doors.key.{door_id}", key)

    def door_key(self, door_id: int, blob: bytes) -> bytes:
        return self.vault.open(f"doors.key.{door_id}", blob)

    def seal_totp(self, operator_id: int, secret: str) -> str:
        return self.vault.seal_text(f"operators.totp_secret.{operator_id}", secret)

    def totp_secret(self, operator_id: int, value: str) -> str:
        return self.vault.open_text(f"operators.totp_secret.{operator_id}", value)

    def seal_template(self, cardholder_id: int, embedding: bytes) -> bytes:
        return self.vault.seal(f"face_templates.embedding.{cardholder_id}", embedding)

    def template(self, cardholder_id: int, blob: bytes) -> bytes:
        return self.vault.open(f"face_templates.embedding.{cardholder_id}", blob)

    def _encrypt_at_rest(self) -> None:
        """Encrypts values written in the clear by older versions, in one
        transaction so a crash cannot leave some encrypted and some not."""
        n = 0
        with self._lock:
            db = self._db
            db.execute("BEGIN IMMEDIATE")
            try:
                for r in db.execute("SELECT id, key FROM doors").fetchall():
                    if not is_sealed(r["key"]):
                        db.execute("UPDATE doors SET key=? WHERE id=?",
                                   (self.seal_door_key(r["id"], bytes(r["key"])), r["id"]))
                        n += 1
                for r in db.execute("SELECT id, totp_secret FROM operators WHERE totp_secret IS NOT NULL").fetchall():
                    if not r["totp_secret"].startswith(TEXT_PREFIX):
                        db.execute("UPDATE operators SET totp_secret=? WHERE id=?",
                                   (self.seal_totp(r["id"], r["totp_secret"]), r["id"]))
                        n += 1
                for r in db.execute("SELECT id, cardholder_id, embedding FROM face_templates").fetchall():
                    if not is_sealed(r["embedding"]):
                        db.execute("UPDATE face_templates SET embedding=? WHERE id=?",
                                   (self.seal_template(r["cardholder_id"], bytes(r["embedding"])), r["id"]))
                        n += 1
                for r in db.execute("SELECT key, value FROM settings").fetchall():
                    if self._secret_setting(r["key"]) and r["value"] and not r["value"].startswith(TEXT_PREFIX):
                        db.execute("UPDATE settings SET value=? WHERE key=?",
                                   (self.vault.seal_text(f"settings.{r['key']}", r["value"]), r["key"]))
                        n += 1
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        if n:
            self.journal("system.encrypted_at_rest", operator="system",
                         detail=f"{n} stored secrets encrypted with the site master key")
        if n or self.setting("storage_scrubbed") != "1":
            self._scrub()
            self.set_setting("storage_scrubbed", "1")

    def _scrub(self) -> None:
        """Rewrites the database file and empties the write-ahead log, so
        plaintext left in free pages by older versions is gone from disk.
        Encrypting a value in place does not erase its old bytes; this does."""
        with self._lock:
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._db.execute("VACUUM")
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def _migrate(self) -> None:
        """Additive column changes for databases created by older versions."""
        for table, column, decl in (("doors", "credential_mode", "TEXT NOT NULL DEFAULT 'pin'"),
                                    ("cardholders", "card_tag", "BLOB"),
                                    ("doors", "diag", "TEXT"),
                                    ("doors", "diag_ts", "REAL"),
                                    ("doors", "key_created", "REAL"),
                                    ("operators", "totp_secret", "TEXT"),
                                    ("operators", "totp_last_step", "INTEGER NOT NULL DEFAULT 0"),
                                    ("operators", "last_login", "REAL"),
                                    ("sessions", "last_seen", "REAL"),
                                    ("schedules", "observe_holidays", "INTEGER"),
                                    # Where the door is on a floor plan: fractions of the plan's width
                                    # and height, so markers stay put whatever size the plan is shown at.
                                    ("doors", "floor_id", "INTEGER REFERENCES floors(id) ON DELETE SET NULL"),
                                    ("doors", "map_x", "REAL"),
                                    ("doors", "map_y", "REAL"),
                                    ("doors", "map_locked", "INTEGER NOT NULL DEFAULT 0")):
            cols = {r["name"] for r in self.q(f"PRAGMA table_info({table})")}
            if column not in cols:
                self.x(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        self.x("CREATE UNIQUE INDEX IF NOT EXISTS cardholders_card ON cardholders(card_tag)")
        self.x("UPDATE doors SET key_created=? WHERE key_created IS NULL", (time.time(),))
        # Round-the-clock schedules ignore holidays; everything else closes on them.
        self.x("UPDATE schedules SET observe_holidays = CASE WHEN name='24/7' THEN 0 ELSE 1 END "
               "WHERE observe_holidays IS NULL")
        for k, v in (("photo_retention_days", "90"), ("rekey_days", "30"), ("require_admin_mfa", "0"),
                     ("tailgate_detection", "1")):
            if not self.setting(k):
                self.set_setting(k, v)

    # ---- first run ----------------------------------------------------------

    def _seed(self) -> None:
        if self.q1("SELECT 1 FROM operators"):
            return
        pw = secrets.token_urlsafe(12)
        self.x("INSERT INTO operators(username, pw_hash, role, created) VALUES(?, ?, 'admin', ?)",
               ("admin", hash_password(pw), time.time()))
        (self.data_dir / "initial_admin.txt").write_text(f"username: admin\npassword: {pw}\n")
        always = self.x("INSERT INTO schedules(name) VALUES('24/7')")
        self.x("INSERT INTO schedule_windows(schedule_id, days, start_min, end_min) VALUES(?, 127, 0, 1440)", (always,))
        office = self.x("INSERT INTO schedules(name) VALUES('Business hours')")
        self.x("INSERT INTO schedule_windows(schedule_id, days, start_min, end_min) VALUES(?, 31, 420, 1140)",
               (office,))
        self.set_setting("site_mode", "0")
        self.set_setting("site_name", "Lintel HQ")
        self.journal("system.initialised", detail="database created")

    # ---- PIN tags -----------------------------------------------------------

    def pin_tag(self, pin: str) -> bytes:
        """Keyed hash of a PIN. The key (pepper) lives in secrets.json, not
        the database, so a stolen database cannot be brute-forced offline."""
        return hmac.new(self.secrets.pepper, b"lintel-pin:" + pin.encode(), hashlib.sha256).digest()

    def card_tag(self, uid: bytes) -> bytes:
        """Keyed hash of a card UID, so the database never holds raw card numbers."""
        return hmac.new(self.secrets.pepper, b"lintel-card:" + uid, hashlib.sha256).digest()

    # ---- the journal ----------------------------------------------------------

    def _link(self, prev: str, row: dict[str, Any]) -> str:
        body = json.dumps([row.get(f) for f in _CHAIN_FIELDS], separators=(",", ":"), default=str)
        return hmac.new(self.secrets.audit_key, (prev + body).encode(), hashlib.sha256).hexdigest()

    def journal(self, kind: str, *, door_id: int | None = None, cardholder_id: int | None = None,
                operator: str | None = None, decision: str | None = None, reason: str | None = None,
                detail: str = "", req_ctr: int | None = None) -> dict[str, Any]:
        with self._lock:
            last = self.q1("SELECT seq, link FROM events ORDER BY seq DESC LIMIT 1")
            seq = (last["seq"] + 1) if last else 1
            prev = last["link"] if last else "0" * 64
            row: dict[str, Any] = {"seq": seq, "ts": round(time.time(), 3), "kind": kind, "door_id": door_id,
                                   "cardholder_id": cardholder_id, "operator": operator, "decision": decision,
                                   "reason": reason, "detail": detail, "req_ctr": req_ctr}
            row["link"] = self._link(prev, row)
            self.x("INSERT INTO events(seq, ts, kind, door_id, cardholder_id, operator, decision, reason, detail, "
                   "req_ctr, link) VALUES(:seq, :ts, :kind, :door_id, :cardholder_id, :operator, :decision, :reason, "
                   ":detail, :req_ctr, :link)", row)
            row["photo"] = None
            return row

    def verify_journal(self) -> dict[str, Any]:
        prev = "0" * 64
        n = 0
        for r in self.q("SELECT * FROM events ORDER BY seq"):
            n += 1
            d = dict(r)
            if d["seq"] != n:
                return {"ok": False, "checked": n - 1, "broken_at": d["seq"], "why": "sequence gap"}
            if not hmac.compare_digest(self._link(prev, d), d["link"]):
                return {"ok": False, "checked": n - 1, "broken_at": d["seq"], "why": "record altered"}
            prev = d["link"]
        return {"ok": True, "checked": n, "head": prev}

    # ---- alarms ------------------------------------------------------------------

    def raise_alarm(self, priority: int, kind: str, title: str, *, door_id: int | None = None,
                    event_seq: int | None = None) -> dict[str, Any]:
        aid = self.x("INSERT INTO alarms(ts, event_seq, priority, kind, title, door_id) VALUES(?, ?, ?, ?, ?, ?)",
                     (time.time(), event_seq, priority, kind, title, door_id))
        alarm = dict(self.q1("SELECT * FROM alarms WHERE id=?", (aid,)))
        from . import notify
        notify.send_async(self, alarm)
        return alarm
