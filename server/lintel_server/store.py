"""Persistence: cardholders, access groups, schedules, doors, the
hash-chained event journal, alarms and operators, on SQLite or PostgreSQL
(see db.py) with versioned migrations (see migrations.py).

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
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import migrations
from .db import Database, connect
from .vault import TEXT_PREFIX, Vault, is_sealed

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
    def __init__(self, data_dir: Path, database_url: str | None = None) -> None:
        self.data_dir = data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "photos").mkdir(exist_ok=True)
        self.vault = Vault(data_dir)
        self.secrets = Secrets.load_or_create(data_dir / "secrets.json", self.vault)
        self.db: Database = connect(data_dir, database_url or os.environ.get("LINTEL_DATABASE_URL"))
        self.IntegrityError = self.db.IntegrityError
        self._lock = self.db.lock
        migrations.migrate(self.db)
        self._defaults()
        self._seed()
        self._encrypt_at_rest()

    @property
    def _db(self):
        """The raw SQLite connection, for SQLite-only maintenance and tests."""
        return self.db.conn

    # ---- low level ---------------------------------------------------------

    def q(self, sql: str, args: tuple | list = ()) -> list[Any]:
        return self.db.q(sql, args)

    def q1(self, sql: str, args: tuple | list = ()) -> Any:
        return self.db.q1(sql, args)

    def x(self, sql: str, args: tuple | list = ()) -> int:
        return self.db.x(sql, args)

    def backup_to(self, dst) -> None:
        """Consistent online copy of a SQLite database. PostgreSQL is backed up
        with its own tools (pg_dump, or the provider's snapshots)."""
        if self.db.dialect != "sqlite":
            raise RuntimeError("built-in backup covers SQLite; back up PostgreSQL with pg_dump or snapshots")
        with self._lock:
            self.db.conn.backup(dst)

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
        with self.db.transaction() as db:
            for r in db.q("SELECT id, key FROM doors"):
                if not is_sealed(r["key"]):
                    db.x("UPDATE doors SET key=? WHERE id=?", (self.seal_door_key(r["id"], bytes(r["key"])), r["id"]))
                    n += 1
            for r in db.q("SELECT id, totp_secret FROM operators WHERE totp_secret IS NOT NULL"):
                if not r["totp_secret"].startswith(TEXT_PREFIX):
                    db.x("UPDATE operators SET totp_secret=? WHERE id=?",
                         (self.seal_totp(r["id"], r["totp_secret"]), r["id"]))
                    n += 1
            for r in db.q("SELECT id, cardholder_id, embedding FROM face_templates"):
                if not is_sealed(r["embedding"]):
                    db.x("UPDATE face_templates SET embedding=? WHERE id=?",
                         (self.seal_template(r["cardholder_id"], bytes(r["embedding"])), r["id"]))
                    n += 1
            for r in db.q("SELECT key, value FROM settings"):
                if self._secret_setting(r["key"]) and r["value"] and not r["value"].startswith(TEXT_PREFIX):
                    db.x("UPDATE settings SET value=? WHERE key=?",
                         (self.vault.seal_text(f"settings.{r['key']}", r["value"]), r["key"]))
                    n += 1
        if n:
            self.journal("system.encrypted_at_rest", operator="system",
                         detail=f"{n} stored secrets encrypted with the site master key")
        if self.db.dialect == "sqlite" and (n or self.setting("storage_scrubbed") != "1"):
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

    def _defaults(self) -> None:
        """Data defaults every start: idempotent, safe on any version."""
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
        try:
            os.chmod(self.data_dir / "initial_admin.txt", 0o600)  # the first admin's password
        except OSError:
            pass
        always = self.x("INSERT INTO schedules(name) VALUES('24/7')")
        self.x("INSERT INTO schedule_windows(schedule_id, days, start_min, end_min) VALUES(?, 127, 0, 1440)", (always,))
        office = self.x("INSERT INTO schedules(name) VALUES('Business hours')")
        self.x("INSERT INTO schedule_windows(schedule_id, days, start_min, end_min) VALUES(?, 31, 420, 1140)",
               (office,))
        self.set_setting("site_mode", "0")
        self.set_setting("site_name", "Lintel HQ")
        self._defaults()
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
        # Reading the last link and appending the next must not interleave with
        # another writer, in this process or another server on the same database.
        with self.db.transaction() as db:
            last = db.q1("SELECT seq, link FROM events ORDER BY seq DESC LIMIT 1")
            seq = (last["seq"] + 1) if last else 1
            prev = last["link"] if last else "0" * 64
            row: dict[str, Any] = {"seq": seq, "ts": round(time.time(), 3), "kind": kind, "door_id": door_id,
                                   "cardholder_id": cardholder_id, "operator": operator, "decision": decision,
                                   "reason": reason, "detail": detail, "req_ctr": req_ctr}
            row["link"] = self._link(prev, row)
            db.x("INSERT INTO events(seq, ts, kind, door_id, cardholder_id, operator, decision, reason, detail, "
                 "req_ctr, link) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                 tuple(row[f] for f in ("seq", "ts", "kind", "door_id", "cardholder_id", "operator", "decision",
                                        "reason", "detail", "req_ctr", "link")))
            row["photo"] = None
            # Not part of the record or its link: the names the console shows,
            # so an event pushed to the live feed reads like one loaded later.
            door = db.q1("SELECT name FROM doors WHERE id=?", (door_id,)) if door_id is not None else None
            person = (db.q1("SELECT first_name, last_name FROM cardholders WHERE id=?", (cardholder_id,))
                      if cardholder_id is not None else None)
            row["door_name"] = door["name"] if door else None
            row["cardholder_name"] = f"{person['first_name']} {person['last_name']}" if person else None
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
