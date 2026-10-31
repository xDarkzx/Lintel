"""Encrypted backup and restore.

A backup is everything needed to rebuild the server after losing its disk:
the database, secrets.json (PIN pepper, journal key, controller token) and the
TLS certificate controllers have pinned, optionally with the entry photos.

    LINTELBK1 | salt(16) | nonce(12) | AES-256-GCM(tar.gz)
    key = scrypt(passphrase, salt, n=2^15, r=8, p=1)

The passphrase is never stored. Restoring is a command-line operation only.
"""

from __future__ import annotations

import io
import os
import secrets
import sqlite3
import tarfile
import tempfile
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"LINTELBK1"
MIN_PASSPHRASE = 16


class BackupError(Exception):
    pass


def _key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())


def create_backup(data_dir: Path, db: sqlite3.Connection, passphrase: str, include_photos: bool = False) -> bytes:
    if len(passphrase) < MIN_PASSPHRASE:
        raise BackupError(f"passphrase must be at least {MIN_PASSPHRASE} characters")
    buf = io.BytesIO()
    with tempfile.TemporaryDirectory() as tmp:
        snap = Path(tmp) / "lintel.db"
        dst = sqlite3.connect(snap)
        db.backup(dst)  # consistent online snapshot, safe while the server runs
        dst.close()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(snap, arcname="lintel.db")
            # The keyring is useless without the master key. master.key exists only when the
            # key is kept beside the data (development); a key from LINTEL_MASTER_KEY_FILE never
            # enters a backup, and restoring needs that same key.
            for rel in ("secrets.json", "keyring.json", "master.key", "tls/server.crt", "tls/server.key"):
                if (data_dir / rel).exists():
                    tar.add(data_dir / rel, arcname=rel)
            if (data_dir / "plans").exists():  # floor plans are site configuration, always kept
                tar.add(data_dir / "plans", arcname="plans")
            if include_photos and (data_dir / "photos").exists():
                tar.add(data_dir / "photos", arcname="photos")
            info = tarfile.TarInfo("BACKUP_INFO")
            meta = f"created={int(time.time())}\nphotos={int(include_photos)}\n".encode()
            info.size = len(meta)
            tar.addfile(info, io.BytesIO(meta))
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    return MAGIC + salt + nonce + AESGCM(_key(passphrase, salt)).encrypt(nonce, buf.getvalue(), MAGIC)


def open_backup(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 28 + 16:
        raise BackupError("not a Lintel backup")
    salt = blob[len(MAGIC):len(MAGIC) + 16]
    nonce = blob[len(MAGIC) + 16:len(MAGIC) + 28]
    try:
        return AESGCM(_key(passphrase, salt)).decrypt(nonce, blob[len(MAGIC) + 28:], MAGIC)
    except InvalidTag as e:
        raise BackupError("wrong passphrase, or the file has been altered") from e


def restore_backup(blob: bytes, passphrase: str, data_dir: Path, force: bool = False) -> list[str]:
    plain = open_backup(blob, passphrase)
    data_dir.mkdir(parents=True, exist_ok=True)
    if (data_dir / "lintel.db").exists() and not force:
        raise BackupError(f"{data_dir} already holds a database; pass --force to replace it")
    restored = []
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
        for m in tar.getmembers():
            target = (data_dir / m.name).resolve()
            # Refuse anything that would land outside the data folder.
            if not str(target).startswith(str(data_dir.resolve()) + os.sep) or not (m.isfile() or m.isdir()):
                raise BackupError(f"unsafe entry in backup: {m.name}")
        for m in tar.getmembers():
            if m.isfile() and m.name != "BACKUP_INFO":
                (data_dir / m.name).parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(m) as src:
                    (data_dir / m.name).write_bytes(src.read())
                restored.append(m.name)
    for wal in ("lintel.db-wal", "lintel.db-shm"):
        (data_dir / wal).unlink(missing_ok=True)  # stale journal files from the old database
    for rel in ("secrets.json", "keyring.json", "master.key", "tls/server.key"):
        try:
            os.chmod(data_dir / rel, 0o600)
        except OSError:
            pass
    return restored
