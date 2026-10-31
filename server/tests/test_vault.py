"""Encryption at rest: what a stolen database file, or a stolen secrets.json,
reveals (nothing), and the key handling around it."""

import base64
import json
import secrets
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from lintel_server.access import AccessEngine
from lintel_server.controller import Controller
from lintel_server.security import totp_now
from lintel_server.store import Store
from lintel_server.vault import Vault, VaultError, is_sealed
from test_hardening import fake_dns
from test_server import env  # noqa: F401  (fixture reuse)

SERVER = Path(__file__).resolve().parents[1]


def raw_files(store) -> bytes:
    """Everything SQLite has on disk, write-ahead log included."""
    store._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    d = store.data_dir
    return b"".join(p.read_bytes() for p in (d / "lintel.db", d / "lintel.db-wal") if p.exists())


def test_a_stolen_database_file_holds_no_secrets(env, monkeypatch):
    store, ctl, client, panel, gid = env
    door2 = client.post("/api/doors", json={"id": 2, "name": "Plant room"}).json()
    setup = client.post("/api/me/mfa/setup").json()
    assert client.post("/api/me/mfa/confirm", json={"code": totp_now(setup["secret"])}).status_code == 200
    fake_dns(monkeypatch, {"hooks.example": ["93.184.216.34"]})
    hook = "https://hooks.example/T0SECRET/B0SECRET/XyzSecretToken"
    assert client.put("/api/settings/webhook", json={"url": hook}).status_code == 200
    emb = np.random.default_rng(3).normal(size=128).astype(np.float32)
    cid = client.post("/api/cardholders", json={"first_name": "Ana"}).json()["id"]
    store.x("INSERT INTO face_templates(cardholder_id, embedding, source, created) VALUES(?, ?, 'upload', 0)",
            (cid, store.seal_template(cid, emb.tobytes())))

    disk = raw_files(store)
    for secret in (panel.key, bytes.fromhex(door2["key"]), setup["secret"].encode(), hook.encode(),
                   b"XyzSecretToken", emb.tobytes()[:32], store.secrets.pepper, store.secrets.audit_key):
        assert secret not in disk
    # ...while everything still works through the server.
    assert ctl.doors[2].key == bytes.fromhex(door2["key"])
    assert client.get("/api/settings/webhook").json()["url"] == hook


def test_secrets_json_alone_reveals_neither_the_pepper_nor_the_audit_key(env):
    store, ctl, client, panel, gid = env
    on_disk = json.loads((store.data_dir / "secrets.json").read_text())
    assert "pepper" not in on_disk and "audit_key" not in on_disk
    assert store.secrets.pepper.hex() not in json.dumps(on_disk)


def test_a_value_moved_to_another_row_will_not_decrypt(env):
    store, ctl, client, panel, gid = env
    client.post("/api/doors", json={"id": 2, "name": "Plant room"})
    k1 = store.q1("SELECT key FROM doors WHERE id=1")["key"]
    store.x("UPDATE doors SET key=? WHERE id=2", (k1,))  # door 1's key pasted into door 2
    with pytest.raises(VaultError, match="moved from another record"):
        ctl.load_door(2)


def test_altered_ciphertext_is_detected(env):
    store, ctl, client, panel, gid = env
    blob = bytearray(store.q1("SELECT key FROM doors WHERE id=1")["key"])
    blob[-1] ^= 1
    store.x("UPDATE doors SET key=? WHERE id=1", (bytes(blob),))
    with pytest.raises(VaultError):
        ctl.load_door(1)


def test_the_wrong_master_key_stops_the_server(tmp_path, monkeypatch):
    Store(tmp_path)  # creates master.key and keyring.json
    monkeypatch.setenv("LINTEL_MASTER_KEY", base64.b64encode(secrets.token_bytes(32)).decode())
    with pytest.raises(VaultError, match="does not open this site's keyring"):
        Store(tmp_path)


def test_the_master_key_can_live_outside_the_data_folder(tmp_path, monkeypatch):
    key_file = tmp_path / "secret_master_key"
    key_file.write_text(base64.b64encode(secrets.token_bytes(32)).decode())
    monkeypatch.setenv("LINTEL_MASTER_KEY_FILE", str(key_file))
    data = tmp_path / "data"
    Store(data)
    assert not (data / "master.key").exists()


def test_an_older_plaintext_database_is_encrypted_on_upgrade(tmp_path):
    store = Store(tmp_path)
    key = secrets.token_bytes(16)
    # What an older version wrote: the door key in the clear.
    store.x("INSERT INTO doors(id, name, key, unlock_ms) VALUES(3, 'Old door', ?, 5000)", (key,))
    store.x("INSERT INTO settings(key, value) VALUES('alarm_webhook', 'https://hooks.example/old-token')")
    store._db.close()

    upgraded = Store(tmp_path)
    # Encrypting in place must not leave the old bytes in free pages or the log.
    disk = raw_files(upgraded)
    assert key not in disk and b"old-token" not in disk
    blob = upgraded.q1("SELECT key FROM doors WHERE id=3")["key"]
    assert is_sealed(blob) and upgraded.door_key(3, blob) == key
    assert upgraded.setting("alarm_webhook") == "https://hooks.example/old-token"
    assert upgraded.q1("SELECT value FROM settings WHERE key='alarm_webhook'")["value"].startswith("enc:")
    ctl = Controller(upgraded, AccessEngine(upgraded), lambda m: None)
    ctl.load_door(3)
    assert ctl.doors[3].key == key
    assert upgraded.q("SELECT 1 FROM events WHERE kind='system.encrypted_at_rest'")


def test_deleted_records_do_not_linger_on_disk(env):
    store, ctl, client, panel, gid = env
    marker = "Zyxwvutsrq-Deleted-Person"
    for i in range(20):  # others on the same database page, as on a real site
        client.post("/api/cardholders", json={"first_name": f"Colleague{i}", "last_name": "x" * 30})
    cid = client.post("/api/cardholders", json={"first_name": marker}).json()["id"]
    store._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    assert client.delete(f"/api/cardholders/{cid}").status_code == 200
    events = store.q("SELECT seq FROM events WHERE detail LIKE ?", (f"%{marker}%",))
    for e in events:  # the audit trail keeps its own record; scrub those rows for this check
        store.x("UPDATE events SET detail='' WHERE seq=?", (e["seq"],))
    assert marker.encode() not in raw_files(store)


def test_rotating_the_master_key_keeps_everything_readable(tmp_path):
    store = Store(tmp_path)
    store.x("INSERT INTO doors(id, name, key, unlock_ms) VALUES(4, 'Lab', ?, 5000)",
            (store.seal_door_key(4, b"k" * 16),))
    store._db.close()
    new_key = base64.b64encode(secrets.token_bytes(32)).decode()
    new_file = tmp_path / "new.key"
    new_file.write_text(new_key)
    r = subprocess.run([sys.executable, "-m", "lintel_server", "rotate-master-key", "--data", str(tmp_path),
                        "--new-key-file", str(new_file)], cwd=SERVER, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    rotated = Store(tmp_path)  # master.key now holds the new key
    assert rotated.door_key(4, rotated.q1("SELECT key FROM doors WHERE id=4")["key"]) == b"k" * 16
    with pytest.raises(VaultError):
        Vault(tmp_path, master=secrets.token_bytes(32))
