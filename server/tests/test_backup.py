import io
import tarfile

import pytest

from lintel_server.backup import MAGIC, BackupError, open_backup, restore_backup
from lintel_server.store import Store
from test_server import env, resp  # noqa: F401

PASS = "correct horse battery staple"


def download(client, **kw):
    pw = kw.pop("pw")
    return client.post("/api/backup", json={"passphrase": PASS, "password": pw, **kw})


def admin_pw(store):
    return (store.data_dir / "initial_admin.txt").read_text().split("password: ")[1].strip()


def test_backup_restores_a_working_site(env, tmp_path):
    store, ctl, client, panel, gid = env
    client.post("/api/cardholders", json={"first_name": "Ana", "pin": "3691", "groups": [gid]})
    panel.pin("3691")
    r = download(client, pw=admin_pw(store))
    assert r.status_code == 200 and r.content.startswith(MAGIC)
    assert "lintel-backup-" in r.headers["content-disposition"]

    target = tmp_path / "restored"
    files = restore_backup(r.content, PASS, target)
    # The test server has no TLS folder; a live one adds tls/server.crt and tls/server.key.
    assert {"lintel.db", "secrets.json"} <= set(files)
    restored = Store(target)
    assert restored.verify_journal()["ok"]
    # Same pepper, so PINs keep working after a restore.
    assert restored.q1("SELECT id FROM cardholders WHERE pin_tag=?", (restored.pin_tag("3691"),)) is not None
    assert any(e["kind"] == "system.backup" for e in client.get("/api/events?kind=system.*").json())


def test_backup_needs_admin_password_and_long_passphrase(env):
    store, ctl, client, panel, gid = env
    assert download(client, pw="wrong").status_code == 403
    assert client.post("/api/backup", json={"passphrase": "short", "password": admin_pw(store)}).status_code == 422


def test_wrong_passphrase_and_tampering_detected(env):
    store, ctl, client, panel, gid = env
    blob = download(client, pw=admin_pw(store)).content
    with pytest.raises(BackupError):
        open_backup(blob, "not the passphrase at all")
    bad = bytearray(blob)
    bad[-5] ^= 1
    with pytest.raises(BackupError):
        open_backup(bytes(bad), PASS)


def test_restore_refuses_to_overwrite_and_path_escape(env, tmp_path):
    store, ctl, client, panel, gid = env
    blob = download(client, pw=admin_pw(store)).content
    restore_backup(blob, PASS, tmp_path / "a")
    with pytest.raises(BackupError, match="already holds"):
        restore_backup(blob, PASS, tmp_path / "a")

    # A crafted archive with ../ in it is refused even with the right key.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from lintel_server.backup import _key
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("../evil.txt")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"pwnd"))
    salt, nonce = bytes(16), bytes(12)
    evil = MAGIC + salt + nonce + AESGCM(_key(PASS, salt)).encrypt(nonce, buf.getvalue(), MAGIC)
    with pytest.raises(BackupError, match="unsafe"):
        restore_backup(evil, PASS, tmp_path / "b")
    assert not (tmp_path / "evil.txt").exists()
