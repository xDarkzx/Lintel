"""End-to-end: a simulated panel talks to the real controller and API."""

import hashlib
import hmac
import io
import struct
from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from lintel_server.access import LOCKOUT_THRESHOLD, AccessEngine
from lintel_server.controller import Controller, photo_key
from lintel_server.protocol import Decision, Header, MsgType, Reason, open_frame, peek_header, seal
from lintel_server.store import Store
from lintel_server.web import Hub, create_app


class FakeTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append(data)


class Panel:
    """Plays the role of the Guition keypad."""

    def __init__(self, ctl, door_id, key, net):
        self.ctl, self.door, self.key, self.net, self.ctr = ctl, door_id, key, net, 0

    def frame(self, t, payload):
        self.ctr += 1
        return seal(self.key, self.net, Header(t, 0, self.door, self.ctr), payload)

    def pin(self, pin, raw=None):
        f = raw or self.frame(MsgType.PIN_REQ, bytes([len(pin)]) + pin.encode().ljust(9, b"\x00"))
        before = len(self.ctl.transport.sent)
        self.ctl.datagram(f, ("10.0.0.5", 5000))
        if len(self.ctl.transport.sent) == before:
            return None
        h, pt = open_frame(self.key, self.net, self.ctl.transport.sent[-1])
        assert h.type == MsgType.PIN_RESP
        return pt


def resp(pt):
    ctr, dec, reason, unlock, lock = struct.unpack_from("<IBBHH", pt)
    return ctr, Decision(dec), Reason(reason), unlock, lock, pt[10:].rstrip(b"\x00").decode()


@pytest.fixture
def env(tmp_path):
    store = Store(tmp_path)
    hub = Hub()
    ctl = Controller(store, AccessEngine(store), hub.publish)
    ctl.transport = FakeTransport()
    client = TestClient(create_app(store, ctl, hub, 47800))
    # The test client also plays the door controller, which presents the site token.
    client.headers["Authorization"] = f"Bearer {store.secrets.controller_token}"
    pw = (tmp_path / "initial_admin.txt").read_text().split("password: ")[1].strip()
    assert client.post("/api/login", json={"username": "admin", "password": pw}).status_code == 200
    door = client.post("/api/doors", json={"id": 1, "name": "Main Entrance"}).json()
    always = next(s["id"] for s in client.get("/api/schedules").json() if s["name"] == "24/7")
    gid = client.post("/api/groups", json={"name": "Staff", "schedule_id": always, "doors": [1]}).json()["id"]
    panel = Panel(ctl, 1, bytes.fromhex(door["key"]), int(door["net_id"], 16))
    return store, ctl, client, panel, gid


def add(client, gid, first, pin, **kw):
    r = client.post("/api/cardholders", json={"first_name": first, "last_name": "Test", "pin": pin,
                                              "groups": [gid], **kw})
    assert r.status_code == 200, r.text
    return r.json()


def test_grant_names_person_and_binds_counter(env):
    store, ctl, client, panel, gid = env
    add(client, gid, "Dan", "2468")
    ctr, dec, reason, unlock, _, name = resp(panel.pin("2468"))
    assert dec == Decision.GRANT and reason == Reason.OK and name == "Dan" and unlock == 5000
    assert ctr == panel.ctr
    ev = client.get("/api/events?kind=access.*").json()[0]
    assert ev["kind"] == "access.granted" and ev["cardholder_name"] == "Dan Test"


def test_bad_pin_then_lockout_and_alarm(env):
    store, ctl, client, panel, gid = env
    add(client, gid, "Dan", "2468")
    for _ in range(LOCKOUT_THRESHOLD - 1):
        assert resp(panel.pin("1111"))[2] == Reason.BAD_PIN
    r = resp(panel.pin("1111"))
    assert r[2] == Reason.LOCKED_OUT and r[4] >= 30
    assert resp(panel.pin("2468"))[2] == Reason.LOCKED_OUT  # even the right PIN, while locked
    lock = next(a for a in client.get("/api/alarms").json() if a["kind"] == "keypad.lockout")
    assert lock["priority"] == 1

    # The panel's photo of the person is accepted for the lockout attempt.
    buf = io.BytesIO()
    Image.new("RGB", (320, 240), (90, 20, 20)).save(buf, "JPEG")
    jpeg = buf.getvalue()
    req = panel.ctr - 1  # the attempt that started the lockout
    mac = hmac.new(photo_key(panel.key), f"1:{req}:".encode() + hashlib.sha256(jpeg).digest(),
                   hashlib.sha256).hexdigest()
    r = client.post("/api/door/1/photo", content=jpeg, headers={"x-lintel-req": str(req), "x-lintel-mac": mac})
    assert r.status_code == 200, r.text


def test_duress_grants_silently_but_raises_critical_alarm(env):
    store, ctl, client, panel, gid = env
    add(client, gid, "Dan", "2468", duress_pin="1357")
    _, dec, _, _, _, name = resp(panel.pin("1357"))
    assert dec == Decision.GRANT and name == "Dan"
    a = client.get("/api/alarms").json()[0]
    assert a["kind"] == "duress" and a["priority"] == 1
    assert client.get("/api/events?kind=access.*").json()[0]["kind"] == "access.granted"


def test_revoked_wrong_door_schedule_and_lockdown(env):
    store, ctl, client, panel, gid = env
    ch = add(client, gid, "Dan", "2468")
    client.patch(f"/api/cardholders/{ch['id']}", json={"active": False})
    assert resp(panel.pin("2468"))[2] == Reason.REVOKED
    client.patch(f"/api/cardholders/{ch['id']}", json={"active": True, "groups": []})
    assert resp(panel.pin("2468"))[2] == Reason.DOOR_NOT_ALLOWED

    other_day = 1 << ((datetime.now().weekday() + 3) % 7)
    never = client.post("/api/schedules", json={"name": "Never", "windows": [
        {"days": other_day, "start_min": 0, "end_min": 1}]}).json()["id"]
    g2 = client.post("/api/groups", json={"name": "Night", "schedule_id": never, "doors": [1]}).json()["id"]
    client.patch(f"/api/cardholders/{ch['id']}", json={"groups": [g2]})
    assert resp(panel.pin("2468"))[2] == Reason.OUTSIDE_SCHEDULE

    client.patch(f"/api/cardholders/{ch['id']}", json={"groups": [gid]})
    add(client, gid, "Guard", "8642", override=True)
    assert client.post("/api/mode", json={"mode": 1}).status_code == 200
    assert resp(panel.pin("2468"))[2] == Reason.LOCKDOWN
    assert resp(panel.pin("8642"))[1] == Decision.GRANT


def test_replayed_and_forged_frames_get_no_reply(env):
    store, ctl, client, panel, gid = env
    add(client, gid, "Dan", "2468")
    f = panel.frame(MsgType.PIN_REQ, bytes([4]) + b"2468" + bytes(5))
    assert panel.pin("", raw=f) is not None
    assert panel.pin("", raw=f) is None  # replay
    g = bytearray(panel.frame(MsgType.PIN_REQ, bytes([4]) + b"2468" + bytes(5)))
    g[-1] ^= 1
    assert panel.pin("", raw=bytes(g)) is None  # forgery
    assert ctl.doors[1].rejects == 2
    assert any(e["kind"] == "link.rejected" for e in client.get("/api/events").json())


def test_heartbeat_ack_carries_mode_and_binds_counter(env):
    store, ctl, client, panel, gid = env
    client.post("/api/mode", json={"mode": 1})
    ctl.datagram(panel.frame(MsgType.HEARTBEAT, bytes(11)), ("10.0.0.5", 5000))
    h, pt = open_frame(panel.key, panel.net, ctl.transport.sent[-1])
    assert h.type == MsgType.HEARTBEAT_ACK and pt[0] == 1
    assert int.from_bytes(pt[7:11], "little") == panel.ctr
    # Must equal HeartbeatAck::kLen in the C++ core or the panel drops every ack.
    assert len(pt) == 41 and pt[12:].rstrip(b"\x00") == b"Main Entrance"


def test_controller_counters_survive_restart(env):
    store, ctl, client, panel, gid = env
    add(client, gid, "Dan", "2468")
    panel.pin("2468")
    first = peek_header(ctl.transport.sent[-1]).counter
    old = panel.frame(MsgType.PIN_REQ, bytes([4]) + b"2468" + bytes(5))
    ctl.datagram(old, ("10.0.0.5", 5000))

    ctl2 = Controller(store, AccessEngine(store), lambda m: None)
    ctl2.transport = FakeTransport()
    ctl2.load_doors()
    panel.ctl = ctl2
    assert panel.pin("", raw=old) is None  # replay across a server restart
    panel.pin("2468")
    assert peek_header(ctl2.transport.sent[-1]).counter > first


def test_photo_upload_is_signed_stamped_and_chained(env):
    store, ctl, client, panel, gid = env
    add(client, gid, "Dan", "2468")
    panel.pin("2468")
    buf = io.BytesIO()
    Image.new("RGB", (640, 480), (40, 60, 80)).save(buf, "JPEG")
    jpeg = buf.getvalue()
    mac = hmac.new(photo_key(panel.key), f"1:{panel.ctr}:".encode() + hashlib.sha256(jpeg).digest(),
                   hashlib.sha256).hexdigest()
    hdr = {"x-lintel-req": str(panel.ctr)}
    assert client.post("/api/door/1/photo", content=jpeg, headers={**hdr, "x-lintel-mac": "00" * 32}).status_code == 403
    ok = client.post("/api/door/1/photo", content=jpeg, headers={**hdr, "x-lintel-mac": mac})
    assert ok.status_code == 200, ok.text
    img = client.get(f"/api/photos/{ok.json()['event']}.jpg")
    assert img.status_code == 200 and img.content[:2] == b"\xff\xd8"
    assert client.post("/api/door/1/photo", content=jpeg, headers={**hdr, "x-lintel-mac": mac}).status_code == 409
    assert any("sha256=" in e["detail"] for e in client.get("/api/events?kind=photo.*").json())

    # A wrong PIN is photographed too.
    assert resp(panel.pin("9999"))[2] == Reason.BAD_PIN
    mac = hmac.new(photo_key(panel.key), f"1:{panel.ctr}:".encode() + hashlib.sha256(jpeg).digest(),
                   hashlib.sha256).hexdigest()
    r = client.post("/api/door/1/photo", content=jpeg, headers={"x-lintel-req": str(panel.ctr), "x-lintel-mac": mac})
    assert r.status_code == 200, r.text
    denied = client.get("/api/events?kind=access.denied").json()[0]
    assert denied["photo"]


def drop_append_only_guards(store):
    """What an attacker with raw access to the database can do: remove the
    database's own rules. The hash chain must still catch what follows."""
    if store.db.dialect == "sqlite":
        store.db.script("DROP TRIGGER events_no_delete; DROP TRIGGER events_no_rewrite;")
    else:
        store.db.script("DROP TRIGGER events_append_only ON events; DROP TRIGGER events_no_truncate ON events;")


def test_journal_detects_tampering(env):
    store, ctl, client, panel, gid = env
    add(client, gid, "Dan", "2468")
    panel.pin("2468")
    assert client.get("/api/journal/verify").json()["ok"]
    drop_append_only_guards(store)
    store.x("UPDATE events SET detail='nothing to see' WHERE kind='access.granted'")
    v = client.get("/api/journal/verify").json()
    assert not v["ok"] and v["why"] == "record altered"


def test_the_database_refuses_to_rewrite_or_delete_history(env):
    store, ctl, client, panel, gid = env
    add(client, gid, "Dan", "2468")
    panel.pin("2468")
    for sql in ("UPDATE events SET detail='nothing to see' WHERE kind='access.granted'",
                "UPDATE events SET ts=0 WHERE seq=1",
                "DELETE FROM events WHERE kind='access.granted'"):
        with pytest.raises(Exception, match="audit records cannot be"):
            store.x(sql)
    # The one field that may change: retention clears a photo reference.
    store.x("UPDATE events SET photo=NULL WHERE seq=1")
    assert client.get("/api/journal/verify").json()["ok"]


def test_roles_and_pin_rules(env):
    store, ctl, client, panel, gid = env
    assert client.post("/api/cardholders", json={"first_name": "A", "pin": "1111"}).status_code == 400
    assert client.post("/api/cardholders", json={"first_name": "A", "pin": "1234"}).status_code == 400
    add(client, gid, "Dan", "2468")
    assert client.post("/api/cardholders", json={"first_name": "B", "pin": "2468"}).status_code == 409
    client.post("/api/operators", json={"username": "desk", "password": "desk-password-1", "role": "viewer"})
    v = TestClient(client.app)
    v.post("/api/login", json={"username": "desk", "password": "desk-password-1"})
    assert v.get("/api/events").status_code == 200
    assert v.post("/api/mode", json={"mode": 1}).status_code == 403
    assert TestClient(client.app).get("/api/events").status_code == 401


def test_controller_endpoints_need_the_token(env):
    store, ctl, client, panel, gid = env
    anon = TestClient(client.app)
    r = anon.post("/api/devices/announce", json={"serial": "LNT-000000000001", "pubkey": "00" * 32})
    assert r.status_code == 401
    r = anon.post("/api/door/1/photo", content=b"x", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_security_headers_present(env):
    store, ctl, client, panel, gid = env
    h = client.get("/").headers
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"


def test_operator_two_factor_and_login_lockout(env):
    from lintel_server.security import totp_now
    store, ctl, client, panel, gid = env
    setup = client.post("/api/me/mfa/setup").json()
    assert setup["qr_svg"].startswith("<?xml") or setup["qr_svg"].startswith("<svg")
    assert client.post("/api/me/mfa/confirm", json={"code": "000000" if totp_now(setup["secret"]) != "000000"
                                                    else "111111"}).status_code == 400
    assert client.post("/api/me/mfa/confirm", json={"code": totp_now(setup["secret"])}).status_code == 200

    pw = (store.data_dir / "initial_admin.txt").read_text().split("password: ")[1].strip()
    fresh = TestClient(client.app)
    assert fresh.post("/api/login", json={"username": "admin", "password": pw}).json() == {"mfa_required": True}
    code = totp_now(setup["secret"])
    # The code used to confirm is spent; the same 30 s step cannot be replayed.
    assert fresh.post("/api/login", json={"username": "admin", "password": pw, "code": code}).status_code == 401

    attacker = TestClient(client.app)
    # The replayed code above already counts as one failure for this name and address.
    for _ in range(3):
        assert attacker.post("/api/login", json={"username": "admin", "password": "guess"}).status_code == 401
    assert attacker.post("/api/login", json={"username": "admin", "password": "guess"}).status_code == 401
    assert attacker.post("/api/login", json={"username": "admin", "password": pw}).status_code == 429
    assert any(a["kind"] == "operator.bruteforce" for a in client.get("/api/alarms").json())


def test_changing_a_missing_door_or_floor_is_not_found(env):
    store, ctl, client, panel, gid = env
    # An insert first, so a stale "last inserted id" would look like success.
    client.post("/api/floors", json={"name": "Ground"})
    assert client.post("/api/doors/9/rekey").status_code == 404
    assert client.patch("/api/floors/999", json={"name": "Roof"}).status_code == 404


def test_a_valid_credential_between_guesses_does_not_reset_the_lockout(env):
    store, ctl, client, panel, gid = env
    ch = add(client, gid, "Dan", "2468")
    client.patch(f"/api/cardholders/{ch['id']}", json={"active": False})  # even a revoked PIN
    for _ in range(LOCKOUT_THRESHOLD - 1):
        assert resp(panel.pin("1111"))[2] == Reason.BAD_PIN
        assert resp(panel.pin("2468"))[2] == Reason.REVOKED
    assert resp(panel.pin("1111"))[2] == Reason.LOCKED_OUT


def test_keypad_failures_expire_and_the_doubling_fades():
    from lintel_server.access import FAILURE_WINDOW_S, LOCKOUT_BASE_S, STRIKE_RESET_S, KeypadGuard
    g = KeypadGuard()
    for i in range(LOCKOUT_THRESHOLD - 1):
        assert not g.fail(1000 + i)
    assert not g.fail(1000 + FAILURE_WINDOW_S + 10)  # the earlier ones have expired
    t = 5000.0
    for _ in range(LOCKOUT_THRESHOLD):
        g.fail(t)
    assert g.locked(t) == LOCKOUT_BASE_S
    t += LOCKOUT_BASE_S
    for _ in range(LOCKOUT_THRESHOLD):
        g.fail(t)
    assert g.locked(t) == 2 * LOCKOUT_BASE_S  # doubles on a repeat
    t += STRIKE_RESET_S + 2 * LOCKOUT_BASE_S
    for _ in range(LOCKOUT_THRESHOLD):
        g.fail(t)
    assert g.locked(t) == LOCKOUT_BASE_S  # a quiet hour starts it over


def test_a_valid_credential_between_guesses_does_not_reset_the_lockout(env):
    store, ctl, client, panel, gid = env
    ch = add(client, gid, "Dan", "2468")
    client.patch(f"/api/cardholders/{ch['id']}", json={"active": False})  # even a revoked PIN
    for _ in range(LOCKOUT_THRESHOLD - 1):
        assert resp(panel.pin("1111"))[2] == Reason.BAD_PIN
        assert resp(panel.pin("2468"))[2] == Reason.REVOKED
    assert resp(panel.pin("1111"))[2] == Reason.LOCKED_OUT


def test_keypad_failures_expire_and_the_doubling_fades():
    from lintel_server.access import FAILURE_WINDOW_S, LOCKOUT_BASE_S, STRIKE_RESET_S, KeypadGuard
    g = KeypadGuard()
    for i in range(LOCKOUT_THRESHOLD - 1):
        assert not g.fail(1000 + i)
    assert not g.fail(1000 + FAILURE_WINDOW_S + 10)  # the earlier ones have expired
    t = 5000.0
    for _ in range(LOCKOUT_THRESHOLD):
        g.fail(t)
    assert g.locked(t) == LOCKOUT_BASE_S
    t += LOCKOUT_BASE_S
    for _ in range(LOCKOUT_THRESHOLD):
        g.fail(t)
    assert g.locked(t) == 2 * LOCKOUT_BASE_S  # doubles on a repeat
    t += STRIKE_RESET_S + 2 * LOCKOUT_BASE_S
    for _ in range(LOCKOUT_THRESHOLD):
        g.fail(t)
    assert g.locked(t) == LOCKOUT_BASE_S  # a quiet hour starts it over


def test_required_admin_two_factor_is_enforced_by_the_server(env):
    from lintel_server.security import totp_now
    store, ctl, client, panel, gid = env
    assert client.patch("/api/settings", json={"require_admin_mfa": True}).status_code == 200
    # The console's nudge is not the only gate: the API itself refuses.
    assert client.get("/api/doors").status_code == 403
    assert client.post("/api/operators", json={"username": "sneaky", "password": "a-long-password-1",
                                               "role": "admin"}).status_code == 403
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect) as closed:
        with client.websocket_connect("/ws") as ws:
            ws.receive_json()
    assert closed.value.code == 4403
    # Turning two-factor on is still possible, and then everything works again.
    assert client.get("/api/me").status_code == 200
    secret = client.post("/api/me/mfa/setup").json()["secret"]
    assert client.post("/api/me/mfa/confirm", json={"code": totp_now(secret)}).status_code == 200
    assert client.get("/api/doors").status_code == 200


def test_only_one_server_can_run_on_a_database(tmp_path):
    from lintel_server.db import SQLiteDB
    first, second = SQLiteDB(tmp_path / "lintel.db"), SQLiteDB(tmp_path / "lintel.db")
    assert first.claim_server()
    assert not second.claim_server(wait_s=0)  # a second server would reuse door message counters
    first._server_lock.close()
    assert second.claim_server()  # released when the holder goes away
    second._server_lock.close()
    first.close()
    second.close()


def test_sqlite_reports_rows_affected_not_a_stale_insert_id(tmp_path):
    from lintel_server.db import SQLiteDB
    db = SQLiteDB(tmp_path / "t.db")
    db.x("CREATE TABLE t(id INTEGER PRIMARY KEY, v UNIQUE)")
    assert db.x("INSERT INTO t(v) VALUES(?)", (1,)) == 1
    assert db.x("INSERT INTO t(v) VALUES(?)", (2,)) == 2
    assert db.x("UPDATE t SET v=9 WHERE id=99") == 0
    assert db.x("DELETE FROM t WHERE id=99") == 0
    assert db.x("INSERT INTO t(v) VALUES(?) ON CONFLICT DO NOTHING", (2,)) == 0
    assert db.x("UPDATE t SET v=5 WHERE id=1") == 1
    db.close()


@pytest.mark.skipif(__import__("os").name == "nt", reason="Unix file permissions; Windows uses the folder's ACL")
def test_secret_files_are_readable_by_the_owner_only(tmp_path):
    import stat
    from lintel_server.security import ensure_tls
    Store(tmp_path)
    cert, key, _ = ensure_tls(tmp_path / "tls")
    for f in (key, tmp_path / "initial_admin.txt", tmp_path / "secrets.json"):
        assert stat.S_IMODE(f.stat().st_mode) == 0o600, f


def test_an_unconfirmed_two_factor_secret_expires(env):
    import time
    from lintel_server.security import totp_now
    from lintel_server.web import PENDING_TOTP_S
    store, ctl, client, panel, gid = env
    secret = client.post("/api/me/mfa/setup").json()["secret"]
    admin_id = store.q1("SELECT id FROM operators WHERE username='admin'")["id"]
    stale = int(time.time()) - PENDING_TOTP_S - 1
    store.set_setting(f"pending_totp:{admin_id}", f"{stale}:{secret}")  # shown too long ago
    r = client.post("/api/me/mfa/confirm", json={"code": totp_now(secret)})
    assert r.status_code == 400 and "expired" in r.json()["detail"]
    assert store.q1("SELECT totp_secret FROM operators WHERE id=?", (admin_id,))["totp_secret"] is None
