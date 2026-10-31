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


def test_journal_detects_tampering(env):
    store, ctl, client, panel, gid = env
    add(client, gid, "Dan", "2468")
    panel.pin("2468")
    assert client.get("/api/journal/verify").json()["ok"]
    store.x("UPDATE events SET detail='nothing to see' WHERE kind='access.granted'")
    v = client.get("/api/journal/verify").json()
    assert not v["ok"] and v["why"] == "record altered"


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
