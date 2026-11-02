"""Walk-through doors (Lintel Vision): groups recognised by face, each person
journalled, an unauthorised person raised as a P1 alarm."""

import pytest

from lintel_server.access import LOCKOUT_THRESHOLD
from lintel_server.protocol import Decision, Reason
from test_server import add, env  # noqa: F401  (fixture reuse)


@pytest.fixture
def engine_door(env):
    store, ctl, client, panel, gid = env
    assert client.patch("/api/doors/1", json={"credential_mode": "face_group"}).status_code == 200
    ana = add(client, gid, "Ana", "2468")
    return ctl.engine, 1, ana["id"]


def test_walk_through_accepts_face_or_pin_and_strangers_do_not_lock_the_door(engine_door):
    engine, door, ana_id = engine_door
    for _ in range(LOCKOUT_THRESHOLD + 2):
        v = engine.decide(door, face=(None, 0.1, None), enforce_mode=True)
        assert v.reason == Reason.NO_MATCH  # never LOCKED_OUT: passers-by are not guessing
    assert engine.decide(door, face=(ana_id, 0.9, None), enforce_mode=True).decision == Decision.GRANT
    assert engine.decide(door, pin="2468", enforce_mode=True).decision == Decision.GRANT
    assert engine.decide(door, card=b"\1\2\3\4", enforce_mode=True).reason == Reason.WRONG_MODE


def test_wrong_pins_still_lock_a_walk_through_door(engine_door):
    engine, door, ana_id = engine_door
    for _ in range(LOCKOUT_THRESHOLD - 1):
        assert engine.decide(door, pin="1111", enforce_mode=True).reason == Reason.BAD_PIN
    assert engine.decide(door, pin="1111", enforce_mode=True).reason == Reason.LOCKED_OUT


# ---- the walk-through face upload -------------------------------------------------------------

import hashlib  # noqa: E402
import hmac  # noqa: E402
import io  # noqa: E402
import struct  # noqa: E402
import time  # noqa: E402
from types import SimpleNamespace  # noqa: E402

import numpy as np  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from PIL import Image  # noqa: E402

from lintel_server.access import AccessEngine  # noqa: E402
from lintel_server.controller import Controller, photo_key  # noqa: E402
from lintel_server.protocol import MsgType, open_frame  # noqa: E402
from lintel_server.store import Store  # noqa: E402
from lintel_server.web import Hub, create_app  # noqa: E402
from test_enrolment import ANA, BEN, FakeFaces, unit  # noqa: E402
from test_server import FakeTransport, Panel, resp  # noqa: E402

STRANGER = unit(99)


def depth_png(kind="face"):
    y, x = np.mgrid[-1:1:64j, -1:1:64j]
    if kind == "face":
        a = 800 - 40 * np.sqrt(np.clip(1 - x ** 2 - y ** 2, 0, 1))
    else:  # a photo held up: flat, slightly tilted
        a = 700 + 60 * x + 30 * y
    buf = io.BytesIO()
    Image.fromarray(a.astype(np.uint16)).save(buf, "PNG")
    return buf.getvalue()


def enrol_face(store, cid, emb):
    store.x("INSERT INTO face_templates(cardholder_id, embedding, source, created) VALUES(?, ?, ?, ?)",
            (cid, store.seal_template(cid, emb.tobytes()), "test", time.time()))


@pytest.fixture
def walk_env(tmp_path):
    store = Store(tmp_path)
    hub = Hub()
    ctl = Controller(store, AccessEngine(store), hub.publish)
    ctl.transport = FakeTransport()
    faces = FakeFaces()
    client = TestClient(create_app(store, ctl, hub, 47800, faces=faces))
    client.headers["Authorization"] = f"Bearer {store.secrets.controller_token}"
    pw = (tmp_path / "initial_admin.txt").read_text().split("password: ")[1].strip()
    assert client.post("/api/login", json={"username": "admin", "password": pw}).status_code == 200
    door = client.post("/api/doors", json={"id": 1, "name": "Lab"}).json()
    assert client.patch("/api/doors/1", json={"credential_mode": "face_group"}).status_code == 200
    always = next(s["id"] for s in client.get("/api/schedules").json() if s["name"] == "24/7")
    gid = client.post("/api/groups", json={"name": "Staff", "schedule_id": always, "doors": [1]}).json()["id"]
    ana = add(client, gid, "Ana", "2468")
    ben = add(client, gid, "Ben", "3579")
    enrol_face(store, ana["id"], ANA)
    enrol_face(store, ben["id"], BEN)
    key = bytes.fromhex(door["key"])
    return SimpleNamespace(store=store, ctl=ctl, client=client, faces=faces, key=key, gid=gid, ana=ana, ben=ben,
                           panel=Panel(ctl, 1, key, int(door["net_id"], 16)))


def post_walk_face(w, ref, jpeg, depth, mac=None, door=1):
    body = struct.pack("<I", len(jpeg)) + jpeg + depth
    mac = mac or hmac.new(photo_key(w.key), f"walkface:{door}:{ref}:".encode() + hashlib.sha256(jpeg).digest()
                          + hashlib.sha256(depth).digest(), hashlib.sha256).hexdigest()
    return w.client.post(f"/api/door/{door}/walk/face", content=body,
                         headers={"x-lintel-req": str(ref), "x-lintel-mac": mac})


def cred_face(w, ref):
    """A sealed CredReq citing a face ref; returns the decoded reply."""
    p = bytes([4, 0]) + bytes(10) + bytes([0]) + bytes(8) + struct.pack("<I", ref)
    before = len(w.ctl.transport.sent)
    w.ctl.datagram(w.panel.frame(MsgType.CRED_REQ, p), ("10.0.0.9", 5000))
    assert len(w.ctl.transport.sent) == before + 1
    return resp(open_frame(w.key, w.panel.net, w.ctl.transport.sent[-1])[1])


def test_walk_face_matches_a_live_face_and_refuses_a_flat_one(walk_env):
    w = walk_env
    r = post_walk_face(w, 0x0101, w.faces.frame(emb=ANA), depth_png())
    assert r.status_code == 200 and r.json() == {"ok": True, "face": True}
    _, dec, reason, unlock, _, name = cred_face(w, 0x0101)
    assert dec == Decision.GRANT and name == "Ana" and unlock > 0

    r = post_walk_face(w, 0x0102, w.faces.frame(emb=ANA), depth_png("flat"))  # Ana's photo, held up
    assert r.status_code == 200 and r.json()["face"] is False
    assert cred_face(w, 0x0102)[2] == Reason.NO_FACE
    alarms = w.client.get("/api/alarms").json()
    assert any(a["kind"] == "face.spoof" and a["priority"] == 2 for a in alarms)
    assert any(e["kind"] == "face.spoof" for e in w.client.get("/api/events?kind=face.*").json())


def test_walk_face_checks_signature_mode_and_size(walk_env):
    w = walk_env
    jpg, d = w.faces.frame(emb=ANA), depth_png()
    assert post_walk_face(w, 0x0201, jpg, d, mac="00" * 32).status_code == 403
    assert post_walk_face(w, 0, jpg, d).status_code == 403
    r = w.client.post("/api/door/1/walk/face", content=b"\xff\xff\xff\x00" + jpg,
                      headers={"x-lintel-req": "513", "x-lintel-mac": "00" * 32})
    assert r.status_code == 400  # declared jpeg longer than the body
    assert post_walk_face(w, 0x0201, jpg, d, door=7).status_code == 404
    assert w.client.patch("/api/doors/1", json={"credential_mode": "pin"}).status_code == 200
    assert post_walk_face(w, 0x0201, jpg, d).status_code == 409


# ---- passages ---------------------------------------------------------------------------------

from lintel_server.protocol import Crossing  # noqa: E402
from lintel_server.walkthrough import PASSAGE_TTL_S, PASSAGES_MAX, PassageBook, passage_of  # noqa: E402

PERSON = {"id": 1, "first_name": "Ana", "last_name": "Test"}


def test_a_ref_carries_its_passage():
    assert passage_of(0x1203) == 0x1200


def test_reconcile_names_authorised_and_tailgaters():
    b = PassageBook()
    b.record(1, 0x1201, True, PERSON, None, 0)
    b.record(1, 0x1202, False, None, b"jpg", 0)
    r = b.reconcile(1, Crossing(0x1200, 3, False, (0x1201, 0x1202)), 1)
    assert [t.cardholder["id"] for t in r.authorised] == [1]
    assert [t.ref for t in r.tailgaters] == [0x1202] and r.tailgaters[0].jpeg == b"jpg"
    assert r.anonymous == 1 and r.unauthorised == 2
    assert b.reconcile(1, Crossing(0x1200, 1, False, (0x1201,)), 2).authorised == []  # a passage is used once


def test_a_retry_never_turns_a_granted_person_into_a_tailgater():
    b = PassageBook()
    b.record(1, 0x1201, True, PERSON, None, 0)
    b.record(1, 0x1201, False, None, None, 1)  # the unit retried; the held face was already used
    r = b.reconcile(1, Crossing(0x1200, 1, False, (0x1201,)), 2)
    assert r.unauthorised == 0 and len(r.authorised) == 1


def test_an_unknown_passage_with_entries_is_all_unauthorised():
    r = PassageBook().reconcile(1, Crossing(0x9900, 2, True, ()), 0)
    assert r.authorised == [] and r.anonymous == 2 and r.unauthorised == 2


def test_passages_are_bounded_and_expire():
    b = PassageBook()
    for i in range(PASSAGES_MAX + 50):
        b.record(1, ((i + 1) << 8) | 1, True, PERSON, None, 0)
    assert b.size() <= PASSAGES_MAX
    b.record(2, 0x0101, True, PERSON, None, PASSAGE_TTL_S + 1)
    assert b.size() == 1


def test_a_ref_listed_twice_does_not_hide_a_person():
    b = PassageBook()
    b.record(1, 0x1201, True, PERSON, None, 0)
    r = b.reconcile(1, Crossing(0x1200, 2, False, (0x1201, 0x1201)), 1)
    assert len(r.authorised) == 1 and r.anonymous == 1


# ---- crossing reports through the controller --------------------------------------------------

from lintel_server.protocol import CrossingAck  # noqa: E402


def send_crossing(w, c, raw=None):
    """Sends a sealed Crossing; returns the CrossingAck, or None if nothing came back."""
    f = raw or w.panel.frame(MsgType.CROSSING, c.encode())
    before = len(w.ctl.transport.sent)
    w.ctl.datagram(f, ("10.0.0.9", 5000))
    if len(w.ctl.transport.sent) == before:
        return None
    h, pt = open_frame(w.key, w.panel.net, w.ctl.transport.sent[-1])
    assert h.type == MsgType.CROSSING_ACK
    return CrossingAck.decode(pt)


def face_in(w, ref, emb):
    assert post_walk_face(w, ref, w.faces.frame(emb=emb), depth_png()).status_code == 200
    return cred_face(w, ref)


def unauthorised_alarms(w):
    return [a for a in w.client.get("/api/alarms").json() if a["kind"] == "door.unauthorised_person"]


def test_two_staff_crossing_raise_nothing(walk_env):
    w = walk_env
    assert face_in(w, 0x0101, ANA)[1] == Decision.GRANT
    assert face_in(w, 0x0102, BEN)[1] == Decision.GRANT
    assert send_crossing(w, Crossing(0x0100, 2, False, (0x0101, 0x0102))) == CrossingAck(0x0100, 0)
    assert unauthorised_alarms(w) == []


def test_a_refused_person_crossing_raises_a_p1_alarm(walk_env):
    w = walk_env
    face_in(w, 0x0101, ANA)
    assert face_in(w, 0x0102, STRANGER)[2] == Reason.NO_MATCH
    assert send_crossing(w, Crossing(0x0100, 2, False, (0x0101, 0x0102))) == CrossingAck(0x0100, 1)
    (al,) = unauthorised_alarms(w)
    assert al["priority"] == 1 and "unrecognised" in al["title"] and "Lab" in al["title"]
    ev = next(e for e in w.client.get("/api/events?kind=door.*").json() if e["kind"] == "door.unauthorised_person")
    assert "Ana" in ev["detail"]


def test_a_replayed_crossing_is_dropped(walk_env):
    w = walk_env
    face_in(w, 0x0101, ANA)
    f = w.panel.frame(MsgType.CROSSING, Crossing(0x0100, 2, False, (0x0101,)).encode())
    assert send_crossing(w, None, raw=f) == CrossingAck(0x0100, 1)
    assert send_crossing(w, None, raw=f) is None  # the replay window refuses it
    assert len(unauthorised_alarms(w)) == 1


def test_a_crossing_at_a_door_not_in_walk_through_mode_is_rejected(walk_env):
    w = walk_env
    assert w.client.patch("/api/doors/1", json={"credential_mode": "pin"}).status_code == 200
    assert send_crossing(w, Crossing(0x0100, 1, False, ())) is None
    assert any(e["kind"] == "link.rejected" for e in w.client.get("/api/events?kind=link.*").json())
    assert unauthorised_alarms(w) == []


# ---- keypads cannot run walk-through doors ----------------------------------------------------

def test_a_keypad_door_cannot_be_switched_to_walk_through(walk_env):
    w = walk_env
    assert w.client.patch("/api/doors/1", json={"credential_mode": "pin"}).status_code == 200
    w.store.x("INSERT INTO devices(serial, pubkey, first_seen, last_seen, door_id) VALUES(?, ?, ?, ?, ?)",
              ("LNT-0000000000A1", bytes(32), time.time(), time.time(), 1))
    # The keypad's core refuses walk-through mode in every heartbeat reply, so it would drop offline.
    r = w.client.patch("/api/doors/1", json={"credential_mode": "face_group"})
    assert r.status_code == 409 and "keypad" in r.json()["detail"]


def test_a_keypad_cannot_be_adopted_into_a_walk_through_door(walk_env):
    from lintel_server import adopt
    w = walk_env
    pk = bytes(range(32))
    w.store.x("INSERT INTO devices(serial, pubkey, first_seen, last_seen) VALUES(?, ?, ?, ?)",
              ("LNT-0000000000A2", pk, time.time(), time.time()))
    r = w.client.post("/api/devices/LNT-0000000000A2/adopt",
                      json={"pairing_code": adopt.pairing_code(pk), "door_id": 1})
    assert r.status_code == 409 and "keypad" in r.json()["detail"]
    assert w.store.q1("SELECT door_id FROM devices WHERE serial='LNT-0000000000A2'")["door_id"] is None


def test_the_alarm_event_carries_the_evidence_photo_when_it_is_published(walk_env):
    """The console's map shows the tailgater's photo from the event itself, so
    the evidence must be attached before the event goes out."""
    w = walk_env
    published = []
    w.ctl.publish = published.append
    w.ctl.on_face_evidence = lambda ev, jpeg, door, label: ev.__setitem__("photo", "evidence.jpg")
    face_in(w, 0x0101, ANA)
    face_in(w, 0x0102, STRANGER)
    send_crossing(w, Crossing(0x0100, 2, False, (0x0101, 0x0102)))
    ev = next(m["event"] for m in published if m["type"] == "event" and m["event"]["kind"] == "door.unauthorised_person")
    assert ev["photo"] == "evidence.jpg"
