"""Tailgating detection: the counting rule, the signed frame endpoint, and
the alarm with its evidence photo."""

import hashlib
import hmac
import io
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from lintel_server import tailgate
from lintel_server.access import AccessEngine
from lintel_server.controller import Controller, photo_key
from lintel_server.protocol import Decision
from lintel_server.store import Store
from lintel_server.tailgate import Frame, Person, assess
from lintel_server.web import Hub, create_app
from test_server import FakeTransport, Panel, add, resp

H = 1080


def person(h_frac=0.8, score=0.9, x=100.0):
    return Person(x, 50.0, 300.0, h_frac * H, score)


def frames(*counts, **kw):
    return [Frame(i, i * 350, [person(x=100.0 + 400 * k, **kw) for k in range(c)], H) for i, c in enumerate(counts)]


# ---- the counting rule ------------------------------------------------------------

def test_one_person_on_one_credential_is_a_passage():
    a = assess(frames(1, 1, 1, 0, 0), allowed=1)
    assert not a.tailgating and a.max_people == 1 and a.frames_over == 0


def test_two_people_together_in_two_frames_is_tailgating():
    a = assess(frames(1, 2, 2, 1, 0), allowed=1)
    assert a.tailgating and a.max_people == 2 and a.frames_over == 2 and a.worst == 1


def test_a_single_frame_with_an_extra_person_is_not_enough():
    assert not assess(frames(1, 2, 1, 1), allowed=1).tailgating


def test_two_credentials_cover_two_people():
    assert not assess(frames(2, 2, 2), allowed=2).tailgating
    assert assess(frames(3, 3), allowed=2).tailgating


def test_people_far_from_the_door_and_weak_detections_do_not_count():
    far = assess(frames(2, 2, 2, h_frac=0.2), allowed=1)
    weak = assess(frames(2, 2, 2, score=0.3), allowed=1)
    assert far.max_people == 0 and not far.tailgating
    assert weak.max_people == 0 and not weak.tailgating


def test_no_frames_is_not_an_alarm():
    a = assess([], allowed=1)
    assert not a.tailgating and a.max_people == 0


# ---- the endpoint ---------------------------------------------------------------------

def jpeg_frame(i):
    buf = io.BytesIO()
    Image.new("RGB", (64, 48), (i * 9 % 256, 80, 120)).save(buf, "JPEG")
    return buf.getvalue()


class FakeDetector:
    """Stands in for YOLOX: people per frame, looked up by the frame's bytes."""

    def __init__(self):
        self.by_hash = {}
        self.calls = 0

    def plan(self, counts):
        out = []
        for i, c in enumerate(counts):
            jpg = jpeg_frame(i)
            self.by_hash[hashlib.sha256(jpg).digest()] = [Person(5.0 + 20 * k, 2.0, 15.0, 40.0, 0.9) for k in range(c)]
            out.append(jpg)
        return out

    def detect(self, jpeg):
        self.calls += 1
        return self.by_hash[hashlib.sha256(jpeg).digest()], 48


@pytest.fixture
def tg(tmp_path):
    store = Store(tmp_path)
    hub = Hub()
    ctl = Controller(store, AccessEngine(store), hub.publish)
    ctl.transport = FakeTransport()
    det = FakeDetector()
    client = TestClient(create_app(store, ctl, hub, 47800, people=det))
    client.headers["Authorization"] = f"Bearer {store.secrets.controller_token}"
    pw = (tmp_path / "initial_admin.txt").read_text().split("password: ")[1].strip()
    assert client.post("/api/login", json={"username": "admin", "password": pw}).status_code == 200
    door = client.post("/api/doors", json={"id": 1, "name": "Main Entrance"}).json()
    always = next(s["id"] for s in client.get("/api/schedules").json() if s["name"] == "24/7")
    gid = client.post("/api/groups", json={"name": "Staff", "schedule_id": always, "doors": [1]}).json()["id"]
    panel = Panel(ctl, 1, bytes.fromhex(door["key"]), int(door["net_id"], 16))
    add(client, gid, "Ana", "2468")
    return store, client, panel, det


def grant(panel):
    assert resp(panel.pin("2468"))[1] == Decision.GRANT
    return panel.ctr


def send(client, panel, req, index, total, ms, jpg, mac=None):
    mac = mac or hmac.new(photo_key(panel.key), f"watch:1:{req}:{index}:{total}:{ms}:".encode()
                          + hashlib.sha256(jpg).digest(), hashlib.sha256).hexdigest()
    return client.post("/api/door/1/watch", content=jpg,
                       headers={"x-lintel-req": str(req), "x-lintel-frame": f"{index}/{total}",
                                "x-lintel-ms": str(ms), "x-lintel-mac": mac})


def wait_event(client, kind, timeout=5.0, photo=False):
    """The event is journalled first and its evidence photo attached just
    after, so a caller wanting the photo waits for that too."""
    end = time.time() + timeout
    while time.time() < end:
        got = client.get(f"/api/events?kind={kind}").json()
        if got and (got[0]["photo"] or not photo):
            return got[0]
        time.sleep(0.05)
    raise AssertionError(f"no {kind} event")


def test_one_person_is_journalled_as_a_passage_with_frame_hashes(tg):
    store, client, panel, det = tg
    req = grant(panel)
    jpgs = det.plan([1, 1, 1, 0])
    for i, j in enumerate(jpgs):
        assert send(client, panel, req, i, len(jpgs), i * 350, j).json()["analysed"] is True
    ev = wait_event(client, "door.passage")
    assert "1 person" in ev["detail"] and "1 credential" in ev["detail"]
    chain = hashlib.sha256(b"".join(hashlib.sha256(j).digest() for j in jpgs)).hexdigest()
    assert f"frames sha256={chain}" in ev["detail"]
    assert client.get("/api/alarms").json() == []
    assert store.verify_journal()["ok"]


def test_tailgating_raises_an_alarm_with_an_evidence_photo(tg):
    store, client, panel, det = tg
    req = grant(panel)
    jpgs = det.plan([1, 2, 2, 1])
    for i, j in enumerate(jpgs):
        assert send(client, panel, req, i, len(jpgs), i * 350, j).status_code == 200
    ev = wait_event(client, "door.tailgating", photo=True)
    assert "2 people" in ev["detail"] and ev["photo"]
    assert client.get(f"/api/photos/{ev['seq']}.jpg").status_code == 200
    alarm = next(a for a in client.get("/api/alarms").json() if a["kind"] == "door.tailgating")
    assert alarm["priority"] == 2 and "2 people on 1 credential" in alarm["title"]


def test_frames_are_signed_ordered_and_bound_to_a_grant(tg):
    store, client, panel, det = tg
    req = grant(panel)
    jpgs = det.plan([1, 1])
    # Wrong signature, or a frame moved to another index or time: refused.
    assert send(client, panel, req, 0, 2, 0, jpgs[0], mac="00" * 32).status_code == 403
    good = hmac.new(photo_key(panel.key), f"watch:1:{req}:0:2:0:".encode() + hashlib.sha256(jpgs[0]).digest(),
                    hashlib.sha256).hexdigest()
    assert send(client, panel, req, 1, 2, 0, jpgs[0], mac=good).status_code == 403
    assert send(client, panel, req, 0, 2, 350, jpgs[0], mac=good).status_code == 403
    # Out of range, or not following a grant: refused.
    assert send(client, panel, req, 2, 2, 0, jpgs[0]).status_code == 400
    assert send(client, panel, req, 0, 99, 0, jpgs[0]).status_code == 400
    assert send(client, panel, req + 50, 0, 2, 0, jpgs[0]).status_code == 409
    # Accepted once only.
    assert send(client, panel, req, 0, 2, 0, jpgs[0]).status_code == 200
    assert send(client, panel, req, 0, 2, 0, jpgs[0]).status_code == 409


def test_frames_after_a_denial_are_refused(tg):
    store, client, panel, det = tg
    assert resp(panel.pin("1357"))[1] == Decision.DENY
    jpgs = det.plan([2])
    assert send(client, panel, panel.ctr, 0, 1, 0, jpgs[0]).status_code == 409


def test_missing_frames_are_analysed_after_the_timeout(tg, monkeypatch):
    store, client, panel, det = tg
    monkeypatch.setattr(tailgate, "SESSION_TIMEOUT_S", 0.2)
    req = grant(panel)
    jpgs = det.plan([1, 1, 1])
    send(client, panel, req, 0, 3, 0, jpgs[0])
    send(client, panel, req, 2, 3, 700, jpgs[2])
    ev = wait_event(client, "door.passage")
    assert "2 frames analysed, 1 missing" in ev["detail"]


def test_detection_can_be_turned_off(tg):
    store, client, panel, det = tg
    assert client.get("/api/settings").json()["tailgate_detection"] is True
    assert client.patch("/api/settings", json={"tailgate_detection": False}).status_code == 200
    req = grant(panel)
    jpgs = det.plan([2])
    r = send(client, panel, req, 0, 1, 0, jpgs[0]).json()
    assert r["analysed"] is False and det.calls == 0


def test_without_the_person_model_frames_are_refused_not_ignored(tmp_path):
    store = Store(tmp_path)
    hub = Hub()
    ctl = Controller(store, AccessEngine(store), hub.publish)
    ctl.transport = FakeTransport()
    client = TestClient(create_app(store, ctl, hub, 47800))
    client.headers["Authorization"] = f"Bearer {store.secrets.controller_token}"
    pw = (tmp_path / "initial_admin.txt").read_text().split("password: ")[1].strip()
    client.post("/api/login", json={"username": "admin", "password": pw})
    door = client.post("/api/doors", json={"id": 1, "name": "Main Entrance"}).json()
    always = next(s["id"] for s in client.get("/api/schedules").json() if s["name"] == "24/7")
    gid = client.post("/api/groups", json={"name": "Staff", "schedule_id": always, "doors": [1]}).json()["id"]
    add(client, gid, "Ana", "2468")
    panel = Panel(ctl, 1, bytes.fromhex(door["key"]), int(door["net_id"], 16))
    req = grant(panel)
    assert client.get("/api/settings").json()["tailgate_available"] is False
    assert send(client, panel, req, 0, 1, 0, jpeg_frame(0)).status_code == 503


# ---- the real detector, where its model is installed ----------------------------------------

MODELS = Path(__file__).resolve().parents[1] / "models"


@pytest.mark.skipif(not (MODELS / tailgate.PERSON_MODEL).exists(), reason="person model not downloaded")
def test_real_detector_finds_no_people_in_an_empty_frame():
    det = tailgate.PersonDetector(MODELS)
    people, height = det.detect(jpeg_frame(3))
    assert people == [] and height == 48
