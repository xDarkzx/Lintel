"""Guided face enrolment with liveness, and the identity check on PIN entries."""

import hashlib
import hmac
import io
import time

import numpy as np
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from lintel_server import liveness
from lintel_server.access import AccessEngine
from lintel_server.controller import Controller, photo_key
from lintel_server.faces import FaceEngine, FaceError, FaceResult
from lintel_server.protocol import Decision
from lintel_server.store import Store
from lintel_server.web import Hub, create_app
from test_server import FakeTransport, Panel, add, resp


def unit(seed):
    v = np.random.default_rng(seed).normal(size=128).astype(np.float32)
    return v / np.linalg.norm(v)


ANA, BEN = unit(1), unit(2)
YAW = {"front": 0.0, "left": 0.4, "right": -0.4}


def landmarks(yaw):
    # Eyes 100 px apart at y=100; the nose sits `yaw` eye-widths off their midpoint.
    return np.array([[150, 100], [250, 100], [200 + 100 * yaw, 150], [160, 200], [240, 200]], np.float32)


def test_yaw_sign_follows_the_persons_own_left():
    assert liveness.yaw_ratio(landmarks(0.0)) == pytest.approx(0.0)
    assert liveness.step_met("left", liveness.yaw_ratio(landmarks(0.4)))
    assert liveness.step_met("right", liveness.yaw_ratio(landmarks(-0.4)))
    assert not liveness.step_met("front", liveness.yaw_ratio(landmarks(0.3)))


class FakeFaces:
    """FaceEngine stand-in: each frame's bytes decide what is 'seen'."""

    best_match = staticmethod(FaceEngine.best_match)

    def __init__(self):
        self.seen = {}

    def frame(self, pose="front", emb=ANA, error=None, detect=0.95):
        img = np.random.default_rng(len(self.seen)).integers(0, 256, (240, 320, 3), dtype=np.uint8)
        buf = io.BytesIO()
        Image.fromarray(img).save(buf, "JPEG", quality=95)
        jpg = buf.getvalue()
        self.seen[hashlib.sha256(jpg).digest()] = (pose, emb, error, detect)
        return jpg

    def analyse(self, jpeg):
        pose, emb, error, detect = self.seen[hashlib.sha256(jpeg).digest()]
        if error:
            raise FaceError(error)
        return FaceResult(emb, (60, 40, 160, 160), detect, landmarks(YAW[pose]))


class FakeLive:
    def __init__(self, real=0.97):
        self.real = real

    def score(self, img, box):
        return self.real


@pytest.fixture
def en(tmp_path):
    store = Store(tmp_path)
    hub = Hub()
    ctl = Controller(store, AccessEngine(store), hub.publish)
    ctl.transport = FakeTransport()
    faces, live = FakeFaces(), FakeLive()
    client = TestClient(create_app(store, ctl, hub, 47800, faces=faces, live=live))
    client.headers["Authorization"] = f"Bearer {store.secrets.controller_token}"
    pw = (tmp_path / "initial_admin.txt").read_text().split("password: ")[1].strip()
    assert client.post("/api/login", json={"username": "admin", "password": pw}).status_code == 200
    door = client.post("/api/doors", json={"id": 1, "name": "Main Entrance"}).json()
    always = next(s["id"] for s in client.get("/api/schedules").json() if s["name"] == "24/7")
    gid = client.post("/api/groups", json={"name": "Staff", "schedule_id": always, "doors": [1]}).json()["id"]
    panel = Panel(ctl, 1, bytes.fromhex(door["key"]), int(door["net_id"], 16))
    add(client, gid, "Ana", "2468")
    add(client, gid, "Zed", "1593")
    ana = next(c["id"] for c in client.get("/api/cardholders").json() if c["first_name"] == "Ana")
    return store, client, panel, faces, live, ana


def frame(client, sid, jpg):
    r = client.post(f"/api/faces/enrolment/{sid}/frame", content=jpg)
    assert r.status_code == 200, r.text
    return r.json()


def run_steps(client, faces, sid, steps, emb=ANA):
    out = None
    for step in steps:
        for _ in range(liveness.STEP_FRAMES):
            out = frame(client, sid, faces.frame(step, emb))
    return out


def test_live_person_following_the_steps_is_enrolled(en):
    store, client, panel, faces, live, ana = en
    s = client.post(f"/api/cardholders/{ana}/faces/enrolment").json()
    assert s["steps"][0] == "front" and s["steps"][-1] == "front" and set(s["steps"][1:3]) == {"left", "right"}
    assert s["instruction"] == "Look straight at the camera"
    out = run_steps(client, faces, s["id"], s["steps"])
    assert out["state"] == "saved"
    assert store.q1("SELECT COUNT(*) n FROM face_templates WHERE cardholder_id=? AND source='live enrolment'",
                    (ana,))["n"] >= 2
    ev = client.get("/api/events?kind=cardholder.face_enrolled").json()[0]
    assert "guided enrolment with liveness" in ev["detail"] and "lowest live score 0.97" in ev["detail"]


def test_steps_must_be_followed_in_the_order_given(en):
    store, client, panel, faces, live, ana = en
    s = client.post(f"/api/cardholders/{ana}/faces/enrolment").json()
    wrong = "right" if s["steps"][1] == "left" else "left"
    run_steps(client, faces, s["id"], ["front"])
    out = run_steps(client, faces, s["id"], [wrong, wrong])
    assert out["state"] == "active" and out["step"] == 1


def test_a_photo_or_screen_fails_the_liveness_check(en):
    store, client, panel, faces, live, ana = en
    live.real = 0.2
    s = client.post(f"/api/cardholders/{ana}/faces/enrolment").json()
    out = None
    for _ in range(liveness.SPOOF_FRAMES_FAIL):
        out = frame(client, s["id"], faces.frame("front"))
    assert out["state"] == "failed" and "photo or a screen" in out["message"]
    assert store.q1("SELECT COUNT(*) n FROM face_templates")["n"] == 0
    assert client.get("/api/events?kind=cardholder.face_enrol_failed").json()


def test_swapping_faces_mid_enrolment_fails(en):
    store, client, panel, faces, live, ana = en
    s = client.post(f"/api/cardholders/{ana}/faces/enrolment").json()
    run_steps(client, faces, s["id"], ["front"])
    out = None
    for _ in range(liveness.MISMATCH_FAIL):
        out = frame(client, s["id"], faces.frame(s["steps"][1], BEN))
    assert out["state"] == "failed" and "different face" in out["message"]


def test_frame_problems_give_guidance_not_failure(en):
    store, client, panel, faces, live, ana = en
    s = client.post(f"/api/cardholders/{ana}/faces/enrolment").json()
    assert frame(client, s["id"], faces.frame(error="no face found"))["message"].startswith("Move into the frame")
    out = frame(client, s["id"], faces.frame(error="more than one face in view"))
    assert out["state"] == "active" and "one person" in out["message"]


def test_a_face_already_enrolled_for_someone_else_is_refused(en):
    store, client, panel, faces, live, ana = en
    other = next(c["id"] for c in client.get("/api/cardholders").json() if c["first_name"] == "Zed")
    store.x("INSERT INTO face_templates(cardholder_id, embedding, source, created) VALUES(?, ?, 'upload', ?)",
            (other, store.seal_template(other, ANA.tobytes()), time.time()))
    s = client.post(f"/api/cardholders/{ana}/faces/enrolment").json()
    out = run_steps(client, faces, s["id"], s["steps"])
    assert out["state"] == "failed" and "another cardholder" in out["message"]


def test_sessions_belong_to_the_admin_who_started_them(en, tmp_path):
    store, client, panel, faces, live, ana = en
    s = client.post(f"/api/cardholders/{ana}/faces/enrolment").json()
    client.post("/api/operators", json={"username": "second", "password": "second-admin-pw1", "role": "admin"})
    other = TestClient(client.app)
    other.post("/api/login", json={"username": "second", "password": "second-admin-pw1"})
    assert other.post(f"/api/faces/enrolment/{s['id']}/frame", content=faces.frame()).status_code == 404


def test_without_the_liveness_models_enrolment_is_unavailable(tmp_path):
    store = Store(tmp_path)
    hub = Hub()
    ctl = Controller(store, AccessEngine(store), hub.publish)
    client = TestClient(create_app(store, ctl, hub, 47800, faces=FakeFaces()))
    pw = (tmp_path / "initial_admin.txt").read_text().split("password: ")[1].strip()
    client.post("/api/login", json={"username": "admin", "password": pw})
    cid = client.post("/api/cardholders", json={"first_name": "Ana"}).json()["id"]
    assert client.post(f"/api/cardholders/{cid}/faces/enrolment").status_code == 503


def test_doors_can_be_set_to_face_modes(en):
    store, client, panel, faces, live, ana = en
    assert client.patch("/api/doors/1", json={"credential_mode": "face_and_pin"}).status_code == 200
    assert client.get("/api/doors/1").json()["credential_mode"] == "face_and_pin"


# ---- identity check on PIN entries -------------------------------------------------------

def pin_photo(client, panel, jpg):
    mac = hmac.new(photo_key(panel.key), f"1:{panel.ctr}:".encode() + hashlib.sha256(jpg).digest(),
                   hashlib.sha256).hexdigest()
    r = client.post("/api/door/1/photo", content=jpg, headers={"x-lintel-req": str(panel.ctr), "x-lintel-mac": mac})
    assert r.status_code == 200, r.text


def wait_alarm(client, kind, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        hit = [a for a in client.get("/api/alarms").json() if a["kind"] == kind]
        if hit:
            return hit[0]
        time.sleep(0.05)
    return None


def enrol_template(store, cid, emb):
    store.x("INSERT INTO face_templates(cardholder_id, embedding, source, created) VALUES(?, ?, 'live enrolment', ?)",
            (cid, store.seal_template(cid, emb.tobytes()), time.time()))


def test_someone_else_using_a_pin_raises_an_alarm(en):
    store, client, panel, faces, live, ana = en
    enrol_template(store, ana, ANA)
    assert resp(panel.pin("2468"))[1] == Decision.GRANT
    pin_photo(client, panel, faces.frame("front", BEN))
    alarm = wait_alarm(client, "access.face_mismatch")
    assert alarm and alarm["priority"] == 3 and "Ana Test's PIN used by someone else" in alarm["title"]


def test_the_owner_or_an_unclear_photo_raises_nothing(en):
    store, client, panel, faces, live, ana = en
    enrol_template(store, ana, ANA)
    for jpg in (faces.frame("front", ANA), faces.frame(error="no face found"), faces.frame("front", BEN, detect=0.6)):
        assert resp(panel.pin("2468"))[1] == Decision.GRANT
        pin_photo(client, panel, jpg)
    assert wait_alarm(client, "access.face_mismatch", timeout=0.5) is None


def test_without_an_enrolled_face_there_is_nothing_to_compare(en):
    store, client, panel, faces, live, ana = en
    assert resp(panel.pin("2468"))[1] == Decision.GRANT
    pin_photo(client, panel, faces.frame("front", BEN))
    assert wait_alarm(client, "access.face_mismatch", timeout=0.5) is None


# ---- face + PIN at the keypad ------------------------------------------------------------

def cred_frame(panel, pin, face_ref):
    from lintel_server.protocol import CRED_FACE, CRED_PIN, MsgType, PIN_MAX, UID_MAX
    import struct
    p = bytes([CRED_PIN | CRED_FACE, 0]) + bytes(UID_MAX) + bytes([len(pin)]) + pin.encode().ljust(PIN_MAX, b"\x00")
    return panel.frame(MsgType.CRED_REQ, p + struct.pack("<I", face_ref))


def face_upload(client, panel, ref, jpg):
    mac = hmac.new(photo_key(panel.key), f"face:1:{ref}:".encode() + hashlib.sha256(jpg).digest(),
                   hashlib.sha256).hexdigest()
    return client.post("/api/door/1/face", content=jpg, headers={"x-lintel-req": str(ref), "x-lintel-mac": mac})


def decide(ctl, panel, frame):
    from lintel_server.protocol import open_frame
    ctl.datagram(frame, ("10.0.0.5", 5000))
    return resp(open_frame(panel.key, panel.net, ctl.transport.sent[-1])[1])


def test_face_and_pin_door_needs_the_pin_owners_face(en):
    store, client, panel, faces, live, ana = en
    ctl = panel.ctl
    enrol_template(store, ana, ANA)
    assert client.patch("/api/doors/1", json={"credential_mode": "face_and_pin"}).status_code == 200
    # The owner's face with the owner's PIN opens the door.
    assert face_upload(client, panel, 11, faces.frame("front", ANA)).json()["face"] is True
    assert decide(ctl, panel, cred_frame(panel, "2468", 11))[1] == Decision.GRANT
    # The right PIN with someone else's face does not.
    face_upload(client, panel, 12, faces.frame("front", BEN))
    assert decide(ctl, panel, cred_frame(panel, "2468", 12))[1] == Decision.DENY
    # Nor does a PIN alone, or a face reference with no signed image behind it.
    assert resp(panel.pin("2468"))[1] == Decision.DENY
    assert decide(ctl, panel, cred_frame(panel, "2468", 99))[1] == Decision.DENY


def test_a_bare_pin_respects_the_doors_mode(en):
    store, client, panel, faces, live, ana = en
    for mode, want in (("card", Decision.DENY), ("card_and_pin", Decision.DENY), ("face", Decision.DENY),
                       ("card_or_pin", Decision.GRANT), ("pin", Decision.GRANT)):
        assert client.patch("/api/doors/1", json={"credential_mode": mode}).status_code == 200
        assert resp(panel.pin("2468"))[1] == want, mode


def test_face_refusals_say_exactly_why(en):
    from lintel_server.protocol import Reason
    store, client, panel, faces, live, ana = en
    ctl = panel.ctl
    client.patch("/api/doors/1", json={"credential_mode": "face_and_pin"})

    # No face enrolled for the PIN's owner: said plainly, owner named, and not
    # counted as guessing however often it happens.
    for ref in (21, 22, 23, 24):
        face_upload(client, panel, ref, faces.frame("front", ANA))
        r = decide(ctl, panel, cred_frame(panel, "2468", ref))
        assert (r[1], r[2]) == (Decision.DENY, Reason.FACE_NOT_ENROLLED)
    ev = client.get("/api/events?kind=access.denied").json()[0]
    assert ev["detail"] == "Ana Test at Main Entrance: no face enrolled for this person (face + PIN)"
    assert "-1.00" not in ev["detail"]

    # No face in the camera image.
    enrol_template(store, ana, ANA)
    face_upload(client, panel, 31, faces.frame(error="no face found"))
    assert decide(ctl, panel, cred_frame(panel, "2468", 31))[2] == Reason.NO_FACE

    # A face that matches nobody, and one that belongs to someone else.
    face_upload(client, panel, 32, faces.frame("front", BEN))
    assert decide(ctl, panel, cred_frame(panel, "2468", 32))[2] == Reason.NO_MATCH
    zed = next(c["id"] for c in client.get("/api/cardholders").json() if c["first_name"] == "Zed")
    enrol_template(store, zed, BEN)
    face_upload(client, panel, 33, faces.frame("front", BEN))
    assert decide(ctl, panel, cred_frame(panel, "2468", 33))[2] == Reason.MISMATCH
