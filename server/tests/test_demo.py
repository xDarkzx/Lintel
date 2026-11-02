"""The one-command demo: a seeded site and scripted traffic over the real protocol."""

import pytest
from fastapi.testclient import TestClient

from lintel_server import demo
from lintel_server.access import AccessEngine
from lintel_server.controller import Controller
from lintel_server.faces import FaceError
from lintel_server.store import Store
from lintel_server.web import Hub, create_app
from test_server import FakeTransport


def test_demo_faces_recognise_the_same_person_and_nobody_else():
    f = demo.DemoFaces()
    a1, a2 = f.analyse(demo.face_jpeg("Aroha Ngata")), f.analyse(demo.face_jpeg("Aroha Ngata"))
    b = f.analyse(demo.face_jpeg("Ben Carter"))
    assert float(a1.embedding @ a2.embedding) > 0.99 and float(a1.embedding @ b.embedding) < 0.5
    with pytest.raises(FaceError):
        f.analyse(demo.plain_jpeg())  # a frame with nobody in it


def test_seeding_builds_the_site_once(tmp_path):
    store = Store(tmp_path)
    demo.seed(store)
    demo.seed(store)  # a restart must not duplicate anything
    modes = {r["name"]: r["credential_mode"] for r in store.q("SELECT name, credential_mode FROM doors")}
    assert modes == {"Main Entrance": "pin", "Server Room": "pin", "Lab (Lintel Vision)": "face_group"}
    assert store.q1("SELECT COUNT(*) n FROM cardholders")["n"] == len(demo.PEOPLE)
    assert store.q1("SELECT COUNT(*) n FROM face_templates")["n"] == sum(1 for p in demo.PEOPLE if p.face)


@pytest.fixture
def site(tmp_path):
    store = Store(tmp_path)
    demo.seed(store)
    hub = Hub()
    ctl = Controller(store, AccessEngine(store), hub.publish)
    ctl.transport = FakeTransport()
    ctl.load_doors()
    client = TestClient(create_app(store, ctl, hub, 47800, faces=demo.DemoFaces()))
    client.headers["Authorization"] = f"Bearer {store.secrets.controller_token}"

    def deliver(frame):
        before = len(ctl.transport.sent)
        ctl.datagram(frame, ("127.0.0.1", 5000))
        return ctl.transport.sent[-1] if len(ctl.transport.sent) > before else None

    def post(path, body, headers):
        r = client.post(path, content=body, headers=headers)
        return r.status_code, r.json()

    return store, demo.Doors(store, deliver, post)


def kinds(store, prefix):
    return [r["kind"] for r in store.q("SELECT kind FROM events WHERE kind LIKE ? ORDER BY seq", (prefix + "%",))]


def alarm_kinds(store):
    return {r["kind"] for r in store.q("SELECT kind FROM alarms")}


def test_every_scenario_produces_what_it_shows(site):
    store, doors = site
    for scenario in demo.SCENARIOS:
        scenario(doors)
    assert "access.granted" in kinds(store, "access.")
    assert {"keypad.lockout", "duress", "door.unauthorised_person", "face.spoof"} <= alarm_kinds(store)
    names = [r["detail"] for r in store.q("SELECT detail FROM events WHERE kind='door.unauthorised_person'")]
    assert any("unrecognised" in d for d in names)


def test_doors_resume_their_counters_after_a_restart(site):
    store, doors = site
    doors.heartbeat_all()
    again = demo.Doors(store, doors.deliver, doors.post)  # a restarted demo
    again.heartbeat_all()
    assert not kinds(store, "link.rejected")  # no frame was refused as a replay


def test_the_showcase_plays_every_scenario_once_with_incidents_early():
    assert sorted(s.__name__ for s in demo.SHOWCASE) == sorted(s.__name__ for s in demo.SCENARIOS)
    first_incident = next(i for i, s in enumerate(demo.SHOWCASE) if s is demo.stranger_tailgates)
    assert first_incident <= 2  # a visitor sees the headline feature within the first few seconds


def test_the_showcase_runs_against_a_real_site(site):
    store, doors = site
    for scenario in demo.SHOWCASE:
        scenario(doors)
    assert {"keypad.lockout", "duress", "door.unauthorised_person", "face.spoof"} <= alarm_kinds(store)
