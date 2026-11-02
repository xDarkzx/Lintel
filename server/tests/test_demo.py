"""The one-command demo: a seeded site and scripted traffic over the real protocol."""

from pathlib import Path

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


PLANS = Path(__file__).resolve().parents[2] / "docs" / "demo" / "floor-plans"


def test_seeding_builds_the_site_once(tmp_path):
    store = Store(tmp_path)
    demo.seed(store, PLANS)
    demo.seed(store, PLANS)  # a restart must not duplicate anything
    modes = {r["name"]: r["credential_mode"] for r in store.q("SELECT name, credential_mode FROM doors")}
    assert modes == {d.name: d.mode for d in demo.DOORS} and modes["Lab (Lintel Vision)"] == "face_group"
    assert store.q1("SELECT COUNT(*) n FROM cardholders")["n"] == len(demo.PEOPLE)
    assert store.q1("SELECT COUNT(*) n FROM face_templates")["n"] == sum(1 for p in demo.PEOPLE if p.face)
    floors = store.q("SELECT id, plan FROM floors ORDER BY level")
    assert len(floors) == 2 and all((tmp_path / "plans" / f["plan"]).exists() for f in floors)
    assert store.q1("SELECT COUNT(*) n FROM doors WHERE floor_id IS NULL")["n"] == 0  # every door is on a map


def test_seeding_without_plans_still_builds_the_doors(tmp_path):
    store = Store(tmp_path)
    demo.seed(store, None)
    assert store.q1("SELECT COUNT(*) n FROM doors")["n"] == len(demo.DOORS)
    assert store.q1("SELECT COUNT(*) n FROM floors")["n"] == 0


@pytest.fixture
def site(tmp_path):
    store = Store(tmp_path)
    demo.seed(store, PLANS)
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
    # Keypad entries at the front door carry the photo the keypad took.
    main = store.q1("SELECT id FROM doors WHERE name='Main Entrance'")["id"]
    assert store.q1("SELECT COUNT(*) n FROM events WHERE door_id=? AND kind='access.granted' AND photo IS NOT NULL",
                    (main,))["n"] >= 1


def test_doors_resume_their_counters_after_a_restart(site):
    store, doors = site
    doors.heartbeat_all()
    again = demo.Doors(store, doors.deliver, doors.post)  # a restarted demo
    again.heartbeat_all()
    assert not kinds(store, "link.rejected")  # no frame was refused as a replay


def test_the_showcase_plays_every_scenario_in_time_order():
    times = [t for t, _ in demo.SHOWCASE]
    assert times == sorted(times)
    assert {s.__name__ for _, s in demo.SHOWCASE} >= {s.__name__ for s in demo.SCENARIOS}


def test_the_showcase_runs_against_a_real_site(site):
    store, doors = site
    for _, scenario in demo.SHOWCASE:
        scenario(doors)
    assert {"keypad.lockout", "duress", "door.unauthorised_person", "face.spoof"} <= alarm_kinds(store)


def test_keypad_doors_have_adopted_keypads_that_report_diagnostics(site):
    store, doors = site
    keypads = {r["door_id"] for r in store.q("SELECT door_id FROM devices WHERE door_id IS NOT NULL")}
    assert keypads == {d.id for d in demo.DOORS if d.mode != "face_group"}  # walk-through doors take no keypad
    doors.diag_all()
    assert all(r["diag"] for r in store.q("SELECT diag FROM doors WHERE credential_mode != 'face_group'"))
    assert not kinds(store, "link.rejected")
