"""End to end: a simulated Lintel Vision unit, speaking the real protocol, at a walk-through door."""

import pytest

from lintel_server.protocol import Decision, Reason
from lintel_server.vision_sim import VisionUnit, depth_face_png, depth_flat_png
from test_enrolment import ANA, BEN, unit
from test_server import add
from test_walkthrough import STRANGER, enrol_face, walk_env  # noqa: F401  (fixture reuse)

CAT = unit(3)


@pytest.fixture
def sim(walk_env):
    w = walk_env

    def deliver(frame):
        before = len(w.ctl.transport.sent)
        w.ctl.datagram(frame, ("10.0.0.9", 5000))
        return w.ctl.transport.sent[-1] if len(w.ctl.transport.sent) > before else None

    def post(path, body, headers):
        r = w.client.post(path, content=body, headers=headers)
        return r.status_code, r.json()

    w.unit = VisionUnit(1, w.key, w.panel.net, deliver, post)
    w.unit.ctr = w.panel.ctr  # the fixture's panel shares this door's counter space
    return w


def alarms(w, kind="door.unauthorised_person"):
    return [a for a in w.client.get("/api/alarms").json() if a["kind"] == kind]


def granted_names(w):
    return sorted(e["cardholder_name"] for e in w.client.get("/api/events?kind=access.granted").json())


def test_three_staff_walk_through_and_each_is_logged(sim):
    cat = add(sim.client, sim.gid, "Cat", "4826")
    enrol_face(sim.store, cat["id"], CAT)
    u = sim.unit
    u.start_passage()
    first = u.present(1, sim.faces.frame(emb=ANA), depth_face_png())
    assert first.decision == Decision.GRANT and first.name == "Ana" and first.unlock_ms > 0  # the door opens now
    assert u.present(2, sim.faces.frame(emb=BEN), depth_face_png()).decision == Decision.GRANT
    assert u.present(3, sim.faces.frame(emb=CAT), depth_face_png()).decision == Decision.GRANT
    assert u.crossed(3, [1, 2, 3]).unauthorised == 0
    assert granted_names(sim) == ["Ana Test", "Ben Test", "Cat Test"]
    assert alarms(sim) == []


def test_a_stranger_behind_two_staff_raises_the_alarm(sim):
    u = sim.unit
    u.start_passage()
    u.present(1, sim.faces.frame(emb=ANA), depth_face_png())
    u.present(2, sim.faces.frame(emb=BEN), depth_face_png())
    assert u.present(3, sim.faces.frame(emb=STRANGER), depth_face_png()).reason == Reason.NO_MATCH
    assert u.crossed(3, [1, 2, 3]).unauthorised == 1
    (al,) = alarms(sim)
    assert al["priority"] == 1 and al["title"] == "Unauthorised person at Lab: unrecognised"
    ev = next(e for e in sim.client.get("/api/events?kind=door.unauthorised_person").json())
    assert "Ana Test, Ben Test" in ev["detail"]


def test_staff_without_access_following_is_named(sim):
    cat = add(sim.client, sim.gid, "Cat", "4826", groups=[])  # enrolled, but no access to this door
    enrol_face(sim.store, cat["id"], CAT)
    u = sim.unit
    u.start_passage()
    u.present(1, sim.faces.frame(emb=ANA), depth_face_png())
    assert u.present(2, sim.faces.frame(emb=CAT), depth_face_png()).reason == Reason.DOOR_NOT_ALLOWED
    assert u.crossed(2, [1, 2]).unauthorised == 1
    (al,) = alarms(sim)
    assert al["title"] == "Unauthorised person at Lab: Cat Test"


def test_overhead_counts_a_person_hidden_from_the_front_camera(sim):
    u = sim.unit
    u.start_passage()
    u.present(1, sim.faces.frame(emb=ANA), depth_face_png())
    assert u.crossed(2, [1], overhead=True).unauthorised == 1
    (al,) = alarms(sim)
    assert al["title"].endswith(": unrecognised")


def test_a_photo_held_up_opens_nothing(sim):
    u = sim.unit
    u.start_passage()
    r = u.present(1, sim.faces.frame(emb=ANA), depth_flat_png())  # Ana's photo, not Ana
    assert r.decision == Decision.DENY and r.reason == Reason.NO_FACE
    assert [a["priority"] for a in alarms(sim, "face.spoof")] == [2]
    assert granted_names(sim) == []


def test_pin_fallback_opens_for_someone_not_recognised(sim):
    r = sim.unit.pin("2468")
    assert r.decision == Decision.GRANT and r.name == "Ana"


def test_a_unit_that_restarted_mid_passage_still_reports_people(sim):
    u = sim.unit
    u.start_passage()
    u.present(1, sim.faces.frame(emb=ANA), depth_face_png())
    u.start_passage()  # after a restart the unit is on a passage the server never saw decisions for
    assert u.crossed(1, [1]).unauthorised == 1
