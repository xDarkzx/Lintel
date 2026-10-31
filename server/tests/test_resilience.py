"""Hardening regressions: limits that must hold, memory that must stay
bounded, and races that must not break the rules. Each test fails if the
protection it covers is removed."""

import gc
import hashlib
import hmac
import io
import threading
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from starlette.websockets import WebSocketDisconnect

from lintel_server import controller as controller_mod
from lintel_server import liveness, notify, security, web
from lintel_server.controller import photo_key
from lintel_server.protocol import Decision
from lintel_server.security import LoginThrottle
from test_enrolment import en, run_steps  # noqa: F401  (fixture reuse)
from test_hardening import fake_dns
from test_server import add, env, resp  # noqa: F401
from test_tailgate import send as send_frame, tg  # noqa: F401


def admin_password(store):
    return (store.data_dir / "initial_admin.txt").read_text().split("password: ")[1].strip()


# ---- limits ------------------------------------------------------------------------------------

def test_oversized_bodies_are_refused_before_they_are_read(env):
    store, ctl, client, panel, gid = env
    big = b"\0" * (security.MAX_BODY_BYTES + 1)
    r = client.put("/api/floors/1/plan", content=big)
    assert r.status_code == 413

    def chunks():  # no Content-Length: the limit must hold while streaming too
        for _ in range(security.MAX_BODY_BYTES // 1_000_000 + 2):
            yield b"\0" * 1_000_000
    assert client.post("/api/cardholders/import", content=chunks()).status_code == 413
    assert client.get("/api/me").status_code == 200  # the server is unaffected


def test_api_responses_are_never_cached_or_embedded_elsewhere(env):
    store, ctl, client, panel, gid = env
    r = client.get("/api/me")
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["cross-origin-resource-policy"] == "same-origin"
    assert "camera=(self)" in r.headers["permissions-policy"] and "microphone=()" in r.headers["permissions-policy"]


def test_the_live_feed_ends_when_the_session_does(env, monkeypatch):
    store, ctl, client, panel, gid = env
    monkeypatch.setattr(web, "WS_RECHECK_S", 0.2)
    with client.websocket_connect("/ws") as ws:
        client.post("/api/logout")
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
        assert closed.value.code == 4401


def test_the_live_feed_does_not_keep_an_idle_session_alive(env, monkeypatch):
    store, ctl, client, panel, gid = env
    monkeypatch.setattr(web, "WS_RECHECK_S", 0.2)
    with client.websocket_connect("/ws"):
        time.sleep(0.1)  # opening the feed is activity; the re-checks after it are not
        before = store.q1("SELECT last_seen FROM sessions")["last_seen"]
        time.sleep(0.7)  # several re-checks
        assert store.q1("SELECT last_seen FROM sessions")["last_seen"] == before


@pytest.mark.parametrize("addresses", [["127.0.0.1"], ["10.1.2.3"], ["192.168.87.1"], ["169.254.169.254"],
                                       ["::1"], ["fd00::1"], ["93.184.216.34", "10.0.0.9"]])
def test_the_webhook_cannot_be_aimed_at_internal_addresses(env, monkeypatch, addresses):
    store, ctl, client, panel, gid = env
    fake_dns(monkeypatch, {"hooks.example": addresses})
    r = client.put("/api/settings/webhook", json={"url": "https://hooks.example/a"})
    assert r.status_code == 400 and "private or local" in r.json()["detail"]
    monkeypatch.setenv("LINTEL_WEBHOOK_ALLOW_PRIVATE", "1")  # a gateway on the site network, explicitly allowed
    assert client.put("/api/settings/webhook", json={"url": "https://hooks.example/a"}).status_code == 200


def test_the_webhook_rechecks_dns_at_send_time_and_refuses_redirects(env, monkeypatch):
    store, ctl, client, panel, gid = env
    store.set_setting("alarm_webhook", "https://hooks.example/a")
    fake_dns(monkeypatch, {"hooks.example": ["127.0.0.1"]})  # DNS changed after the URL was saved
    ok, why = notify.send(store, {"priority": 1, "title": "t"}, force=True)
    assert not ok and "private or local" in why

    fake_dns(monkeypatch, {"hooks.example": ["93.184.216.34"]})
    connected = []

    class FakeConn:
        def __init__(self, host, address, port, timeout):
            connected.append(address)

        def request(self, *a, **kw):
            pass

        def getresponse(self):
            return type("R", (), {"status": 302})()

        def close(self):
            pass
    monkeypatch.setattr(notify, "_PinnedHTTPS", FakeConn)
    ok, why = notify.send(store, {"priority": 1, "title": "t"}, force=True)
    assert not ok and "redirects are not followed" in why
    assert connected == ["93.184.216.34"]  # the vetted address, not a fresh lookup


def signed_face(client, panel, ref, body):
    mac = hmac.new(photo_key(panel.key), f"face:1:{ref}:".encode() + hashlib.sha256(body).digest(),
                   hashlib.sha256).hexdigest()
    return client.post("/api/door/1/face", content=body, headers={"x-lintel-req": str(ref), "x-lintel-mac": mac})


def test_keypad_face_images_are_size_and_bomb_checked(en):
    store, client, panel, faces, live, ana = en
    assert signed_face(client, panel, 5, b"\xff" * 2_000_001).status_code == 413
    bomb = io.BytesIO()
    Image.new("1", (10_000, 10_000)).save(bomb, "PNG")  # tiny file, 100 megapixels decoded
    assert signed_face(client, panel, 6, bomb.getvalue()).status_code == 413


def test_one_admin_cannot_hold_unlimited_enrolment_sessions(en):
    store, client, panel, faces, live, ana = en
    ids = [client.post(f"/api/cardholders/{ana}/faces/enrolment").json()["id"] for _ in range(10)]
    live_ids = [i for i in ids if client.post(f"/api/faces/enrolment/{i}/frame",
                                              content=faces.frame()).status_code == 200]
    assert len(live_ids) == liveness.SESSIONS_PER_OPERATOR and live_ids == ids[-liveness.SESSIONS_PER_OPERATOR:]


# ---- bounded memory ----------------------------------------------------------------------------

def test_unclaimed_face_results_do_not_pile_up(env, monkeypatch):
    store, ctl, client, panel, gid = env
    for i in range(1000):
        ctl.hold_face(1, i + 1, (None, 0.0, time.time(), b"x" * 1000, None))
    assert len(ctl.face_results) <= controller_mod.FACE_RESULTS_MAX
    later = time.time() + controller_mod.FACE_RESULT_TTL_S + 1
    monkeypatch.setattr(controller_mod.time, "time", lambda: later)
    ctl.hold_face(1, 99999, (None, 0.0, later, b"", None))
    assert list(ctl.face_results) == [(1, 99999)]  # everything older expired


def test_login_throttle_memory_and_cost_stay_bounded():
    t = LoginThrottle()
    start = time.perf_counter()
    for i in range(security.LOGIN_MAX_TRACKED * 3):
        t.fail(f"user:random{i}", "ip:203.0.113.7")
    assert t.size() <= security.LOGIN_MAX_TRACKED + 1
    assert time.perf_counter() - start < 5  # no per-request scan of every entry
    assert t.blocked("ip:203.0.113.7")  # the attacking address is still locked
    t2 = LoginThrottle()
    t2.fail("user:a", now=1000.0)
    t2.fail("user:b", now=1000.0 + security.LOGIN_LOCK_S + 1)
    assert list(t2.failures) == ["user:b"]  # stale entries expire


def test_memory_stays_flat_over_many_entries(tg):
    """Hundreds of grants, door frames and photos must not grow the server's
    Python memory: everything per entry is released once it is handled."""
    store, client, panel, det = tg
    jpgs = det.plan([1, 1])

    def entries(n):
        for _ in range(n):
            assert resp(panel.pin("2468"))[1] == Decision.GRANT
            req = panel.ctr
            for i, j in enumerate(jpgs):
                send_frame(client, panel, req, i, len(jpgs), i * 350, j)
        deadline = time.time() + 10
        while len(client.get("/api/events?kind=door.passage&limit=1000").json()) < counted[0] + n:
            assert time.time() < deadline
            time.sleep(0.05)
        counted[0] += n

    counted = [0]
    entries(60)  # warm up caches, connections and lazy imports
    gc.collect()
    tracemalloc.start()
    base = tracemalloc.take_snapshot()
    entries(240)
    gc.collect()
    grown = sum(s.size_diff for s in tracemalloc.take_snapshot().compare_to(base, "filename"))
    tracemalloc.stop()
    assert grown < 1_500_000, f"Python memory grew by {grown} bytes over 240 entries"


# ---- races -------------------------------------------------------------------------------------

def test_simultaneous_wrong_passwords_all_count(env):
    store, ctl, client, panel, gid = env
    pw = admin_password(store)

    def attempt(_):
        c = TestClient(client.app)
        return c.post("/api/login", json={"username": "admin", "password": "wrong-password"}).status_code

    with ThreadPoolExecutor(16) as pool:
        codes = list(pool.map(attempt, range(16)))
    assert codes.count(401) >= security.LOGIN_MAX_FAILURES
    fresh = TestClient(client.app)
    assert fresh.post("/api/login", json={"username": "admin", "password": pw}).status_code == 429


def test_parallel_writers_keep_the_audit_chain_intact(env):
    store, ctl, client, panel, gid = env

    def writer(n):
        for i in range(40):
            store.journal("test.parallel", detail=f"writer {n} record {i}")

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check = store.verify_journal()
    assert check["ok"], check
    seqs = [r["seq"] for r in store.q("SELECT seq FROM events ORDER BY seq")]
    assert seqs == list(range(1, len(seqs) + 1))


def test_a_door_frame_sent_twice_at_once_is_counted_once(tg):
    store, client, panel, det = tg
    assert resp(panel.pin("2468"))[1] == Decision.GRANT
    req = panel.ctr
    jpg = det.plan([1])[0]
    with ThreadPoolExecutor(10) as pool:
        codes = list(pool.map(lambda _: send_frame(client, panel, req, 0, 1, 0, jpg).status_code, range(10)))
    assert codes.count(200) == 1 and codes.count(409) == 9
    deadline = time.time() + 5
    while not client.get("/api/events?kind=door.passage").json():
        assert time.time() < deadline
        time.sleep(0.05)
    time.sleep(0.3)
    assert len(client.get("/api/events?kind=door.passage").json()) == 1


def test_racing_enrolment_frames_save_the_face_once(en):
    store, client, panel, faces, live, ana = en
    s = client.post(f"/api/cardholders/{ana}/faces/enrolment").json()
    steps = s["steps"]
    run_steps(client, faces, s["id"], steps[:-1])
    last = [faces.frame(steps[-1]) for _ in range(8)]  # the final step, many frames at once

    def push(jpg):
        return client.post(f"/api/faces/enrolment/{s['id']}/frame", content=jpg).json()["state"]

    with ThreadPoolExecutor(8) as pool:
        states = list(pool.map(push, last))
    assert "saved" in states
    assert len(client.get("/api/events?kind=cardholder.face_enrolled").json()) == 1
    n = store.q1("SELECT COUNT(*) n FROM face_templates WHERE cardholder_id=?", (ana,))["n"]
    assert 1 <= n <= liveness.MAX_TEMPLATES


# ---- responsiveness ----------------------------------------------------------------------------

DECISION_BUDGET_MS = 10.0  # server side of a door decision: frame in, sealed reply out


def test_door_decisions_stay_inside_the_10ms_budget(env):
    """The server's part of opening a door must stay well inside 10 ms at the
    99th percentile with a realistic number of cardholders. A slow query or a
    blocking call added to the decision path fails this test."""
    import statistics
    from lintel_server.protocol import MsgType
    store, ctl, client, panel, gid = env
    for i in range(500):
        store.x("INSERT INTO cardholders(first_name, last_name, pin_tag, created) VALUES(?, '', ?, ?)",
                (f"P{i}", store.pin_tag(f"7{i:05d}"), time.time()))
    add(client, gid, "Ana", "2468")
    for _ in range(50):  # warm up
        panel.pin("2468")
    times = []
    for _ in range(400):
        frame = panel.frame(MsgType.PIN_REQ, bytes([4]) + b"2468".ljust(9, b"\x00"))
        t = time.perf_counter()
        ctl.datagram(frame, ("10.0.0.5", 5000))
        times.append((time.perf_counter() - t) * 1000)
    times.sort()
    p99 = times[int(len(times) * 0.99)]
    assert p99 < DECISION_BUDGET_MS, f"p99 {p99:.2f} ms (median {statistics.median(times):.2f} ms)"
