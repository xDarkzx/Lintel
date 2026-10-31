"""Regression tests for the security review fixes and the admin features."""

import io

from fastapi.testclient import TestClient
from PIL import Image

from test_server import env  # noqa: F401  (fixture reuse)


def test_api_map_is_not_public(env):
    store, ctl, client, panel, gid = env
    assert client.get("/api/openapi.json").status_code == 404
    assert client.get("/api/docs").status_code == 404


def test_cross_origin_writes_are_refused(env):
    store, ctl, client, panel, gid = env
    r = client.post("/api/mode", json={"mode": 1}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert client.post("/api/mode", json={"mode": 0}, headers={"Origin": "http://testserver"}).status_code == 200


def test_csv_export_neutralises_formulas(env):
    store, ctl, client, panel, gid = env
    client.post("/api/cardholders", json={"first_name": "=HYPERLINK(\"http://x\")", "pin": "2468", "groups": [gid]})
    panel.pin("2468")
    csv_text = client.get("/api/events.csv").text
    assert "'=HYPERLINK" in csv_text and ",=HYPERLINK" not in csv_text


def test_last_admin_cannot_be_removed_or_demoted(env):
    store, ctl, client, panel, gid = env
    me = next(o for o in client.get("/api/operators").json() if o["username"] == "admin")
    assert client.patch(f"/api/operators/{me['id']}", json={"role": "viewer"}).status_code == 409
    assert client.patch(f"/api/operators/{me['id']}", json={"active": False}).status_code == 409
    client.post("/api/operators", json={"username": "second", "password": "second-admin-pw", "role": "admin"})
    second = next(o for o in client.get("/api/operators").json() if o["username"] == "second")
    assert client.patch(f"/api/operators/{me['id']}", json={"role": "operator"}).status_code == 200
    # Now 'second' is the only admin and is protected; our own session was ended by the change.
    assert client.get("/api/operators").status_code == 401


def test_operator_changes_end_their_sessions(env):
    store, ctl, client, panel, gid = env
    client.post("/api/operators", json={"username": "desk", "password": "desk-password-12", "role": "operator"})
    desk = TestClient(client.app)
    desk.post("/api/login", json={"username": "desk", "password": "desk-password-12"})
    assert desk.get("/api/me").status_code == 200
    oid = next(o for o in client.get("/api/operators").json() if o["username"] == "desk")["id"]
    assert client.patch(f"/api/operators/{oid}", json={"active": False}).status_code == 200
    assert desk.get("/api/me").status_code == 401
    assert desk.post("/api/login", json={"username": "desk", "password": "desk-password-12"}).status_code == 401


def test_short_passwords_and_odd_usernames_refused(env):
    store, ctl, client, panel, gid = env
    assert client.post("/api/operators", json={"username": "x1", "password": "short", "role": "viewer"}).status_code == 422
    assert client.post("/api/operators", json={"username": "bad name<", "password": "long-enough-pw-1", "role": "viewer"}).status_code == 422


def test_remote_unlock_needs_a_reason_and_is_journalled(env):
    store, ctl, client, panel, gid = env
    assert client.post("/api/doors/1/command", json={"command": "unlock"}).status_code == 400
    assert client.post("/api/doors/1/command", json={"command": "unlock", "reason": "courier at loading bay"}).status_code == 200
    ev = client.get("/api/events?kind=door.remote_unlock").json()[0]
    assert "courier" in ev["detail"] and ev["operator"] == "admin"
    assert ctl.commands[1][-1][0] == 5


def test_image_bomb_rejected_before_decoding(env):
    store, ctl, client, panel, gid = env
    ch = client.post("/api/cardholders", json={"first_name": "Ana", "groups": [gid]}).json()
    buf = io.BytesIO()
    Image.new("1", (10000, 10000)).save(buf, "PNG")  # tiny file, 100 megapixels
    r = client.post(f"/api/cardholders/{ch['id']}/faces", content=buf.getvalue(), headers={"Content-Type": "image/png"})
    assert r.status_code in (413, 503)  # 503 only when face models are not installed in the test environment
    if r.status_code == 413:
        assert "too large" in r.json()["detail"]


def test_bulk_import(env):
    store, ctl, client, panel, gid = env
    csv_body = "first_name,last_name,department,email,groups\nAna,Lee,Ops,ana@x.nz,Staff\n,No,Name,,\nBo,Ray,IT,,Nope\n"
    r = client.post("/api/cardholders/import", content=csv_body.encode(), headers={"Content-Type": "text/csv"})
    assert r.json()["added"] == 2 and len(r.json()["issues"]) == 2
    names = {c["first_name"]: c for c in client.get("/api/cardholders").json()}
    assert names["Ana"]["groups"] == [gid] and not names["Ana"]["has_pin"]


def fake_dns(monkeypatch, table):
    """Resolves the test host names to chosen addresses, so no real DNS is used."""
    import socket
    def getaddrinfo(host, port, *a, **kw):
        if host not in table:
            raise socket.gaierror("unknown host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in table[host]]
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


def test_webhook_must_be_https(env, monkeypatch):
    store, ctl, client, panel, gid = env
    fake_dns(monkeypatch, {"hooks.example": ["93.184.216.34"]})
    assert client.put("/api/settings/webhook", json={"url": "http://internal:8080/x"}).status_code == 422
    assert client.put("/api/settings/webhook", json={"url": "https://hooks.example/abc", "min_priority": 2}).status_code == 200
    assert client.get("/api/settings/webhook").json()["min_priority"] == 2
