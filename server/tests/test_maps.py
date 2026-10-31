"""Floor plans: floors, plan images, door markers that lock in place."""

import io

from fastapi.testclient import TestClient
from PIL import Image

from test_server import env  # noqa: F401  (fixture reuse)


def plan_bytes(w=1200, h=800, fmt="JPEG"):
    buf = io.BytesIO()
    img = Image.new("RGB", (w, h), (245, 245, 240))
    img.info["comment"] = b"<script>alert(1)</script>"
    img.save(buf, fmt, comment=b"<script>alert(1)</script>" if fmt == "JPEG" else None)
    return buf.getvalue()


def floor(client, name="Ground", level=0):
    r = client.post("/api/floors", json={"name": name, "level": level})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_floors_are_ordered_by_level_and_hold_a_reencoded_plan(env):
    store, ctl, client, panel, gid = env
    upper = floor(client, "Level 1", 1)
    ground = floor(client, "Ground", 0)
    r = client.put(f"/api/floors/{ground}/plan", content=plan_bytes())
    assert r.status_code == 200 and r.json() == {"ok": True, "width": 1200, "height": 800}
    got = client.get("/api/floors").json()
    assert [f["name"] for f in got["floors"]] == ["Ground", "Level 1"]
    assert got["floors"][0]["has_plan"] and not got["floors"][1]["has_plan"]
    png = client.get(f"/api/floors/{ground}/plan.png")
    assert png.status_code == 200 and png.content.startswith(b"\x89PNG")
    assert b"<script>" not in png.content  # only pixels survive the upload
    assert client.get(f"/api/floors/{upper}/plan.png").status_code == 404


def test_big_plans_are_scaled_down_and_non_images_refused(env):
    store, ctl, client, panel, gid = env
    fid = floor(client)
    assert client.put(f"/api/floors/{fid}/plan", content=plan_bytes(6000, 3000)).json()["width"] == 4096
    assert client.put(f"/api/floors/{fid}/plan", content=b"<svg onload=alert(1)>").status_code == 400


def test_doors_are_placed_moved_and_locked_in_place(env):
    store, ctl, client, panel, gid = env
    fid = floor(client)
    assert client.put("/api/doors/1/location", json={"floor_id": fid, "x": 0.25, "y": 0.6}).status_code == 200
    door = next(d for d in client.get("/api/floors").json()["doors"] if d["id"] == 1)
    assert (door["floor_id"], door["map_x"], door["map_y"], door["map_locked"]) == (fid, 0.25, 0.6, 0)

    assert client.put("/api/doors/1/location/lock", json={"locked": True}).status_code == 200
    moved = client.put("/api/doors/1/location", json={"floor_id": fid, "x": 0.9, "y": 0.9})
    assert moved.status_code == 409 and "locked" in moved.json()["detail"]
    assert client.put("/api/doors/1/location", json={"floor_id": None}).status_code == 409

    client.put("/api/doors/1/location/lock", json={"locked": False})
    assert client.put("/api/doors/1/location", json={"floor_id": fid, "x": 0.9, "y": 0.1}).status_code == 200
    kinds = [e["kind"] for e in client.get("/api/events?kind=map.*").json()]
    assert {"map.door_placed", "map.door_locked", "map.door_unlocked"} <= set(kinds)


def test_markers_stay_on_the_plan(env):
    store, ctl, client, panel, gid = env
    fid = floor(client)
    assert client.put("/api/doors/1/location", json={"floor_id": fid, "x": 1.4, "y": 0.5}).status_code == 422
    assert client.put("/api/doors/1/location", json={"floor_id": 999, "x": 0.5, "y": 0.5}).status_code == 404
    assert client.put("/api/doors/1/location/lock", json={"locked": True}).status_code == 409  # not placed yet


def test_only_admins_change_maps_but_everyone_can_read_them(env):
    store, ctl, client, panel, gid = env
    fid = floor(client)
    client.post("/api/operators", json={"username": "guard", "password": "guard-password-1", "role": "viewer"})
    guard = TestClient(client.app)
    guard.post("/api/login", json={"username": "guard", "password": "guard-password-1"})
    assert guard.get("/api/floors").status_code == 200
    assert guard.post("/api/floors", json={"name": "Roof"}).status_code == 403
    assert guard.put("/api/doors/1/location", json={"floor_id": fid}).status_code == 403
    assert guard.put(f"/api/floors/{fid}/plan", content=plan_bytes()).status_code == 403


def test_deleting_a_floor_takes_its_doors_off_the_map(env):
    store, ctl, client, panel, gid = env
    fid = floor(client)
    client.put(f"/api/floors/{fid}/plan", content=plan_bytes())
    client.put("/api/doors/1/location", json={"floor_id": fid, "x": 0.5, "y": 0.5})
    client.put("/api/doors/1/location/lock", json={"locked": True})
    assert client.delete(f"/api/floors/{fid}").status_code == 200
    door = next(d for d in client.get("/api/floors").json()["doors"] if d["id"] == 1)
    assert door["floor_id"] is None and door["map_locked"] == 0
    assert not (store.data_dir / "plans" / f"floor{fid}.png").exists()


def test_plans_are_part_of_every_backup(env, tmp_path):
    from lintel_server.backup import restore_backup
    store, ctl, client, panel, gid = env
    fid = floor(client)
    client.put(f"/api/floors/{fid}/plan", content=plan_bytes())
    pw = (store.data_dir / "initial_admin.txt").read_text().split("password: ")[1].strip()
    blob = client.post("/api/backup", json={"passphrase": "a long backup passphrase", "password": pw}).content
    restored = restore_backup(blob, "a long backup passphrase", tmp_path / "restored")
    assert f"plans/floor{fid}.png" in restored
