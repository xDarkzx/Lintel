"""The one-command demo: a real Lintel server with a seeded site and doors
that generate traffic over the real protocol, so the console can be explored
without any hardware.

    docker compose -f demo/compose.yaml up      # then open https://localhost:8443

Everything a door sends here goes through the same path a keypad's or a
Lintel Vision unit's would: sealed UDP frames, signed HTTPS uploads, the
replay window, the access engine, the journal and the alarms.

The only stand-in is the face engine. The demo's people are drawn cartoons,
not photos of real people, and a real face model cannot recognise a cartoon,
so `DemoFaces` recognises each drawing by a tag in its JPEG. It is used only
by this entry point; `python -m lintel_server serve` never loads it.
"""

from __future__ import annotations

import asyncio
import hashlib
import http.client
import io
import logging
import os
import random
import secrets
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import numpy as np
from PIL import Image, ImageDraw

from .faces import FaceEngine, FaceError, FaceResult
from .vision_sim import VisionUnit, depth_face_png, depth_flat_png

log = logging.getLogger("lintel.demo")
TAG = b"lintel-demo-face:"


# ---- people and faces --------------------------------------------------------------------------

@dataclass(frozen=True)
class Person:
    first: str
    last: str
    pin: str
    groups: tuple[str, ...]
    face: bool = True
    duress: str | None = None

    @property
    def name(self) -> str:
        return f"{self.first} {self.last}"


PEOPLE = (
    Person("Aroha", "Ngata", "2468", ("Staff", "IT"), duress="8642"),
    Person("Ben", "Carter", "3579", ("Staff",)),
    Person("Mei", "Chen", "4826", ("Staff",)),
    Person("Sam", "Patel", "5937", ("Staff", "IT")),
    Person("Tom", "Wilson", "6149", ("Contractors",)),  # enrolled, but no access to the lab
)
STAFF = [p for p in PEOPLE if "Staff" in p.groups]
DOORS = (  # id, name, area, credential mode
    (1, "Main Entrance", "Ground floor", "pin"),
    (2, "Server Room", "Ground floor", "pin"),
    (3, "Lab (Lintel Vision)", "Level 1", "face_group"),
)
GROUPS = {"Staff": (1, 3), "IT": (1, 2), "Contractors": (1,)}


def face_jpeg(name: str) -> bytes:
    """A cartoon face for a demo person, tagged so DemoFaces knows who it is."""
    h = hashlib.sha256(name.encode()).digest()
    img = Image.new("RGB", (320, 240), (40, 44, 52))
    d = ImageDraw.Draw(img)
    d.ellipse((110, 40, 210, 170), fill=(200 + h[0] % 55, 150 + h[1] % 60, 110 + h[2] % 60))
    d.ellipse((135, 85, 150, 100), fill=(30, 30, 30))
    d.ellipse((170, 85, 185, 100), fill=(30, 30, 30))
    d.arc((140, 110, 180, 145), 20, 160, fill=(90, 30, 30), width=4)
    d.rectangle((100, 170, 220, 240), fill=(h[3], h[4], h[5]))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=90, comment=TAG + name.encode())
    return buf.getvalue()


def plain_jpeg() -> bytes:
    """A frame with nobody in it."""
    buf = io.BytesIO()
    Image.new("RGB", (320, 240), (40, 44, 52)).save(buf, "JPEG", quality=90)
    return buf.getvalue()


class DemoFaces:
    """Recognises the demo's cartoon faces by their tag: each name always
    gives the same embedding, and different names give unrelated ones."""

    best_match = staticmethod(FaceEngine.best_match)

    def analyse(self, jpeg: bytes) -> FaceResult:
        comment = Image.open(io.BytesIO(jpeg)).info.get("comment", b"")
        if not comment.startswith(TAG):
            raise FaceError("no face found")
        return FaceResult(self.embedding(comment[len(TAG):].decode()), (110, 40, 100, 130), 0.95, None)

    @staticmethod
    def embedding(name: str) -> np.ndarray:
        seed = int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], "little")
        v = np.random.default_rng(seed).normal(size=128).astype(np.float32)
        return v / np.linalg.norm(v)


# ---- the site ----------------------------------------------------------------------------------

def seed(store) -> None:
    """Doors, groups, people and their faces. Does nothing on a site that is already seeded."""
    if store.q1("SELECT 1 FROM doors WHERE name=?", (DOORS[-1][1],)):
        return
    now = time.time()
    always = store.q1("SELECT id FROM schedules WHERE name='24/7'")["id"]
    for door_id, name, area, mode in DOORS:
        store.x("INSERT INTO doors(id, name, area, key, credential_mode, key_created) VALUES(?, ?, ?, ?, ?, ?)",
                (door_id, name, area, store.seal_door_key(door_id, secrets.token_bytes(16)), mode, now))
    group_ids = {}
    for g, doors in GROUPS.items():
        group_ids[g] = store.x("INSERT INTO access_groups(name, schedule_id) VALUES(?, ?)", (g, always))
        for door_id in doors:
            store.x("INSERT INTO access_group_doors(group_id, door_id) VALUES(?, ?)", (group_ids[g], door_id))
    for p in PEOPLE:
        cid = store.x("INSERT INTO cardholders(first_name, last_name, department, pin_tag, duress_tag, created) "
                      "VALUES(?, ?, ?, ?, ?, ?)", (p.first, p.last, p.groups[0], store.pin_tag(p.pin),
                                                   store.pin_tag(p.duress) if p.duress else None, now))
        for g in p.groups:
            store.x("INSERT INTO cardholder_groups(cardholder_id, group_id) VALUES(?, ?)", (cid, group_ids[g]))
        if p.face:
            emb = DemoFaces.embedding(p.name)
            store.x("INSERT INTO face_templates(cardholder_id, embedding, source, created) VALUES(?, ?, ?, ?)",
                    (cid, store.seal_template(cid, emb.tobytes()), "demo", now))
    store.journal("demo.seeded", operator="system", detail="demo site created: 3 doors, 5 people")


class Doors:
    """One simulated device per door, resuming from the counters the server
    has seen, so a restarted demo is not refused as a replay."""

    def __init__(self, store, deliver: Callable[[bytes], bytes | None],
                 post: Callable[[str, bytes, dict[str, str]], tuple[int, dict]]) -> None:
        self.deliver, self.post = deliver, post
        self.units: dict[str, VisionUnit] = {}
        for r in store.q("SELECT id, name, key, rx_highest FROM doors ORDER BY id"):
            u = VisionUnit(r["id"], store.door_key(r["id"], r["key"]), store.secrets.net_id, deliver, post)
            u.ctr = r["rx_highest"]
            self.units[r["name"]] = u

    def __getitem__(self, name: str) -> VisionUnit:
        return self.units[name]

    def heartbeat_all(self) -> None:
        for u in self.units.values():
            u.heartbeat()


# ---- scenarios: each one is something a visitor should see in the console -----------------------

LAB, MAIN, SERVERS = "Lab (Lintel Vision)", "Main Entrance", "Server Room"


def pin_entry(doors: Doors) -> None:
    p = random.choice(PEOPLE)
    doors[MAIN].pin(p.pin)


def server_room_entry(doors: Doors) -> None:
    doors[SERVERS].pin(random.choice([p for p in PEOPLE if "IT" in p.groups]).pin)


def walk_through_group(doors: Doors) -> None:
    u = doors[LAB]
    u.start_passage()
    group = random.sample(STAFF, random.randint(1, 3))
    for i, p in enumerate(group, 1):
        u.present(i, face_jpeg(p.name), depth_face_png())
    u.crossed(len(group), list(range(1, len(group) + 1)))


def stranger_tailgates(doors: Doors) -> None:
    u = doors[LAB]
    u.start_passage()
    group = random.sample(STAFF, 2)
    for i, p in enumerate(group, 1):
        u.present(i, face_jpeg(p.name), depth_face_png())
    u.present(3, face_jpeg("A Visitor"), depth_face_png())  # not enrolled
    u.crossed(3, [1, 2, 3])


def contractor_follows_into_the_lab(doors: Doors) -> None:
    u = doors[LAB]
    u.start_passage()
    u.present(1, face_jpeg(random.choice(STAFF).name), depth_face_png())
    u.present(2, face_jpeg("Tom Wilson"), depth_face_png())  # enrolled, no access here
    u.crossed(2, [1, 2])


def hidden_behind_someone(doors: Doors) -> None:
    u = doors[LAB]
    u.start_passage()
    u.present(1, face_jpeg(random.choice(STAFF).name), depth_face_png())
    u.crossed(2, [1], overhead=True)  # the overhead camera counted two


def photo_spoof(doors: Doors) -> None:
    u = doors[LAB]
    u.start_passage()
    u.present(1, face_jpeg(random.choice(STAFF).name), depth_flat_png())  # a printed photo held up


def pin_guessing(doors: Doors) -> None:
    for guess in ("1357", "2580", "1470"):
        doors[SERVERS].pin(guess)


def duress(doors: Doors) -> None:
    doors[MAIN].pin(PEOPLE[0].duress)


SCENARIOS = (pin_entry, server_room_entry, walk_through_group, stranger_tailgates, contractor_follows_into_the_lab,
             hidden_behind_someone, photo_spoof, pin_guessing, duress)
WEIGHTS = (30, 10, 30, 6, 4, 3, 3, 2, 1)  # mostly ordinary days, with the occasional incident
# The first minute after start: every scenario once, incidents early, so a
# visitor sees everything Lintel does before the ordinary day takes over.
SHOWCASE = (walk_through_group, stranger_tailgates, pin_entry, photo_spoof, contractor_follows_into_the_lab,
            server_room_entry, pin_guessing, hidden_behind_someone, duress)
SHOWCASE_GAP_S = 6


# ---- running against the real server ------------------------------------------------------------

def _udp(port: int) -> Callable[[bytes], bytes | None]:
    def deliver(frame: bytes) -> bytes | None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(frame, ("127.0.0.1", port))
            try:
                return s.recv(512)
            except socket.timeout:
                return None
    return deliver


def _https(port: int, token: str) -> Callable[[str, bytes, dict[str, str]], tuple[int, dict]]:
    # The demo talks to its own server on this machine only; a real door
    # controller pins the certificate instead (see door_controller.py).
    ctx = ssl._create_unverified_context()

    def post(path: str, body: bytes, headers: dict[str, str]) -> tuple[int, dict]:
        import json
        conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=ctx)
        try:
            conn.request("POST", path, body=body, headers={**headers, "Authorization": f"Bearer {token}"})
            r = conn.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            conn.close()
    return post


def run_traffic(store, http_port: int, udp_port: int, stop: Callable[[], bool] = lambda: False) -> None:
    doors = Doors(store, _udp(udp_port), _https(http_port, store.secrets.controller_token))
    doors.heartbeat_all()
    last_beat = time.time()
    # Optionally hold the showcase back (time to sign in and start recording),
    # still heartbeating so the doors do not drop offline meanwhile.
    begin = time.time() + float(os.environ.get("LINTEL_DEMO_START_DELAY", "0"))
    while time.time() < begin and not stop():
        if time.time() - last_beat > 10:
            doors.heartbeat_all()
            last_beat = time.time()
        time.sleep(min(1.0, max(0.0, begin - time.time())))
    showcase = list(SHOWCASE)
    while not stop():
        try:
            if time.time() - last_beat > 10:
                doors.heartbeat_all()
                last_beat = time.time()
            scenario = showcase.pop(0) if showcase else random.choices(SCENARIOS, WEIGHTS)[0]
            scenario(doors)
            log.info("demo: %s", scenario.__name__.replace("_", " "))
        except Exception:  # a demo keeps going; the server's own logs say what it refused
            log.exception("demo scenario failed")
        time.sleep(SHOWCASE_GAP_S if showcase else random.uniform(4, 9))


async def traffic(store, ctl, http_port: int, udp_port: int) -> None:
    for _ in range(100):  # wait for the HTTPS listener
        try:
            with socket.create_connection(("127.0.0.1", http_port), timeout=1):
                break
        except OSError:
            await asyncio.sleep(0.2)
    await asyncio.to_thread(run_traffic, store, http_port, udp_port)


def main() -> None:
    from .__main__ import serve
    from .store import Store
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    data = Path(os.environ.get("LINTEL_DATA", "demo-data"))
    http_port = int(os.environ.get("LINTEL_HTTPS_PORT", "8443"))
    udp_port = int(os.environ.get("LINTEL_UDP_PORT", "47800"))
    store = Store(data)
    seed(store)
    init = data / "initial_admin.txt"
    if init.exists():
        pw = init.read_text().split("password: ")[1].strip()
        log.warning("DEMO: sign in as admin / %s (https://localhost:8443, or the LINTEL_DEMO_PORT you set)", pw)
    store.db.close()
    asyncio.run(serve(data, os.environ.get("LINTEL_HOST", "0.0.0.0"), http_port, udp_port,
                      engines=(DemoFaces(), None, None), background=traffic))


if __name__ == "__main__":
    main()
