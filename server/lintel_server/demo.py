"""The one-command demo: a real Lintel server with a seeded site and doors
that generate traffic over the real protocol, so the console can be explored
without any hardware.

    docker compose -f demo/compose.yaml up --build      # then open https://localhost:8443

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
import json
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


# ---- the site -----------------------------------------------------------------------------------

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


@dataclass(frozen=True)
class Door:
    id: int
    name: str
    area: str
    mode: str
    floor: str  # a key of FLOORS
    x: float    # position on the plan, as fractions
    y: float


PEOPLE = (
    Person("Aroha", "Ngata", "2468", ("Staff", "IT"), duress="8642"),
    Person("Ben", "Carter", "3579", ("Staff",)),
    Person("Mei", "Chen", "4826", ("Staff",)),
    Person("Sam", "Patel", "5937", ("Staff", "IT")),
    Person("Lucy", "Fraser", "7351", ("Staff",)),
    Person("Hemi", "Walker", "8264", ("Staff",)),
    Person("Priya", "Singh", "9173", ("Staff", "IT")),
    Person("Tom", "Wilson", "6149", ("Contractors",)),  # enrolled, but no access upstairs
)
STAFF = [p for p in PEOPLE if "Staff" in p.groups]
IT = [p for p in PEOPLE if "IT" in p.groups]

# Two levels of a public-domain plan (docs/demo/floor-plans); doors sit where the rooms' doors are.
FLOORS = {"ground": ("Ground floor", 0, "ground-floor.png"), "level-1": ("Level 1", 1, "level-1.png")}
MAIN, SERVERS, LAB = "Main Entrance", "Server Room", "Lab (Lintel Vision)"
DOORS = (
    Door(1, MAIN, "Ground floor", "pin", "ground", 0.50, 0.86),
    Door(2, SERVERS, "Ground floor", "pin", "ground", 0.41, 0.15),
    Door(3, LAB, "Level 1", "face_group", "level-1", 0.30, 0.39),
    Door(4, "Reception", "Ground floor", "pin", "ground", 0.60, 0.65),
    Door(5, "General Office", "Ground floor", "pin", "ground", 0.38, 0.65),
    Door(6, "Stock Room", "Ground floor", "pin", "ground", 0.60, 0.33),
    Door(7, "Boardroom", "Level 1", "pin", "level-1", 0.60, 0.43),
    Door(8, "Clean Room", "Level 1", "pin", "level-1", 0.39, 0.50),
)
GROUPS = {"Staff": (1, 3, 4, 5, 7, 8), "IT": (1, 2, 6), "Contractors": (1, 4)}


# ---- faces --------------------------------------------------------------------------------------

SKIN = ((255, 219, 172), (241, 194, 125), (224, 172, 105), (198, 134, 66), (141, 85, 36), (233, 190, 160))
HAIR = ((35, 28, 25), (90, 56, 37), (180, 130, 70), (60, 40, 30), (20, 20, 20), (140, 140, 140))
SHIRT = ((37, 99, 235), (22, 163, 74), (220, 38, 38), (124, 58, 237), (15, 118, 110), (202, 138, 4))


def face_jpeg(name: str) -> bytes:
    """A cartoon portrait for a demo person, tagged so DemoFaces knows who it is."""
    h = hashlib.sha256(name.encode()).digest()
    skin, hair, shirt = SKIN[h[0] % len(SKIN)], HAIR[h[1] % len(HAIR)], SHIRT[h[2] % len(SHIRT)]
    img = Image.new("RGB", (320, 240), (226 - h[3] % 30, 232 - h[4] % 30, 240 - h[5] % 30))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((90, 175, 230, 260), 40, fill=shirt)                  # shoulders
    d.rectangle((145, 150, 175, 185), fill=skin)                              # neck
    if h[6] % 2:                                                              # long hair behind the face
        d.rounded_rectangle((100, 40, 220, 175), 50, fill=hair)
    d.ellipse((112, 48, 208, 165), fill=skin)                                 # face
    d.pieslice((106, 34, 214, 120), 180, 360, fill=hair)                      # hair on top
    for ex in (138, 170):                                                     # eyes and brows
        d.ellipse((ex, 96, ex + 12, 108), fill=(255, 255, 255))
        d.ellipse((ex + 3, 99, ex + 9, 105), fill=(40, 30, 25))
        d.line((ex - 2, 90, ex + 14, 88 + h[7] % 4), fill=hair, width=3)
    d.line((160, 108, 156, 126), fill=tuple(max(0, c - 40) for c in skin), width=2)  # nose
    d.arc((142, 120, 178, 146), 20, 160, fill=(150, 60, 60), width=3)               # smile
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=88, comment=TAG + name.encode())
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
        return FaceResult(self.embedding(comment[len(TAG):].decode()), (112, 48, 96, 117), 0.95, None)

    @staticmethod
    def embedding(name: str) -> np.ndarray:
        seed = int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], "little")
        v = np.random.default_rng(seed).normal(size=128).astype(np.float32)
        return v / np.linalg.norm(v)


# ---- seeding ------------------------------------------------------------------------------------

def seed(store, plans: Path | None) -> None:
    """Doors, floor plans, groups, people and their faces. Does nothing on a
    site that is already seeded. Without `plans` the doors are not on a map."""
    if store.q1("SELECT 1 FROM doors WHERE name=?", (DOORS[-1].name,)):
        return
    now = time.time()
    floor_ids = _seed_floors(store, plans, now)
    always = store.q1("SELECT id FROM schedules WHERE name='24/7'")["id"]
    for d in DOORS:
        placed = d.floor in floor_ids
        store.x("INSERT INTO doors(id, name, area, key, credential_mode, key_created, floor_id, map_x, map_y, "
                "map_locked) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (d.id, d.name, d.area, store.seal_door_key(d.id, secrets.token_bytes(16)), d.mode, now,
                 floor_ids.get(d.floor), d.x if placed else None, d.y if placed else None, int(placed)))
        if d.mode != "face_group":  # an adopted keypad; walk-through doors use a Lintel Vision unit instead
            serial = "LNT-" + hashlib.sha256(f"demo-keypad-{d.id}".encode()).hexdigest()[:12].upper()
            mac = ":".join(f"{b:02X}" for b in hashlib.sha256(serial.encode()).digest()[:6])
            store.x("INSERT INTO devices(serial, pubkey, mac, firmware, controller, first_seen, last_seen, door_id, "
                    "reported_door, adopted_at, adopt_seq) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (serial, secrets.token_bytes(32), mac, "1.4.2", f"door-ctl-{d.id:02d}", now, now, d.id, d.id,
                     now, 1))
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
    store.journal("demo.seeded", operator="system",
                  detail=f"demo site created: {len(DOORS)} doors, {len(floor_ids)} floor plans, {len(PEOPLE)} people")


def _seed_floors(store, plans: Path | None, now: float) -> dict[str, int]:
    """Floors with their plans, stored as the console's own upload stores them."""
    from .web import PLAN_MAX_SIDE
    ids: dict[str, int] = {}
    if plans is None or not plans.is_dir():
        return ids
    out = store.data_dir / "plans"
    out.mkdir(exist_ok=True)
    for key, (name, level, file) in FLOORS.items():
        if not (plans / file).exists():
            continue
        fid = store.x("INSERT INTO floors(name, level, created) VALUES(?, ?, ?)", (name, level, now))
        with Image.open(plans / file) as im:
            im = im.convert("RGB")
            im.thumbnail((PLAN_MAX_SIDE, PLAN_MAX_SIDE))
            im.save(out / f"floor{fid}.png", "PNG", optimize=True)
            w, h = im.size
        store.x("UPDATE floors SET plan=?, width=?, height=? WHERE id=?", (f"floor{fid}.png", w, h, fid))
        ids[key] = fid
    return ids


class Doors:
    """One simulated device per door, resuming from the counters the server
    has seen, so a restarted demo is not refused as a replay."""

    def __init__(self, store, deliver: Callable[[bytes], bytes | None],
                 post: Callable[[str, bytes, dict[str, str]], tuple[int, dict]]) -> None:
        self.deliver, self.post = deliver, post
        self.units: dict[str, VisionUnit] = {}
        self.keypads: list[VisionUnit] = []
        for r in store.q("SELECT id, name, key, rx_highest, credential_mode FROM doors ORDER BY id"):
            u = VisionUnit(r["id"], store.door_key(r["id"], r["key"]), store.secrets.net_id, deliver, post)
            u.ctr = r["rx_highest"]
            self.units[r["name"]] = u
            if r["credential_mode"] != "face_group":
                self.keypads.append(u)

    def __getitem__(self, name: str) -> VisionUnit:
        return self.units[name]

    def heartbeat_all(self) -> None:
        for u in self.units.values():
            u.heartbeat()

    def diag_all(self) -> None:
        for i, u in enumerate(self.keypads):
            u.diag(uptime_s=86_400 * (3 + i) + 3_600 * i, temp_c=38 + i % 5)


# ---- scenarios: each one is something a visitor should see in the console -----------------------

def keypad(doors: Doors, door: str, pin: str, who: str) -> None:
    """A PIN at a keypad, then the photo the keypad takes of every attempt."""
    doors[door].pin(pin)
    doors[door].photo(face_jpeg(who))


def front_door_entry(doors: Doors) -> None:
    p = random.choice(PEOPLE)
    keypad(doors, MAIN, p.pin, p.name)


def reception_entry(doors: Doors) -> None:
    p = random.choice(PEOPLE)
    keypad(doors, "Reception", p.pin, p.name)


def office_entry(doors: Doors) -> None:
    p = random.choice(STAFF)
    keypad(doors, "General Office", p.pin, p.name)


def boardroom_entry(doors: Doors) -> None:
    p = random.choice(STAFF)
    keypad(doors, "Boardroom", p.pin, p.name)


def clean_room_entry(doors: Doors) -> None:
    p = random.choice(STAFF)
    keypad(doors, "Clean Room", p.pin, p.name)


def server_room_entry(doors: Doors) -> None:
    p = random.choice(IT)
    keypad(doors, SERVERS, p.pin, p.name)


def wrong_pin(doors: Doors) -> None:
    keypad(doors, "Stock Room", "1593", "A Visitor")


def walk_through_group(doors: Doors) -> None:
    u = doors[LAB]
    u.start_passage()
    group = random.sample(STAFF, random.randint(2, 3))
    for i, p in enumerate(group, 1):
        u.present(i, face_jpeg(p.name), depth_face_png())
    u.crossed(len(group), list(range(1, len(group) + 1)))


def stranger_tailgates(doors: Doors) -> None:
    u = doors[LAB]
    u.start_passage()
    group = random.sample(STAFF, 2)
    for i, p in enumerate(group, 1):
        u.present(i, face_jpeg(p.name), depth_face_png())
    u.present(3, face_jpeg("A Stranger"), depth_face_png())  # not enrolled
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
        keypad(doors, SERVERS, guess, "A Stranger")


def duress(doors: Doors) -> None:
    keypad(doors, MAIN, PEOPLE[0].duress, PEOPLE[0].name)


SCENARIOS = (front_door_entry, reception_entry, office_entry, boardroom_entry, clean_room_entry, server_room_entry,
             walk_through_group, wrong_pin, stranger_tailgates, contractor_follows_into_the_lab,
             hidden_behind_someone, photo_spoof, pin_guessing, duress)
WEIGHTS = (24, 10, 10, 6, 6, 8, 20, 4, 4, 3, 2, 2, 1, 1)  # mostly ordinary days, with the occasional incident

# The first minute and a bit after start, timed (seconds) so that everything
# happens while the console is showing the right place: the ground floor map
# from 8 s, Level 1 from 24 s. Then the ordinary day takes over.
SHOWCASE = (
    (1, front_door_entry), (3.5, front_door_entry), (6, walk_through_group),
    (9, front_door_entry), (11, office_entry), (13, reception_entry), (15, wrong_pin), (17, server_room_entry),
    (19, pin_guessing), (22, front_door_entry),
    (25, walk_through_group), (28, boardroom_entry), (31, stranger_tailgates), (35, photo_spoof),
    (37.5, contractor_follows_into_the_lab), (40, hidden_behind_someone), (42, clean_room_entry),
    (46, duress), (50, front_door_entry),
)


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
    beat = [time.time()]
    doors.heartbeat_all()
    doors.diag_all()

    def wait_until(t: float) -> None:
        # Sleeps, heartbeating so no door drops offline meanwhile.
        while time.time() < t and not stop():
            if time.time() - beat[0] > 10:
                doors.heartbeat_all()
                beat[0] = time.time()
            time.sleep(min(0.25, max(0.0, t - time.time())))

    def play(scenario) -> None:
        try:
            scenario(doors)
            log.info("demo: %s", scenario.__name__.replace("_", " "))
        except Exception:  # a demo keeps going; the server's own logs say what it refused
            log.exception("demo scenario failed")

    # Optionally hold the showcase back (time to sign in and start recording).
    start = time.time() + float(os.environ.get("LINTEL_DEMO_START_DELAY", "0"))
    wait_until(start)
    for at, scenario in SHOWCASE:
        wait_until(start + at)
        play(scenario)
    while not stop():
        wait_until(time.time() + random.uniform(3, 7))
        play(random.choices(SCENARIOS, WEIGHTS)[0])


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
    plans = Path(os.environ.get("LINTEL_DEMO_PLANS", Path(__file__).resolve().parents[2] / "docs/demo/floor-plans"))
    http_port = int(os.environ.get("LINTEL_HTTPS_PORT", "8443"))
    udp_port = int(os.environ.get("LINTEL_UDP_PORT", "47800"))
    store = Store(data)
    seed(store, plans)
    init = data / "initial_admin.txt"
    if init.exists():
        pw = init.read_text().split("password: ")[1].strip()
        log.warning("DEMO: sign in as admin / %s (https://localhost:8443, or the LINTEL_DEMO_PORT you set)", pw)
    store.db.close()
    asyncio.run(serve(data, os.environ.get("LINTEL_HOST", "0.0.0.0"), http_port, udp_port,
                      engines=(DemoFaces(), None, None), background=traffic))


if __name__ == "__main__":
    main()
