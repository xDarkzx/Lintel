"""Tailgating detection: count the people who go through a door against the
credentials used to open it.

After a grant the keypad records a short burst of frames while the door is
unlocked (the same way reader-based systems such as Alcatraz's Rock work,
with no extra camera). Each frame is signed by the panel with its index and
capture time, so the door controller relaying them cannot add, drop or
reorder frames unnoticed.

People are found with YOLOX-S (OpenCV model zoo, Apache-2.0), a general
person detector. This is deliberately not face recognition: counting people
needs no biometric processing of bystanders, and the frames are discarded
after analysis unless they are evidence for an alarm.

The rule is conservative, because an alarm nobody trusts gets ignored: more
people than credentials must be in view together, close to the door, in at
least CONFIRM_FRAMES frames. Someone hidden directly behind the first person
can still be missed from a camera at the keypad; an overhead camera covers
that case.
"""

from __future__ import annotations

import hashlib
import io
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("lintel.tailgate")

PERSON_MODEL = "object_detection_yolox_2022nov.onnx"
PERSON_CLASS = 0          # COCO "person"
MIN_SCORE = 0.40          # backlit doorways score lower; measured 0.45 on a real one
MIN_HEIGHT_FRAC = 0.30    # near the door: people further away are passers-by
CONFIRM_FRAMES = 2        # an extra person must be seen in at least this many frames
MAX_FRAMES = 32
MAX_FRAME_MS = 60_000
DONE_REMEMBERED = 1024     # finished bursts remembered, to refuse late or replayed frames
SESSION_TIMEOUT_S = 25.0  # analyse with what arrived if frames go missing
CREDENTIAL_SLACK_S = 2.0  # grants this close to the window count as legitimate entries


@dataclass
class Person:
    x: float
    y: float
    w: float
    h: float
    score: float


@dataclass
class Frame:
    index: int
    ms: int
    people: list[Person]
    height: int


@dataclass
class Assessment:
    counts: list[int]       # people near the door, per frame
    max_people: int
    allowed: int
    frames_over: int        # frames with more people than credentials
    tailgating: bool
    worst: int | None       # index into the frame list of the clearest evidence


def near_door(people: list[Person], height: int) -> list[Person]:
    return [p for p in people if p.score >= MIN_SCORE and p.h >= MIN_HEIGHT_FRAC * height]


def assess(frames: list[Frame], allowed: int) -> Assessment:
    """Pure counting rule, separate from the detector so it can be tested."""
    allowed = max(1, allowed)
    counts = [len(near_door(f.people, f.height)) for f in frames]
    over = [i for i, c in enumerate(counts) if c > allowed]
    worst = max(over, key=lambda i: counts[i]) if over else None
    return Assessment(counts, max(counts, default=0), allowed, len(over), len(over) >= CONFIRM_FRAMES, worst)


class PersonDetector:
    """YOLOX-S through OpenCV's DNN module, following the model zoo's demo:
    RGB input letterboxed to 640x640 with grey padding, no normalisation."""

    SIZE = 640

    def __init__(self, models: Path) -> None:
        import cv2
        import numpy as np
        path = models / PERSON_MODEL
        if not path.exists():
            raise FileNotFoundError(f"person model missing: {path}")
        self._cv2, self._np = cv2, np
        self._net = cv2.dnn.readNet(str(path))
        self._lock = threading.Lock()  # OpenCV networks are not thread-safe
        grids, strides = [], []
        for s in (8, 16, 32):
            n = self.SIZE // s
            xv, yv = np.meshgrid(np.arange(n), np.arange(n))
            g = np.stack((xv, yv), 2).reshape(1, -1, 2)
            grids.append(g)
            strides.append(np.full((*g.shape[:2], 1), s))
        self._grids = np.concatenate(grids, 1)
        self._strides = np.concatenate(strides, 1)

    def detect(self, jpeg: bytes) -> tuple[list[Person], int]:
        cv2, np = self._cv2, self._np
        img = cv2.imdecode(np.frombuffer(jpeg, np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            raise ValueError("not a decodable image")
        rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        r = min(self.SIZE / rgb.shape[0], self.SIZE / rgb.shape[1])
        pad = np.full((self.SIZE, self.SIZE, 3), 114.0, np.float32)
        small = cv2.resize(rgb, (int(rgb.shape[1] * r), int(rgb.shape[0] * r))).astype(np.float32)
        pad[:small.shape[0], :small.shape[1]] = small
        with self._lock:
            self._net.setInput(np.transpose(pad, (2, 0, 1))[None])
            d = self._net.forward(self._net.getUnconnectedOutLayersNames())[0][0].copy()
        d[:, :2] = (d[:, :2] + self._grids) * self._strides
        d[:, 2:4] = np.exp(d[:, 2:4]) * self._strides
        score = d[:, 4] * d[:, 5 + PERSON_CLASS]
        xywh = np.stack([d[:, 0] - d[:, 2] / 2, d[:, 1] - d[:, 3] / 2, d[:, 2], d[:, 3]], 1)
        keep = np.array(cv2.dnn.NMSBoxes(xywh.tolist(), score.tolist(), MIN_SCORE, 0.5)).flatten()
        people = [Person(*(float(v) / r for v in xywh[i]), float(score[i])) for i in keep]
        return people, img.shape[0]


def evidence_image(jpeg: bytes, people: list[Person], height: int) -> bytes:
    """The frame with the counted people outlined, for the alarm."""
    from PIL import Image, ImageDraw
    img = Image.open(io.BytesIO(jpeg)).convert("RGB")
    draw = ImageDraw.Draw(img)
    width = max(3, img.height // 200)
    for p in near_door(people, height):
        draw.rectangle([p.x, p.y, p.x + p.w, p.y + p.h], outline=(239, 68, 68), width=width)
    out = io.BytesIO()
    img.save(out, "JPEG", quality=90)
    return out.getvalue()


@dataclass
class Session:
    door_id: int
    door_name: str
    event: dict[str, Any]
    total: int
    started: float
    frames: dict[int, tuple[int, bytes]] = field(default_factory=dict)  # index -> (ms, jpeg)


class WatchManager:
    """Collects each grant's frames and analyses them once all have arrived
    (or SESSION_TIMEOUT_S after the first, with whatever did)."""

    def __init__(self, store: Any, detector: PersonDetector, publish: Callable[[dict[str, Any]], None],
                 stamp: Callable[..., str]) -> None:
        self.store, self.detector, self.publish, self.stamp = store, detector, publish, stamp
        self._sessions: dict[tuple[int, int], Session] = {}
        self._done: OrderedDict[tuple[int, int], float] = OrderedDict()  # finished bursts, oldest first
        self._lock = threading.Lock()

    def add_frame(self, door_id: int, door_name: str, event: dict[str, Any], req: int, index: int, total: int,
                  ms: int, jpeg: bytes) -> bool:
        """Returns False if this frame was already received."""
        key = (door_id, req)
        with self._lock:
            if key in self._done:
                return False  # this burst was already analysed: a late or replayed frame
            s = self._sessions.get(key)
            if s is None:
                s = self._sessions[key] = Session(door_id, door_name, event, total, time.time())
                timer = threading.Timer(SESSION_TIMEOUT_S, self._finish, args=(key,))
                timer.daemon = True
                timer.start()
            if index in s.frames or total != s.total:
                return False
            s.frames[index] = (ms, jpeg)
            complete = len(s.frames) == s.total
        if complete:
            threading.Thread(target=self._finish, args=(key,), daemon=True).start()
        return True

    def _finish(self, key: tuple[int, int]) -> None:
        with self._lock:
            s = self._sessions.pop(key, None)
            if s is not None:
                self._done[key] = time.time()
                while len(self._done) > DONE_REMEMBERED:
                    self._done.popitem(last=False)
        if s is None:
            return  # already analysed
        try:
            self.analyse(s)
        except Exception as e:  # surfaced in the journal, never silently passed
            log.exception("door %d: tailgating analysis failed", s.door_id)
            ev = self.store.journal("watch.failed", door_id=s.door_id, req_ctr=s.event["req_ctr"],
                                    detail=f"tailgating analysis failed for event #{s.event['seq']}: {e}")
            self.publish({"type": "event", "event": ev})

    def credentials_used(self, s: Session, window_s: float) -> int:
        """Grants at this door around the unlock window: each is one person
        entitled to walk through."""
        ts = s.event["ts"]
        r = self.store.q1("SELECT COUNT(*) n FROM events WHERE door_id=? AND kind='access.granted' "
                          "AND ts BETWEEN ? AND ?", (s.door_id, ts - window_s, ts + window_s))
        return max(1, r["n"])

    def analyse(self, s: Session) -> dict[str, Any]:
        ordered = sorted(s.frames.items())
        frames, digests = [], []
        for index, (ms, jpeg) in ordered:
            people, height = self.detector.detect(jpeg)
            frames.append(Frame(index, ms, people, height))
            digests.append(hashlib.sha256(jpeg).digest())
        window_s = (max((f.ms for f in frames), default=0) / 1000) + CREDENTIAL_SLACK_S
        a = assess(frames, self.credentials_used(s, window_s))
        chain = hashlib.sha256(b"".join(digests)).hexdigest()
        missing = s.total - len(frames)
        note = f"{len(frames)} frames analysed" + (f", {missing} missing" if missing else "") + f", frames sha256={chain}"
        ev0 = s.event
        if a.tailgating:
            ev = self.store.journal("door.tailgating", door_id=s.door_id, cardholder_id=ev0["cardholder_id"],
                                    req_ctr=ev0["req_ctr"],
                                    detail=f"{a.max_people} people at {s.door_name} on {a.allowed} credential(s) "
                                           f"after event #{ev0['seq']}; extra person in {a.frames_over} frames; {note}")
            worst = frames[a.worst]
            jpeg = evidence_image(s.frames[worst.index][1], worst.people, worst.height)
            rel = self.stamp(self.store.data_dir / "photos", jpeg, ev["seq"], ev["ts"], s.door_name,
                             f"TAILGATING - {a.max_people} people, {a.allowed} credential(s)")
            self.store.x("UPDATE events SET photo=? WHERE seq=?", (rel, ev["seq"]))
            ev["photo"] = rel
            al = self.store.raise_alarm(2, "door.tailgating",
                                        f"Tailgating at {s.door_name}: {a.max_people} people on "
                                        f"{a.allowed} credential{'s' if a.allowed != 1 else ''}",
                                        door_id=s.door_id, event_seq=ev["seq"])
            self.publish({"type": "alarm", "alarm": al})
        else:
            ev = self.store.journal("door.passage", door_id=s.door_id, cardholder_id=ev0["cardholder_id"],
                                    req_ctr=ev0["req_ctr"],
                                    detail=f"{a.max_people} {'person' if a.max_people == 1 else 'people'} at "
                                           f"{s.door_name} on {a.allowed} credential(s) after event #{ev0['seq']}; "
                                           f"{note}")
        self.publish({"type": "event", "event": ev})
        log.info("door %d event #%d: %s (counts %s)", s.door_id, ev0["seq"],
                 "TAILGATING" if a.tailgating else "ok", a.counts)
        return {"event": ev, "assessment": a}
