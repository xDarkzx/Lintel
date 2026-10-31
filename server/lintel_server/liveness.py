"""Guided face enrolment with liveness checks, in the style of identity
verification services such as Persona: the person follows on-screen steps in
front of a camera and only a live, consistent face is enrolled.

Two independent checks, both decided on the server so a modified browser
cannot skip them:

- Passive: every frame goes through Minivision's Silent-Face anti-spoofing
  models (MiniFASNetV2 at 2.7x the face box and MiniFASNetV1SE at 4.0x,
  Apache-2.0, converted to ONNX by tools/export_antispoof.py). They are
  trained to tell a live face from a printed photo or a screen.
- Active: the person is asked to look straight ahead and turn their head left
  and right, in an order chosen at random per session, so a pre-recorded
  video is unlikely to show the right movement at the right time.

The same face must stay in view throughout; templates are taken only from
the straight-ahead steps, where face recognition is most reliable.

Limits, stated plainly: this is not an ISO/IEC 30107-3 certified presentation
attack detector, and a high-quality 3D mask could pass. It raises the bar
from "any photo works" to "a live person was present and followed
instructions", which is what enrolment needs.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import cv2
import numpy as np

from .faces import FaceEngine, FaceError

ANTISPOOF = (("antispoof_2.7_80x80_minifasnetv2.onnx", 2.7), ("antispoof_4.0_80x80_minifasnetv1se.onnx", 4.0))
REAL_MIN = 0.80          # mean "live" probability a frame needs
SPOOF_FRAMES_FAIL = 4    # frames judged not live before the session fails
FRONT_MAX_YAW = 0.12     # |yaw ratio| for "looking straight ahead"
TURN_MIN_YAW = 0.28      # |yaw ratio| for a clear head turn
STEP_FRAMES = 2          # consecutive qualifying frames to complete a step
SAME_FACE_FRONT = 0.45   # similarity to the first straight-ahead frame
SAME_FACE_TURNED = 0.25  # turned faces embed less reliably
MISMATCH_FAIL = 2
MIN_SHARPNESS = 25.0     # variance of the Laplacian over the face
SESSION_S = 90
MAX_FRAMES = 400
MAX_TEMPLATES = 3

INSTRUCTIONS = {"front": "Look straight at the camera",
                "left": "Slowly turn your head to your left",
                "right": "Slowly turn your head to your right"}


def crop_scaled(img: np.ndarray, box: tuple[int, int, int, int], scale: float) -> np.ndarray:
    """The face box grown by `scale` around its centre and kept inside the
    image, resized to 80x80: Minivision's CropImage, which the models were
    trained with."""
    H, W = img.shape[:2]
    x, y, w, h = box
    scale = min((H - 1) / h, (W - 1) / w, scale)
    nw, nh = w * scale, h * scale
    cx, cy = x + w / 2, y + h / 2
    left, top, right, bottom = cx - nw / 2, cy - nh / 2, cx + nw / 2, cy + nh / 2
    if left < 0:
        right -= left
        left = 0
    if top < 0:
        bottom -= top
        top = 0
    if right > W - 1:
        left -= right - W + 1
        right = W - 1
    if bottom > H - 1:
        top -= bottom - H + 1
        bottom = H - 1
    return cv2.resize(img[int(top):int(bottom) + 1, int(left):int(right) + 1], (80, 80))


class PassiveLiveness:
    def __init__(self, models: Path) -> None:
        self._nets = []
        for name, scale in ANTISPOOF:
            path = models / name
            if not path.exists():
                raise FileNotFoundError(f"anti-spoofing model missing: {path}")
            self._nets.append((cv2.dnn.readNetFromONNX(str(path)), scale))
        self._lock = threading.Lock()

    def score(self, img: np.ndarray, box: tuple[int, int, int, int]) -> float:
        """Probability the face is live, averaged over both models. Input is
        raw BGR 0..255, as upstream feeds it (no /255 scaling)."""
        total = 0.0
        with self._lock:
            for net, scale in self._nets:
                x = crop_scaled(img, box, scale).astype(np.float32).transpose(2, 0, 1)[None]
                net.setInput(x)
                z = net.forward()[0]
                p = np.exp(z - z.max())
                total += float(p[1] / p.sum())  # class 1 is "real"
        return total / len(self._nets)


def yaw_ratio(landmarks: np.ndarray) -> float:
    """Horizontal offset of the nose from the midpoint of the eyes, in units
    of the distance between the eyes. About 0 looking straight ahead; positive
    when the person turns to their left (their nose moves to the camera's
    right in an unmirrored image)."""
    right_eye, left_eye, nose = landmarks[0], landmarks[1], landmarks[2]
    eyes = float(np.linalg.norm(left_eye - right_eye)) or 1.0
    return float(nose[0] - (right_eye[0] + left_eye[0]) / 2) / eyes


def step_met(step: str, yaw: float) -> bool:
    if step == "front":
        return abs(yaw) <= FRONT_MAX_YAW
    if step == "left":
        return yaw >= TURN_MIN_YAW
    return yaw <= -TURN_MIN_YAW


@dataclass
class Enrolment:
    id: str
    cardholder_id: int
    operator: str
    steps: list[str]
    started: float = field(default_factory=time.time)
    step: int = 0
    streak: int = 0
    state: str = "active"            # active, done, failed
    message: str = ""
    frames: int = 0
    spoof_frames: int = 0
    mismatches: int = 0
    anchor: np.ndarray | None = None
    templates: list[tuple[float, int, np.ndarray]] = field(default_factory=list)  # (quality, step, embedding)
    real_scores: list[float] = field(default_factory=list)
    logged: bool = False  # the failure has been written to the journal

    def view(self) -> dict:
        current = self.steps[self.step] if self.step < len(self.steps) else None
        return {"id": self.id, "state": self.state, "step": self.step, "steps": self.steps,
                "instruction": INSTRUCTIONS.get(current, "") if self.state == "active" else "",
                "message": self.message}


def new_steps() -> list[str]:
    turns = ["left", "right"]
    if secrets.randbelow(2):
        turns.reverse()
    return ["front", *turns, "front"]


def sharpness(img: np.ndarray, box: tuple[int, int, int, int]) -> float:
    x, y, w, h = box
    face = img[max(0, y):y + h, max(0, x):x + w]
    if face.size == 0:
        return 0.0
    return float(cv2.Laplacian(cv2.cvtColor(face, cv2.COLOR_BGR2GRAY), cv2.CV_64F).var())


class EnrolmentService:
    def __init__(self, faces: FaceEngine, live: PassiveLiveness) -> None:
        self.faces, self.live = faces, live
        self.sessions: dict[str, Enrolment] = {}
        self._lock = threading.Lock()

    def start(self, cardholder_id: int, operator: str) -> Enrolment:
        now = time.time()
        with self._lock:
            for k in [k for k, s in self.sessions.items() if now - s.started > SESSION_S * 2]:
                del self.sessions[k]
            e = Enrolment(secrets.token_urlsafe(16), cardholder_id, operator, new_steps())
            self.sessions[e.id] = e
        return e

    def get(self, sid: str) -> Enrolment | None:
        return self.sessions.get(sid)

    def _fail(self, e: Enrolment, why: str) -> Enrolment:
        e.state, e.message = "failed", why
        return e

    def frame(self, e: Enrolment, jpeg: bytes) -> Enrolment:
        if e.state != "active":
            return e
        e.frames += 1
        if time.time() - e.started > SESSION_S or e.frames > MAX_FRAMES:
            return self._fail(e, "Timed out. Start again and follow the steps on screen.")
        img = cv2.imdecode(np.frombuffer(jpeg, np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            e.message = "Camera frame unreadable"
            return e
        try:
            r = self.faces.analyse(jpeg)
        except FaceError as err:
            e.streak = 0
            e.message = {"no face found": "Move into the frame so your whole face is visible",
                         "more than one face in view": "Only one person should be in view",
                         "face too small; step closer": "Move closer to the camera"}.get(str(err), str(err))
            return e
        real = self.live.score(img, r.box)
        e.real_scores.append(real)
        if real < REAL_MIN:
            e.spoof_frames += 1
            e.streak = 0
            if e.spoof_frames >= SPOOF_FRAMES_FAIL:
                return self._fail(e, "Liveness check failed: this looks like a photo or a screen, not a live face.")
            e.message = "Hold still and face the camera in good light"
            return e
        if sharpness(img, r.box) < MIN_SHARPNESS:
            e.streak = 0
            e.message = "Too blurry. Hold still for a moment"
            return e
        step = e.steps[e.step]
        if e.anchor is not None:
            same = float(np.dot(r.embedding, e.anchor))
            if same < (SAME_FACE_FRONT if step == "front" else SAME_FACE_TURNED):
                e.mismatches += 1
                e.streak = 0
                if e.mismatches >= MISMATCH_FAIL:
                    return self._fail(e, "A different face appeared during enrolment. Start again with one person.")
                e.message = "Keep your face in view"
                return e
        yaw = yaw_ratio(r.landmarks)
        if not step_met(step, yaw):
            e.streak = 0
            e.message = INSTRUCTIONS[step]
            return e
        if step == "front":
            if e.anchor is None:
                e.anchor = r.embedding
            e.templates.append((r.detect_score * real, e.step, r.embedding))
        e.streak += 1
        e.message = "Hold it there"
        if e.streak >= STEP_FRAMES:
            e.step += 1
            e.streak = 0
            e.message = "Done" if e.step == len(e.steps) else "Good"
            if e.step == len(e.steps):
                e.state = "done"
        return e

    @staticmethod
    def chosen_templates(e: Enrolment) -> list[np.ndarray]:
        """The best straight-ahead frame from each front step, then the next
        best, up to MAX_TEMPLATES."""
        ranked = sorted(e.templates, key=lambda t: t[0], reverse=True)
        out, steps = [], set()
        for q, step, emb in ranked:
            if step not in steps:
                out.append(emb)
                steps.add(step)
        for q, step, emb in ranked:
            if len(out) >= MAX_TEMPLATES:
                break
            if not any(emb is o for o in out):
                out.append(emb)
        return out[:MAX_TEMPLATES]
