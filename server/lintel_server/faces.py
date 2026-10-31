"""Face recognition: OpenCV YuNet (detection) + SFace (128-d embeddings).

Both models are from the OpenCV model zoo, Apache-2.0, and run on a CPU in a
few tens of milliseconds, so a Pi-class server can do this too.

What this is and is not: a single RGB camera cannot tell a live face from a
good photo of one. Doors in "face" mode are a convenience tier; "face + PIN"
is the secure tier, and the dashboard says so.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path

import cv2
import numpy as np

log = logging.getLogger("lintel.faces")

DETECTOR = "face_detection_yunet_2023mar.onnx"
RECOGNIZER = "face_recognition_sface_2021dec.onnx"

# OpenCV's published SFace cosine threshold is 0.363; access control errs
# towards refusing, so require a clearer match.
MATCH_THRESHOLD = 0.42
MIN_FACE_PX = 90
MIN_DETECT_SCORE = 0.85


class FaceError(Exception):
    """A problem with the image: no face, too small, too many faces."""


@dataclass
class FaceResult:
    embedding: np.ndarray  # unit-length float32[128]
    box: tuple[int, int, int, int]
    detect_score: float
    # Five points in image pixels: right eye, left eye, nose tip, right and
    # left mouth corners (YuNet's order; "right" is the person's right).
    landmarks: np.ndarray | None = None


class FaceEngine:
    def __init__(self, models: Path) -> None:
        det, rec = models / DETECTOR, models / RECOGNIZER
        if not det.exists() or not rec.exists():
            raise FileNotFoundError(f"face models missing in {models}; run scripts/fetch_face_models.sh")
        self._det = cv2.FaceDetectorYN.create(str(det), "", (320, 320), MIN_DETECT_SCORE, 0.3, 5000)
        self._rec = cv2.FaceRecognizerSF.create(str(rec), "")
        self._clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        self._lock = threading.Lock()  # the OpenCV objects are not thread-safe

    def analyse(self, jpeg: bytes) -> FaceResult:
        img = cv2.imdecode(np.frombuffer(jpeg, np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            raise FaceError("not a decodable image")
        # Even out lighting first: door cameras face bright windows and corridors,
        # and backlit faces are the common failure. Applied to enrolment and
        # checks alike, so templates and probes stay comparable.
        ycc = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
        ycc[:, :, 0] = self._clahe.apply(ycc[:, :, 0])
        img = cv2.cvtColor(ycc, cv2.COLOR_YCrCb2BGR)
        # YuNet works best on modest input sizes; faces at a door fill the frame.
        h, w = img.shape[:2]
        scale = min(1.0, 640 / max(h, w))
        small = cv2.resize(img, (int(w * scale), int(h * scale))) if scale < 1.0 else img
        with self._lock:
            self._det.setInputSize((small.shape[1], small.shape[0]))
            _, faces = self._det.detect(small)
            if faces is None or len(faces) == 0:
                raise FaceError("no face found")
            faces = sorted(faces, key=lambda f: f[2] * f[3], reverse=True)
            best = faces[0].copy()
            if len(faces) > 1 and faces[1][2] * faces[1][3] > 0.6 * best[2] * best[3]:
                raise FaceError("more than one face in view")
            best[:14] /= scale  # back to full-resolution coordinates
            if min(best[2], best[3]) < MIN_FACE_PX:
                raise FaceError("face too small; step closer")
            aligned = self._rec.alignCrop(img, best)
            feat = self._rec.feature(aligned).flatten().astype(np.float32)
        feat /= np.linalg.norm(feat) + 1e-9
        x, y, fw, fh = (int(v) for v in best[:4])
        return FaceResult(feat, (x, y, fw, fh), float(best[14]), best[4:14].reshape(5, 2).astype(np.float32))

    @staticmethod
    def best_match(probe: np.ndarray, templates: list[tuple[int, np.ndarray]]) -> tuple[int | None, float]:
        """Returns (cardholder_id, score) of the closest template, or (None, best score)."""
        best_id, best = None, -1.0
        for cid, t in templates:
            score = float(np.dot(probe, t))
            if score > best:
                best_id, best = cid, score
        return (best_id, best) if best >= MATCH_THRESHOLD else (None, best)
