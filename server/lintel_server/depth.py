"""Depth liveness for Lintel Vision.

A Lintel Vision unit sends, with each face crop, the matching patch of its
depth camera: 16-bit greyscale, one value per pixel in millimetres, 0 where
the camera has no reading. The server judges it here, so a unit (or anything
relaying for it) cannot simply declare a face live.

A printed photo or a screen is flat: every point lies close to one plane,
however it is tilted. A real face has relief (nose, cheeks, eye sockets) of
a few centimetres, and sits at a distance a person stands from a door.
"""

from __future__ import annotations

import io

import numpy as np
from PIL import Image

PATCH_MAX = 128           # pixels per side
MIN_VALID = 0.60          # share of pixels with a depth reading
NEAREST_MM, FARTHEST_MM = 300, 2500
MIN_RELIEF_RMS_MM = 4.0   # distance from the best-fit plane; a photo or screen is below this
MAX_SPAN_MM = 150         # 5th to 95th percentile; more than this is not one face


def read_depth_patch(png: bytes) -> np.ndarray:
    """The patch as uint16 millimetres; ValueError unless it is a 16-bit
    greyscale PNG of at most PATCH_MAX x PATCH_MAX pixels."""
    try:
        img = Image.open(io.BytesIO(png))
        if img.format != "PNG" or img.mode not in ("I;16", "I;16B", "I;16L", "I"):
            raise ValueError("depth patch must be a 16-bit greyscale PNG")
        if img.width > PATCH_MAX or img.height > PATCH_MAX:  # checked before the pixels are decoded
            raise ValueError("depth patch too large")
        a = np.asarray(img)
    except ValueError:
        raise
    except Exception as e:  # Pillow raises several types for a file it cannot read
        raise ValueError("depth patch is not a readable PNG") from e
    if a.ndim != 2 or a.min(initial=0) < 0 or a.max(initial=0) > 0xFFFF:
        raise ValueError("depth patch must be 16-bit greyscale")
    return a.astype(np.uint16)


def judge_depth(depth: np.ndarray) -> tuple[bool, str]:
    """(True, "") for a patch shaped like a live face, else (False, why)."""
    valid = depth > 0
    if valid.mean() < MIN_VALID:
        return False, "too little depth on the face"
    z = depth[valid].astype(np.float64)
    median = float(np.median(z))
    if not NEAREST_MM <= median <= FARTHEST_MM:
        return False, f"face at {median:.0f} mm, not where a person stands"
    lo, hi = np.percentile(z, [5, 95])
    if hi - lo > MAX_SPAN_MM:
        return False, "depth spans more than one face"
    ys, xs = np.nonzero(valid)
    a = np.column_stack([xs, ys, np.ones_like(xs)]).astype(np.float64)
    coef, *_ = np.linalg.lstsq(a, z, rcond=None)
    rms = float(np.sqrt(np.mean((z - a @ coef) ** 2)))
    if rms < MIN_RELIEF_RMS_MM:
        return False, f"flat, like a photo or screen ({rms:.1f} mm relief)"
    return True, ""
