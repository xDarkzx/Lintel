"""Depth liveness for Lintel Vision faces: real faces have relief, photos and screens are flat."""

import io

import numpy as np
import pytest
from PIL import Image

from lintel_server.depth import judge_depth, read_depth_patch


def face(dist=800, bump=40):
    """A 64 x 64 depth patch shaped like a face: nose and cheeks nearer than the edges."""
    y, x = np.mgrid[-1:1:64j, -1:1:64j]
    return (dist - bump * np.sqrt(np.clip(1 - x ** 2 - y ** 2, 0, 1))).astype(np.uint16)


def png16(a):
    buf = io.BytesIO()
    Image.fromarray(a.astype(np.uint16)).save(buf, "PNG")
    return buf.getvalue()


def test_a_real_face_shape_passes():
    assert judge_depth(face()) == (True, "")


def test_a_flat_tilted_photo_is_refused():
    y, x = np.mgrid[0:64, 0:64]
    ok, why = judge_depth((700 + 2 * x + y).astype(np.uint16))
    assert not ok and "flat" in why


def test_too_far_mostly_empty_or_not_a_face_are_refused():
    assert judge_depth(face(dist=4000))[0] is False
    sparse = face()
    sparse[:, :40] = 0
    assert judge_depth(sparse)[0] is False
    deep = face()
    deep[:, 32:] += 600
    assert judge_depth(deep)[0] is False


def test_patch_format_is_checked():
    buf = io.BytesIO()
    Image.fromarray(np.zeros((64, 64), np.uint8)).save(buf, "PNG")
    with pytest.raises(ValueError):
        read_depth_patch(buf.getvalue())  # 8-bit, not millimetres
    with pytest.raises(ValueError):
        read_depth_patch(png16(np.zeros((200, 200), np.uint16)))  # too large
    with pytest.raises(ValueError):
        read_depth_patch(b"not a png")
    got = read_depth_patch(png16(face()))
    assert got.dtype == np.uint16 and (got == face()).all()
