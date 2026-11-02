"""A simulated Lintel Vision unit.

It speaks the real protocol (sealed UDP frames and signed HTTPS uploads), so
the server's walk-through behaviour can be built and tested before the
hardware exists, and so the unit's own software has a reference to match:
whatever this class sends, the real unit sends.

The caller supplies the transport: `deliver(frame) -> reply frame or None`
for the sealed UDP link, and `post(path, body, headers) -> (status, json)`
for HTTPS, so the same unit runs in-process in tests or against a server.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import secrets
import struct
from dataclasses import dataclass
from typing import Callable

import numpy as np
from PIL import Image

from .controller import photo_key
from .protocol import (CRED_FACE, PIN_MAX, UID_MAX, Crossing, CrossingAck, Decision, FrameError, Header, MsgType,
                       Reason, open_frame, seal)


@dataclass
class PinResult:
    decision: Decision
    reason: Reason
    name: str
    unlock_ms: int


def depth_face_png(dist_mm: int = 800) -> bytes:
    """A depth patch shaped like a live face."""
    y, x = np.mgrid[-1:1:64j, -1:1:64j]
    return _png16(dist_mm - 40 * np.sqrt(np.clip(1 - x ** 2 - y ** 2, 0, 1)))


def depth_flat_png() -> bytes:
    """A depth patch of a photo or screen held up: flat, slightly tilted."""
    y, x = np.mgrid[-1:1:64j, -1:1:64j]
    return _png16(700 + 60 * x + 30 * y)


def _png16(a: np.ndarray) -> bytes:
    buf = io.BytesIO()
    Image.fromarray(a.astype(np.uint16)).save(buf, "PNG")
    return buf.getvalue()


class VisionUnit:
    def __init__(self, door_id: int, key: bytes, net_id: int, deliver: Callable[[bytes], bytes | None],
                 post: Callable[[str, bytes, dict[str, str]], tuple[int, dict]]) -> None:
        self.door, self.key, self.net = door_id, key, net_id
        self.deliver, self.post = deliver, post
        self.ctr = 0
        # Passage ids are multiples of 256; a random start keeps a restarted
        # unit from reusing one the server still remembers.
        self.passage = secrets.randbits(23) << 8

    def start_passage(self) -> int:
        self.passage = (self.passage + 0x100) & 0xFFFFFF00 or 0x100
        return self.passage

    def present(self, track: int, jpeg: bytes, depth_png: bytes) -> PinResult:
        """One tracked person: upload their face and depth, then ask for a decision."""
        if not 1 <= track <= 255:
            raise ValueError("track must be 1-255")
        ref = self.passage | track
        mac = hmac.new(photo_key(self.key), f"walkface:{self.door}:{ref}:".encode() + hashlib.sha256(jpeg).digest()
                       + hashlib.sha256(depth_png).digest(), hashlib.sha256).hexdigest()
        status, _ = self.post(f"/api/door/{self.door}/walk/face", struct.pack("<I", len(jpeg)) + jpeg + depth_png,
                              {"x-lintel-req": str(ref), "x-lintel-mac": mac})
        if status != 200:
            raise RuntimeError(f"face upload refused: HTTP {status}")
        payload = bytes([CRED_FACE, 0]) + bytes(UID_MAX) + bytes([0]) + bytes(PIN_MAX) + struct.pack("<I", ref)
        return self._decision(self._exchange(MsgType.CRED_REQ, payload, MsgType.PIN_RESP))

    def pin(self, pin: str) -> PinResult:
        """The fallback PIN pad on the unit's touchscreen."""
        payload = bytes([len(pin)]) + pin.encode().ljust(PIN_MAX, b"\x00") + bytes([0])
        return self._decision(self._exchange(MsgType.PIN_REQ, payload, MsgType.PIN_RESP))

    def heartbeat(self, uptime_s: int = 0) -> None:
        """Tells the server the unit is alive; the reply carries the door's mode."""
        payload = struct.pack("<BHbHIB", 0, 0, 0, 0, uptime_s, 0)
        self._exchange(MsgType.HEARTBEAT, payload, MsgType.HEARTBEAT_ACK)

    def crossed(self, entered: int, tracks: list[int], overhead: bool = False) -> CrossingAck:
        """The door has closed: report how many went in and which tracks they were."""
        c = Crossing(self.passage, entered, overhead, tuple(self.passage | t for t in tracks))
        return CrossingAck.decode(self._exchange(MsgType.CROSSING, c.encode(), MsgType.CROSSING_ACK))

    def _exchange(self, t: MsgType, payload: bytes, want: MsgType) -> bytes:
        self.ctr += 1
        reply = self.deliver(seal(self.key, self.net, Header(t, 0, self.door, self.ctr), payload))
        if reply is None:
            raise TimeoutError(f"no reply to {t.name}")
        h, pt = open_frame(self.key, self.net, reply)
        if h.type != want:
            raise FrameError(f"expected {want.name}, got {h.type.name}")
        return pt

    @staticmethod
    def _decision(pt: bytes) -> PinResult:
        _, dec, reason, unlock_ms, _ = struct.unpack_from("<IBBHH", pt)
        return PinResult(Decision(dec), Reason(reason), pt[10:].rstrip(b"\x00").decode(), unlock_ms)
