"""Wire format shared with the C++ core (components/lintel_core).

A frame is an 8-byte cleartext header, authenticated as AAD, then an
AES-128-CCM payload with an 8-byte tag. The nonce binds door, direction,
counter and network, exactly as in frame.cpp.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

PROTO_VERSION = 1
HEADER_LEN = 8
TAG_LEN = 8
MAX_PAYLOAD = 200
MAX_FRAME = HEADER_LEN + MAX_PAYLOAD + TAG_LEN
BROADCAST_DOOR = 0xFFFF


class MsgType(IntEnum):
    ACCESS_REQ = 1
    ACCESS_RESP = 2
    HEARTBEAT = 3
    HEARTBEAT_ACK = 4
    EVENT = 5
    MODE = 6
    CACHE_CHUNK = 7
    PIN_REQ = 8
    PIN_RESP = 9


class Dir(IntEnum):
    DOOR_TO_CTRL = 0
    CTRL_TO_DOOR = 1
    BROADCAST = 2


_UPLINK = {MsgType.ACCESS_REQ, MsgType.HEARTBEAT, MsgType.EVENT, MsgType.PIN_REQ}


def dir_for(t: MsgType) -> Dir:
    if t in _UPLINK:
        return Dir.DOOR_TO_CTRL
    if t == MsgType.MODE:
        return Dir.BROADCAST
    return Dir.CTRL_TO_DOOR


class Decision(IntEnum):
    DENY = 0
    GRANT = 1


class Reason(IntEnum):
    OK = 0
    MALFORMED = 1
    FORGED = 2
    CARD_REPLAY = 3
    UNKNOWN_CARD = 4
    REVOKED = 5
    DOOR_NOT_ALLOWED = 6
    OUTSIDE_SCHEDULE = 7
    LOCKDOWN = 8
    OFFLINE = 9
    BAD_PIN = 10
    LOCKED_OUT = 11


class SiteMode(IntEnum):
    NORMAL = 0
    LOCKDOWN = 1
    FREE_ACCESS = 2


@dataclass(frozen=True)
class Header:
    type: MsgType
    flags: int
    door_id: int
    counter: int

    def pack(self) -> bytes:
        return struct.pack("<BBHI", (PROTO_VERSION << 4) | int(self.type), self.flags, self.door_id, self.counter)


class FrameError(Exception):
    """Raised for anything that is not a valid, authentic frame."""


def _nonce(h: Header, net_id: int) -> bytes:
    return struct.pack("<HBII", h.door_id, int(dir_for(h.type)), h.counter, net_id) + b"\x00\x00"


def peek_header(frame: bytes) -> Header:
    if not (HEADER_LEN + TAG_LEN <= len(frame) <= MAX_FRAME):
        raise FrameError("bad length")
    b0, flags, door_id, counter = struct.unpack_from("<BBHI", frame)
    if b0 >> 4 != PROTO_VERSION:
        raise FrameError("bad version")
    try:
        t = MsgType(b0 & 0x0F)
    except ValueError as e:
        raise FrameError("bad type") from e
    if (dir_for(t) == Dir.BROADCAST) != (door_id == BROADCAST_DOOR):
        raise FrameError("bad broadcast address")
    return Header(t, flags, door_id, counter)


def seal(key: bytes, net_id: int, h: Header, payload: bytes) -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise FrameError("payload too long")
    aad = h.pack()
    return aad + AESCCM(key, tag_length=TAG_LEN).encrypt(_nonce(h, net_id), payload, aad)


def open_frame(key: bytes, net_id: int, frame: bytes) -> tuple[Header, bytes]:
    h = peek_header(frame)
    try:
        pt = AESCCM(key, tag_length=TAG_LEN).decrypt(_nonce(h, net_id), frame[HEADER_LEN:], frame[:HEADER_LEN])
    except InvalidTag as e:
        raise FrameError("authentication failed") from e
    return h, pt


# ---- payloads (fixed sizes, mirror messages.cpp) -------------------------------

PIN_MAX = 8
NAME_MAX = 16


@dataclass
class PinReq:
    pin: str
    status: int

    @staticmethod
    def decode(p: bytes) -> "PinReq":
        if len(p) != 1 + PIN_MAX + 1:
            raise FrameError("PinReq length")
        n = p[0]
        if not 4 <= n <= PIN_MAX:
            raise FrameError("PinReq pin length")
        digits = p[1 : 1 + n]
        if not digits.isdigit() or any(p[1 + n : 1 + PIN_MAX]):
            raise FrameError("PinReq pin chars")
        return PinReq(digits.decode(), p[1 + PIN_MAX])


@dataclass
class PinResp:
    req_counter: int
    decision: Decision
    reason: Reason
    unlock_ms: int = 0
    lockout_s: int = 0
    name: str = ""

    def encode(self) -> bytes:
        name = self.name.encode()[: NAME_MAX - 1].ljust(NAME_MAX, b"\x00")
        return struct.pack("<IBBHH", self.req_counter, self.decision, self.reason, self.unlock_ms, self.lockout_s) + name


@dataclass
class Heartbeat:
    status: int
    cache_version: int
    last_rssi: int
    battery_mv: int
    uptime_s: int
    pending_events: int

    @staticmethod
    def decode(p: bytes) -> "Heartbeat":
        if len(p) != 11:
            raise FrameError("Heartbeat length")
        return Heartbeat(*struct.unpack("<BHbHIB", p))


@dataclass
class HeartbeatAck:
    mode: SiteMode
    cache_version: int
    time: int
    hb_counter: int

    def encode(self) -> bytes:
        return struct.pack("<BHII", self.mode, self.cache_version, self.time, self.hb_counter)


class ReplayWindow:
    """64-wide sliding window, same semantics as counters.cpp."""

    WINDOW = 64

    def __init__(self, highest: int = 0) -> None:
        self.highest = highest
        self.bitmap = (1 << self.WINDOW) - 1 if highest else 0

    def accepts(self, c: int) -> bool:
        if c == 0:
            return False
        if self.highest == 0 or c > self.highest:
            return True
        age = self.highest - c
        return age < self.WINDOW and not (self.bitmap >> age) & 1

    def commit(self, c: int) -> None:
        if not self.accepts(c):
            return
        if c > self.highest:
            shift = c - self.highest
            self.bitmap = ((self.bitmap << shift) | 1) & ((1 << self.WINDOW) - 1) if shift < self.WINDOW else 1
            self.highest = c
        else:
            self.bitmap |= 1 << (self.highest - c)
