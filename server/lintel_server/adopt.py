"""Device adoption, server side. Mirrors components/lintel_core/src/adopt.cpp."""

from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

LABEL = b"lintel-adopt-v1"
BLOB_LEN = 32 + 4 + 22 + 8


def pairing_code(panel_pk: bytes) -> str:
    return f"{struct.unpack('<I', hashlib.sha256(panel_pk).digest()[:4])[0] % 1_000_000:06d}"


def seal(panel_pk: bytes, door_id: int, net_id: int, key: bytes, seq: int, eph_sk: bytes | None = None) -> bytes:
    eph = X25519PrivateKey.from_private_bytes(eph_sk) if eph_sk else X25519PrivateKey.generate()
    eph_pk = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(panel_pk))
    k = hmac.new(shared, LABEL + panel_pk + eph_pk, hashlib.sha256).digest()[:16]
    head = eph_pk + struct.pack("<I", seq)
    body = struct.pack("<HI", door_id, net_id) + key
    return head + AESCCM(k, tag_length=8).encrypt(bytes(13), body, head)
