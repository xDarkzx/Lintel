"""Operator-facing hardening: TOTP second factor, login throttling, TLS
certificate bootstrap and HTTP security headers."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import secrets
import socket
import struct
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# ---- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) --------------------------------------


def totp_new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def totp_now(secret: str, at: float | None = None) -> str:
    return _hotp(secret, int((time.time() if at is None else at) // 30))


def totp_verify(secret: str, code: str, at: float | None = None) -> int | None:
    """Returns the matched time step (for replay protection) or None. Allows one
    step of clock drift either side."""
    now = int((time.time() if at is None else at) // 30)
    code = code.strip().replace(" ", "")
    for step in (now - 1, now, now + 1):
        if hmac.compare_digest(_hotp(secret, step), code):
            return step
    return None


def totp_uri(secret: str, account: str, issuer: str = "Lintel") -> str:
    return f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&digits=6&period=30"


# ---- login throttling ------------------------------------------------------------------

LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_S = 15 * 60


LOGIN_MAX_TRACKED = 10_000  # names and addresses remembered at once


@dataclass
class LoginThrottle:
    """Per-username and per-address failure counting. A locked name or address
    is refused before the password is even checked.

    Sign-ins run on parallel worker threads, so every update holds a lock: two
    wrong passwords at the same instant must both count. Entries are kept in
    order of last activity, so expiry and eviction cost O(1) per sign-in and no
    more than LOGIN_MAX_TRACKED are kept: guessing with random names cannot
    grow memory or slow sign-in down."""
    failures: OrderedDict = field(default_factory=OrderedDict)  # key -> failure times, oldest activity first
    locked: OrderedDict = field(default_factory=OrderedDict)    # key -> locked until, in lock order
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def blocked(self, *keys: str, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            return max([0] + [int(self.locked.get(k, 0) - now) for k in keys])

    def fail(self, *keys: str, now: float | None = None) -> bool:
        """Records a failure; True when this failure triggered a lock."""
        now = time.time() if now is None else now
        tripped = False
        with self._lock:
            self._prune(now)
            for k in keys:
                if self.locked.get(k, 0) > now:
                    continue  # already locked: more failures change nothing and must not pile up
                recent = [t for t in self.failures.get(k, []) if now - t < LOGIN_LOCK_S] + [now]
                self.failures[k] = recent
                self.failures.move_to_end(k)
                if len(recent) >= LOGIN_MAX_FAILURES:
                    self.locked[k] = now + LOGIN_LOCK_S
                    self.locked.move_to_end(k)
                    self.failures[k] = []
                    tripped = True
            while len(self.failures) > LOGIN_MAX_TRACKED:
                self.failures.popitem(last=False)
            while len(self.locked) > LOGIN_MAX_TRACKED:
                self.locked.popitem(last=False)
        return tripped

    def succeed(self, *keys: str) -> None:
        with self._lock:
            for k in keys:
                self.failures.pop(k, None)

    def _prune(self, now: float) -> None:
        # Both maps are ordered oldest first, so expired entries are all at the front.
        while self.failures:
            k, ts = next(iter(self.failures.items()))
            if ts and now - ts[-1] < LOGIN_LOCK_S:
                break
            del self.failures[k]
        while self.locked:
            k, until = next(iter(self.locked.items()))
            if until > now:
                break
            del self.locked[k]

    def size(self) -> int:
        with self._lock:
            return len(self.failures) + len(self.locked)


# ---- request size limit ---------------------------------------------------------------------

MAX_BODY_BYTES = 25_000_000  # the largest legitimate upload is a 20 MB floor plan


class BodyLimit:
    """ASGI middleware refusing request bodies over MAX_BODY_BYTES before any
    handler reads them, whether or not the client declared a length: a client
    cannot make the server buffer gigabytes into memory."""

    def __init__(self, app, limit: int = MAX_BODY_BYTES) -> None:
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None:
            # The HTTP layer enforces the declared length, so checking it is enough.
            if not declared.isdigit() or int(declared) > self.limit:
                return await _too_large(send)
            return await self.app(scope, receive, send)
        # No declared length (chunked): read it here, up to the limit, then
        # hand the app the whole body. Over the limit, the app never runs.
        chunks, seen = [], 0
        while True:
            msg = await receive()
            if msg["type"] != "http.request":
                return await self.app(scope, _replay([msg], receive), send)
            seen += len(msg.get("body", b""))
            if seen > self.limit:
                return await _too_large(send)
            chunks.append(msg.get("body", b""))
            if not msg.get("more_body"):
                break
        await self.app(scope, _replay([{"type": "http.request", "body": b"".join(chunks), "more_body": False}],
                                      receive), send)


def _replay(messages, upstream):
    """Hands the app the buffered messages, then the real connection, so
    streaming responses still learn when the client actually goes away."""
    pending = list(messages)

    async def receive():
        if pending:
            return pending.pop(0)
        return await upstream()
    return receive


async def _too_large(send) -> None:
    body = b'{"detail":"request body too large"}'
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


# ---- TLS ----------------------------------------------------------------------------------


def ensure_tls(directory: Path) -> tuple[Path, Path, str]:
    """Creates a long-lived self-signed P-256 certificate on first run.
    Returns (cert, key, sha256 fingerprint). Controllers pin the fingerprint."""
    directory.mkdir(parents=True, exist_ok=True)
    cert_p, key_p = directory / "server.crt", directory / "server.key"
    if not cert_p.exists() or not key_p.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        host = socket.gethostname()
        names = [x509.DNSName("localhost"), x509.DNSName(host), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Lintel server ({host})"),
                             x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lintel")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName(names), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        key_p.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
        cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cert = x509.load_pem_x509_certificate(cert_p.read_bytes())
    fp = cert.fingerprint(hashes.SHA256()).hex()
    return cert_p, key_p, fp


SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
                                "script-src 'self'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; "
                                "base-uri 'none'; form-action 'self'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    # The console's own pages may use the camera, for guided face enrolment;
    # nothing embedded or third-party can.
    "Permissions-Policy": "camera=(self), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",  # no other site may embed our photos or plans
}
