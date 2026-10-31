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
import time
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


@dataclass
class LoginThrottle:
    """Per-username and per-address failure counting. A locked name or address
    is refused before the password is even checked."""
    failures: dict[str, list[float]] = field(default_factory=dict)
    locked: dict[str, float] = field(default_factory=dict)

    def blocked(self, *keys: str, now: float | None = None) -> int:
        now = time.time() if now is None else now
        return max([0] + [int(self.locked.get(k, 0) - now) for k in keys])

    def fail(self, *keys: str, now: float | None = None) -> bool:
        """Records a failure; True when this failure triggered a lock."""
        now = time.time() if now is None else now
        tripped = False
        for k in keys:
            recent = [t for t in self.failures.get(k, []) if now - t < LOGIN_LOCK_S] + [now]
            self.failures[k] = recent
            if len(recent) >= LOGIN_MAX_FAILURES and self.locked.get(k, 0) < now:
                self.locked[k] = now + LOGIN_LOCK_S
                self.failures[k] = []
                tripped = True
        return tripped

    def succeed(self, *keys: str) -> None:
        for k in keys:
            self.failures.pop(k, None)


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
}
