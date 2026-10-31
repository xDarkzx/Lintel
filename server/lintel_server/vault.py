"""Encryption at rest for the secrets the database holds: door keys, operators'
two-factor secrets, face templates, and sensitive settings.

Envelope encryption, as cloud key services do it:

- A master key (the key-encryption key) lives outside the database: in the
  file named by LINTEL_MASTER_KEY_FILE (a Docker secret, or a file a KMS or
  TPM unlocks at boot), in LINTEL_MASTER_KEY, or, for development only, in
  data/master.key with a warning.
- A random data key does the encrypting. It is stored in keyring.json only
  wrapped by the master key, so rotating the master key rewraps one small
  file and never re-encrypts the data.
- Every value is AES-256-GCM with a fresh nonce, and its additional data names
  exactly where it belongs (table, column, row). A door key copied into
  another door's row, or a face template moved to another person, fails to
  decrypt instead of quietly working.

A wrong or missing master key stops the server with an error. There is no
fallback to unencrypted storage.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger("lintel.vault")

MAGIC = b"LV1"
TEXT_PREFIX = "enc:"
KEY_LEN = 32


class VaultError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode(), validate=True)


def load_master_key(data_dir: Path) -> tuple[bytes, str]:
    """Returns (master key, where it came from)."""
    path = os.environ.get("LINTEL_MASTER_KEY_FILE")
    if path:
        raw = Path(path).read_bytes().strip()
        source = f"file {path}"
    elif os.environ.get("LINTEL_MASTER_KEY"):
        raw = os.environ["LINTEL_MASTER_KEY"].encode().strip()
        source = "LINTEL_MASTER_KEY"
    else:
        f = data_dir / "master.key"
        if not f.exists():
            f.write_text(_b64(secrets.token_bytes(KEY_LEN)) + "\n")
            try:
                os.chmod(f, 0o600)
            except OSError:
                pass
        raw = f.read_bytes().strip()
        source = f"{f} (beside the data: set LINTEL_MASTER_KEY_FILE in production)"
        log.warning("master key is stored beside the database; anyone with the data folder can decrypt it. "
                    "Use LINTEL_MASTER_KEY_FILE (a Docker secret or KMS-unlocked file) in production.")
    try:
        key = _unb64(raw.decode())
    except (ValueError, UnicodeDecodeError):
        raise VaultError(f"master key from {source} is not base64")
    if len(key) != KEY_LEN:
        raise VaultError(f"master key from {source} must be {KEY_LEN} bytes")
    return key, source


class Vault:
    def __init__(self, data_dir: Path, master: bytes | None = None) -> None:
        self.data_dir = data_dir
        if master is None:
            master, self.source = load_master_key(data_dir)
        else:
            self.source = "supplied"
        self._kek = AESGCM(master)
        self.path = data_dir / "keyring.json"
        if not self.path.exists():
            self._write({"active": 1, "keys": {"1": self._wrap(1, secrets.token_bytes(KEY_LEN))}})
        ring = json.loads(self.path.read_text())
        self.active = int(ring["active"])
        self._keys: dict[int, AESGCM] = {}
        for kid, wrapped in ring["keys"].items():
            try:
                self._keys[int(kid)] = AESGCM(self._kek.decrypt(*self._split(wrapped), self._ring_aad(int(kid))))
            except (InvalidTag, ValueError):
                raise VaultError("the master key does not open this site's keyring: wrong key, or the keyring "
                                 "belongs to another installation")

    # ---- keyring ---------------------------------------------------------------------

    @staticmethod
    def _ring_aad(kid: int) -> bytes:
        return f"lintel-data-key:{kid}".encode()

    def _wrap(self, kid: int, dek: bytes) -> str:
        nonce = secrets.token_bytes(12)
        return _b64(nonce + self._kek.encrypt(nonce, dek, self._ring_aad(kid)))

    @staticmethod
    def _split(wrapped: str) -> tuple[bytes, bytes]:
        raw = _unb64(wrapped)
        return raw[:12], raw[12:]

    def _write(self, ring: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(ring, indent=2))
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)  # atomic: never a half-written keyring

    def rewrap(self, new_master: bytes) -> None:
        """Master key rotation: the data keys are rewrapped, the data untouched."""
        ring = json.loads(self.path.read_text())
        deks = {int(k): self._kek.decrypt(*self._split(w), self._ring_aad(int(k))) for k, w in ring["keys"].items()}
        self._kek = AESGCM(new_master)
        self._write({"active": ring["active"], "keys": {str(k): self._wrap(k, d) for k, d in deks.items()}})

    # ---- values ------------------------------------------------------------------------

    def seal(self, where: str, data: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return MAGIC + bytes([self.active]) + nonce + self._keys[self.active].encrypt(nonce, data, where.encode())

    def open(self, where: str, blob: bytes) -> bytes:
        blob = bytes(blob)
        if not is_sealed(blob):
            raise VaultError(f"{where} is not encrypted")
        aead = self._keys.get(blob[3])
        if aead is None:
            raise VaultError(f"{where} was encrypted with a data key this keyring does not hold")
        try:
            return aead.decrypt(blob[4:16], blob[16:], where.encode())
        except InvalidTag:
            raise VaultError(f"{where} failed to decrypt: altered, or moved from another record")

    def seal_text(self, where: str, text: str) -> str:
        return TEXT_PREFIX + _b64(self.seal(where, text.encode()))

    def open_text(self, where: str, value: str) -> str:
        if not value.startswith(TEXT_PREFIX):
            raise VaultError(f"{where} is not encrypted")
        return self.open(where, _unb64(value[len(TEXT_PREFIX):])).decode()


def is_sealed(blob) -> bool:
    return isinstance(blob, (bytes, bytearray, memoryview)) and bytes(blob[:3]) == MAGIC and len(blob) > 16
