"""Device adoption: discovery, pairing-code check, sealed key delivery, unassign."""

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from lintel_server.adopt import LABEL, pairing_code
from lintel_server.protocol import Decision, MsgType, open_frame
from test_server import Panel, env, resp  # noqa: F401  (fixture reuse)


class FakeDevice:
    """A panel's identity, as the firmware keeps it."""

    def __init__(self, serial="LNT-80F1B2D3611F"):
        self.serial = serial
        self.sk = X25519PrivateKey.generate()
        self.pk = self.sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.door = 0
        self.seq = 0

    def announce(self, client):
        return client.post("/api/devices/announce", json={
            "serial": self.serial, "pubkey": self.pk.hex(), "mac": "80:f1:b2:d3:61:1f",
            "firmware": "0.2.0", "controller": "pi-zero-1", "door": self.door, "seq": self.seq})

    def open_blob(self, blob: bytes):
        eph_pk, head = blob[:32], blob[:36]
        shared = self.sk.exchange(X25519PublicKey.from_public_bytes(eph_pk))
        k = hmac.new(shared, LABEL + self.pk + eph_pk, hashlib.sha256).digest()[:16]
        body = AESCCM(k, tag_length=8).decrypt(bytes(13), blob[36:], head)
        door_id, net_id = struct.unpack_from("<HI", body)
        return door_id, net_id, body[6:22], struct.unpack_from("<I", blob, 32)[0]


def test_discover_adopt_deliver_and_use(env):
    store, ctl, client, _, gid = env
    dev = FakeDevice()
    assert dev.announce(client).json()["state"] == "unassigned"
    listed = client.get("/api/devices").json()
    assert listed[0]["serial"] == dev.serial and listed[0]["door_id"] is None

    bad = client.post(f"/api/devices/{dev.serial}/adopt", json={"pairing_code": "000000", "door_id": 2})
    assert bad.status_code == 400
    ok = client.post(f"/api/devices/{dev.serial}/adopt", json={
        "pairing_code": pairing_code(dev.pk), "door_id": 2, "name": "Side Door", "groups": [gid]})
    assert ok.status_code == 200, ok.text

    r = dev.announce(client).json()
    assert r["state"] == "provisioning"
    door_id, net_id, key, seq = dev.open_blob(bytes.fromhex(r["provision"]))
    assert door_id == 2 and net_id == store.secrets.net_id and seq == 1

    dev.door, dev.seq = 2, seq  # firmware stored it and reports what it applied
    assert dev.announce(client).json()["state"] == "assigned"
    assert "provision" not in dev.announce(client).json()

    # The delivered key works for real traffic.
    client.post("/api/cardholders", json={"first_name": "Ana", "pin": "3691", "groups": [gid]})
    panel = Panel(ctl, 2, key, net_id)
    assert resp(panel.pin("3691"))[1] == Decision.GRANT

    detail = client.get("/api/doors/2").json()
    assert detail["serial"] == dev.serial and detail["groups"][0]["id"] == gid

    # Rotating the key re-delivers automatically.
    assert client.post("/api/doors/2/rekey").json()["auto"]
    new = dev.open_blob(bytes.fromhex(dev.announce(client).json()["provision"]))
    assert new[0] == 2 and new[2] != key and new[3] == 2


def test_unassign_rotates_key_and_tells_panel_to_forget(env):
    store, ctl, client, _, gid = env
    dev = FakeDevice()
    dev.announce(client)
    client.post(f"/api/devices/{dev.serial}/adopt", json={"pairing_code": pairing_code(dev.pk), "door_id": 3})
    _, net_id, key, seq = dev.open_blob(bytes.fromhex(dev.announce(client).json()["provision"]))
    dev.door, dev.seq = 3, seq
    dev.announce(client)

    assert client.post("/api/doors/3/unassign").status_code == 200
    door_id, _, _, seq = dev.open_blob(bytes.fromhex(dev.announce(client).json()["provision"]))
    assert door_id == 0 and seq == 2
    # The old key no longer reaches the controller as a valid door.
    panel = Panel(ctl, 3, key, net_id)
    assert panel.pin("3691") is None
    dev.door, dev.seq = 0, seq
    assert dev.announce(client).json()["state"] == "unassigned"


def test_identity_change_on_adopted_device_raises_alarm(env):
    store, ctl, client, _, gid = env
    dev = FakeDevice()
    dev.announce(client)
    client.post(f"/api/devices/{dev.serial}/adopt", json={"pairing_code": pairing_code(dev.pk), "door_id": 4})
    clone = FakeDevice(dev.serial)
    assert clone.announce(client).status_code == 409
    assert any(a["kind"] == "device.identity" for a in client.get("/api/alarms").json())
