"""Remote commands ride in the sealed heartbeat ack; diagnostics are stored per door."""

import struct

from fastapi.testclient import TestClient

from lintel_server.protocol import MsgType, open_frame
from test_server import env  # noqa: F401  (fixture reuse)


def heartbeat(ctl, panel):
    ctl.datagram(panel.frame(MsgType.HEARTBEAT, bytes(11)), ("10.0.0.5", 5000))
    h, pt = open_frame(panel.key, panel.net, ctl.transport.sent[-1])
    assert h.type == MsgType.HEARTBEAT_ACK
    return pt[36], struct.unpack_from("<I", pt, 37)[0]


def test_reboot_is_delivered_once_and_needs_admin(env):
    store, ctl, client, panel, gid = env
    assert heartbeat(ctl, panel) == (0, 0)
    r = client.post("/api/doors/1/command", json={"command": "reboot"})
    assert r.status_code == 200
    cmd, cid = heartbeat(ctl, panel)
    assert cmd == 1 and cid == r.json()["command_id"]
    assert heartbeat(ctl, panel) == (0, 0)  # not repeated

    client.post("/api/operators", json={"username": "ops", "password": "ops-password-1", "role": "operator"})
    o = TestClient(client.app)
    o.post("/api/login", json={"username": "ops", "password": "ops-password-1"})
    assert o.post("/api/doors/1/command", json={"command": "reboot"}).status_code == 403
    assert o.post("/api/doors/1/command", json={"command": "identify"}).status_code == 200
    assert client.post("/api/doors/1/command", json={"command": "format_disk"}).status_code == 422


def test_diag_is_decoded_and_shown(env):
    store, ctl, client, panel, gid = env
    p = b"0.4.0".ljust(8, b"\x00") + struct.pack("<IBIIIbBBHHH", 3600, 4, 150000, 90000, 30000000, 47, 1, 0, 2, 0, 38)
    ctl.datagram(panel.frame(MsgType.DIAG, p), ("10.0.0.5", 5000))
    d = client.get("/api/doors/1").json()["diag"]
    assert d["firmware"] == "0.4.0" and d["reset_reason"] == "crash (panic)" and d["temp_c"] == 47
    assert d["camera"] is True and d["reader"] is False and d["last_decision_ms"] == 38
