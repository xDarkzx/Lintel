"""Door controller: the box between a keypad and the server.

In a building this runs on a Pi Zero (or similar) inside the secure side of
the door, wired to the keypad over USB and to the site network over Ethernet
or Wi-Fi. The keypad has no network of its own.

It is a relay, deliberately. Protocol frames are sealed by the keypad with
its door key and opened only by the server, so this box never holds a key:
taking it over gives an attacker nothing they could not already sniff.

    python -m lintel_server.door_controller --server 192.168.1.10
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import json
import os
import ssl
import logging
import socket
import struct
import threading
import time
from pathlib import Path

import serial
from serial.tools import list_ports

log = logging.getLogger("lintel.door_controller")

MAGIC = b"\xA5\x5A"

# controller -> panel
FRAME_DOWN = 0x01
PROVISION = 0x02
SERVER_STATE = 0x03
PING = 0x05
# panel -> controller
FRAME_UP = 0x81
PONG = 0x82
HELLO = 0x85
PHOTO_START = 0x86
PHOTO_CHUNK = 0x87
PHOTO_END = 0x88
ANNOUNCE = 0x89
MEDIA_START = 0x8A  # u8 kind (1 screenshot, 2 test photo), u32 ref, u32 size, mac[32]
MEDIA_CHUNK = 0x8B
MEDIA_END = 0x8C
MEDIA_KINDS = {1: "screenshot", 2: "test_photo", 3: "face"}
WATCH_START = 0x8D  # u32 req, u8 index, u8 total, u32 ms, u32 size, mac[32]: one frame of the open-door burst
WATCH_CHUNK = 0x8E
WATCH_END = 0x8F

MAX_PAYLOAD = 1024
MAX_PHOTO = 2_000_000
ESPRESSIF_VID = 0x303A
TINYUSB_PIDS = {0x4001, 0x4002}


def crc16(data: bytes, crc: int = 0xFFFF) -> int:
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def encode_packet(ptype: int, payload: bytes = b"") -> bytes:
    body = struct.pack("<BH", ptype, len(payload)) + payload
    return MAGIC + body + struct.pack("<H", crc16(body))


class PacketReader:
    """Byte-stream parser for the panel link; resyncs on any bad packet."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.errors = 0

    def feed(self, data: bytes) -> list[tuple[int, bytes]]:
        self.buf += data
        out = []
        while True:
            i = self.buf.find(MAGIC)
            if i < 0:
                del self.buf[:-1]
                return out
            del self.buf[:i]
            if len(self.buf) < 5:
                return out
            ptype, n = struct.unpack_from("<BH", self.buf, 2)
            if n > MAX_PAYLOAD:
                self.errors += 1
                del self.buf[:1]
                continue
            if len(self.buf) < 7 + n:
                return out
            body = bytes(self.buf[2:5 + n])
            (crc,) = struct.unpack_from("<H", self.buf, 5 + n)
            if crc16(body) == crc:
                out.append((ptype, body[3:]))
                del self.buf[:7 + n]
            else:
                self.errors += 1
                del self.buf[:1]


def find_panel_port() -> str | None:
    """The keypad's link is the TinyUSB CDC port, not its flashing/log port."""
    for p in list_ports.comports():
        if p.vid == ESPRESSIF_VID and p.pid in TINYUSB_PIDS:
            return p.device
    return None


class DoorController:
    def __init__(self, port: str | None, server: str, udp_port: int, http_port: int, token: str, pin: str) -> None:
        self.port_name = port
        self.server = (server, udp_port)
        self.http_host, self.http_port = server, http_port
        self.http = f"https://{server}:{http_port}"
        self.token = token
        self.pin = pin.lower().replace(":", "")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.5)
        self.ser: serial.Serial | None = None
        self.write_lock = threading.Lock()
        self.door_id: int | None = None
        self.photo: dict | None = None
        self.stats = {"up": 0, "down": 0, "photos": 0}
        self.name = socket.gethostname()
        self.media: dict | None = None
        self.watch: dict | None = None
        self.local_media = Path("panel_media")

    # ---- panel side -----------------------------------------------------------

    def send_panel(self, ptype: int, payload: bytes = b"") -> None:
        if self.ser is None:
            return
        with self.write_lock:
            self.ser.write(encode_packet(ptype, payload))

    def on_packet(self, ptype: int, p: bytes) -> None:
        if ptype == FRAME_UP:
            self.sock.sendto(p, self.server)
            self.stats["up"] += 1
        elif ptype == HELLO:
            text = p.rstrip(b"\x00").decode(errors="replace")
            door = next((int(x[5:]) for x in text.split() if x.startswith("door=")), None)
            if door != self.door_id or door is None:
                log.info("panel says hello: %s", text)
            self.door_id = door or None
        elif ptype == ANNOUNCE and len(p) > 32:
            threading.Thread(target=self.announce, args=(p,), daemon=True).start()
        elif ptype == MEDIA_START and len(p) == 41:
            kind, ref, size = struct.unpack_from("<BII", p)
            if kind in MEDIA_KINDS and size <= 3_000_000:
                self.media = {"kind": MEDIA_KINDS[kind], "req": ref, "size": size, "mac": p[9:41].hex(),
                              "data": bytearray()}
        elif ptype == MEDIA_CHUNK and self.media is not None:
            self.media["data"] += p
        elif ptype == MEDIA_END and self.media is not None:
            m, self.media = self.media, None
            if len(m["data"]) == m["size"] and m["kind"] == "face":
                # Uploaded before reading on: the request that cites this face
                # is the panel's next packet and must not overtake it.
                self.upload_face(m)
            elif len(m["data"]) == m["size"]:
                threading.Thread(target=self.upload_media, args=(m,), daemon=True).start()
            else:
                log.warning("%s truncated, dropped", m["kind"])
        elif ptype == WATCH_START and len(p) == 46:
            req, index, total, ms, size = struct.unpack_from("<IBBII", p)
            if size <= MAX_PHOTO:
                self.watch = {"req": req, "index": index, "total": total, "ms": ms, "size": size,
                              "mac": p[14:46].hex(), "data": bytearray()}
        elif ptype == WATCH_CHUNK and self.watch is not None:
            self.watch["data"] += p
            if len(self.watch["data"]) > self.watch["size"]:
                log.warning("door frame overran its declared size, dropped")
                self.watch = None
        elif ptype == WATCH_END and self.watch is not None:
            w, self.watch = self.watch, None
            if len(w["data"]) == w["size"]:
                threading.Thread(target=self.upload_watch, args=(w,), daemon=True).start()
            else:
                log.warning("door frame truncated (%d of %d bytes), dropped", len(w["data"]), w["size"])
        elif ptype == PHOTO_START and len(p) == 40:
            req, size = struct.unpack_from("<II", p)
            if size <= MAX_PHOTO:
                self.photo = {"req": req, "size": size, "mac": p[8:40].hex(), "data": bytearray()}
        elif ptype == PHOTO_CHUNK and self.photo is not None:
            self.photo["data"] += p
            if len(self.photo["data"]) > self.photo["size"]:
                log.warning("photo overran its declared size, dropped")
                self.photo = None
        elif ptype == PHOTO_END and self.photo is not None:
            ph, self.photo = self.photo, None
            if len(ph["data"]) == ph["size"]:
                threading.Thread(target=self.upload_photo, args=(ph,), daemon=True).start()
            else:
                log.warning("photo truncated (%d of %d bytes), dropped", len(ph["data"]), ph["size"])

    def post(self, path: str, data: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
        """HTTPS POST to the server, accepting only the certificate we pinned.
        Our own self-signed server has no CA, so the pin is the trust anchor."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # replaced by the explicit pin check below
        conn = http.client.HTTPSConnection(self.http_host, self.http_port, timeout=10, context=ctx)
        try:
            conn.connect()
            der = conn.sock.getpeercert(binary_form=True)
            if not der or not hmac.compare_digest(hashlib.sha256(der).hexdigest(), self.pin):
                raise ssl.SSLError("server certificate does not match the pinned fingerprint")
            conn.request("POST", path, body=data, headers={**headers, "Authorization": f"Bearer {self.token}"})
            r = conn.getresponse()
            return r.status, r.read()
        finally:
            conn.close()

    def announce(self, p: bytes) -> None:
        """Pass the panel's identity to the server; hand back a sealed
        adoption message if the server has one waiting for it."""
        fields = dict(kv.split("=", 1) for kv in p[32:].decode(errors="replace").split() if "=" in kv)
        body = {"serial": fields.get("serial", ""), "pubkey": p[:32].hex(), "mac": fields.get("mac", ""),
                "firmware": fields.get("fw", ""), "controller": self.name,
                "door": int(fields.get("door", "0")), "seq": int(fields.get("seq", "0"))}
        try:
            status, raw = self.post("/api/devices/announce", json.dumps(body).encode(),
                                    {"Content-Type": "application/json"})
        except (OSError, ssl.SSLError) as e:
            log.warning("announce failed: %s", e)
            return
        if status != 200:
            log.error("server refused announce from %s: %s %s", body["serial"], status, raw.decode(errors="replace"))
            return
        reply = json.loads(raw)
        state = reply.get("state")
        if reply.get("provision"):
            log.info("delivering sealed door assignment to %s", body["serial"])
            self.send_panel(PROVISION, bytes.fromhex(reply["provision"]))
        elif state == "unassigned":
            log.info("%s is waiting for adoption in the dashboard", body["serial"])
        if state in ("assigned", "unassigned"):
            self.send_panel(SERVER_STATE, bytes([1 if state == "assigned" else 0]))

    def upload_media(self, m: dict) -> None:
        self.local_media.mkdir(exist_ok=True)
        local = self.local_media / f"door{self.door_id}_{m['kind']}.jpg"
        local.write_bytes(bytes(m["data"]))
        try:
            status, raw = self.post(f"/api/door/{self.door_id}/media?kind={m['kind']}", bytes(m["data"]),
                                    {"Content-Type": "image/jpeg", "X-Lintel-Req": str(m["req"]),
                                     "X-Lintel-Mac": m["mac"]})
            if status == 200:
                log.info("%s from door %s stored (%d bytes, local copy %s)", m["kind"], self.door_id, m["size"], local)
            else:
                log.error("%s refused: %s %s", m["kind"], status, raw.decode(errors="replace"))
        except (OSError, ssl.SSLError) as e:
            log.error("%s upload failed: %s", m["kind"], e)

    def upload_photo(self, ph: dict) -> None:
        if self.door_id is None:
            log.warning("photo before HELLO, door id unknown; dropped")
            return
        try:
            status, raw = self.post(f"/api/door/{self.door_id}/photo", bytes(ph["data"]),
                                    {"Content-Type": "image/jpeg", "X-Lintel-Req": str(ph["req"]),
                                     "X-Lintel-Mac": ph["mac"]})
            if status == 200:
                log.info("entry photo stored (%d bytes): %s", ph["size"], raw.decode())
                self.stats["photos"] += 1
            else:
                log.error("server refused photo: %s %s", status, raw.decode(errors="replace"))
        except (OSError, ssl.SSLError) as e:
            log.error("photo upload failed: %s", e)

    def upload_face(self, m: dict) -> None:
        """A face + PIN door's face image. The server holds its verdict for the
        request that follows; this box only learns whether a face was usable."""
        if self.door_id is None:
            log.warning("face image before HELLO, door id unknown; dropped")
            return
        try:
            status, raw = self.post(f"/api/door/{self.door_id}/face", bytes(m["data"]),
                                    {"Content-Type": "image/jpeg", "X-Lintel-Req": str(m["req"]),
                                     "X-Lintel-Mac": m["mac"]})
            if status == 200:
                log.info("face image delivered: %s", raw.decode(errors="replace"))
            else:
                log.error("face image refused: %s %s", status, raw.decode(errors="replace"))
        except (OSError, ssl.SSLError) as e:
            log.error("face image upload failed: %s", e)

    def upload_watch(self, w: dict) -> None:
        if self.door_id is None:
            log.warning("door frame before HELLO, door id unknown; dropped")
            return
        try:
            status, raw = self.post(f"/api/door/{self.door_id}/watch", bytes(w["data"]),
                                    {"Content-Type": "image/jpeg", "X-Lintel-Req": str(w["req"]),
                                     "X-Lintel-Frame": f"{w['index']}/{w['total']}", "X-Lintel-Ms": str(w["ms"]),
                                     "X-Lintel-Mac": w["mac"]})
            if status != 200:
                log.error("door frame %d/%d refused: %s %s", w["index"] + 1, w["total"], status,
                          raw.decode(errors="replace"))
            elif w["index"] + 1 == w["total"]:
                log.info("door frames for request %d delivered", w["req"])
        except (OSError, ssl.SSLError) as e:
            log.error("door frame upload failed: %s", e)

    # ---- loops ---------------------------------------------------------------------

    def server_loop(self) -> None:
        while True:
            try:
                data, _ = self.sock.recvfrom(512)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                time.sleep(0.5)
                continue
            try:
                self.send_panel(FRAME_DOWN, data)
                self.stats["down"] += 1
            except serial.SerialException:
                pass

    def panel_loop(self) -> None:
        while True:
            port = self.port_name or find_panel_port()
            if port is None:
                log.info("waiting for the keypad on USB (its high-speed OTG socket)")
                time.sleep(2)
                continue
            try:
                self.ser = serial.Serial(port, 115200, timeout=0.2)
                self.ser.dtr = True  # tells the panel a controller is attached
                log.info("keypad connected on %s", port)
                reader = PacketReader()
                self.send_panel(PING)
                last_ping = time.time()
                while True:
                    data = self.ser.read(4096)
                    for ptype, payload in reader.feed(data):
                        self.on_packet(ptype, payload)
                    if time.time() - last_ping > 5:
                        self.send_panel(PING)
                        last_ping = time.time()
            except (serial.SerialException, OSError) as e:
                log.warning("keypad link lost: %s", e)
            finally:
                if self.ser is not None:
                    try:
                        self.ser.close()
                    except Exception:
                        pass
                self.ser = None
            time.sleep(1)

    def run(self) -> None:
        log.info("relaying keypad <-> server %s:%d (HTTP %s)", *self.server, self.http)
        threading.Thread(target=self.server_loop, daemon=True).start()
        self.panel_loop()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", help="keypad serial port (default: auto-detect the TinyUSB CDC device)")
    p.add_argument("--server", default="127.0.0.1", help="Lintel server address")
    p.add_argument("--udp-port", type=int, default=47800)
    p.add_argument("--https-port", type=int, default=8443)
    p.add_argument("--env", help="controller.env written by the server (token and certificate pin)")
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    env = dict(os.environ)
    if a.env:
        env.update(dict(line.split("=", 1) for line in Path(a.env).read_text().split() if "=" in line))
    token, pin = env.get("LINTEL_TOKEN"), env.get("LINTEL_PIN_SHA256")
    if not token or not pin:
        raise SystemExit("need LINTEL_TOKEN and LINTEL_PIN_SHA256 (pass --env path/to/controller.env)")
    DoorController(a.port, a.server, a.udp_port, a.https_port, token, pin).run()


if __name__ == "__main__":
    main()
