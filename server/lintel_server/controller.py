"""Door controller: the UDP endpoint panels talk to.

Authenticates every frame (AES-CCM + replay window), decides PIN entries,
answers heartbeats, supervises door links and raises alarms.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .access import AccessEngine
import json
from dataclasses import asdict

from .protocol import (CredReq, Decision, Diag, FrameError, Header, Heartbeat, HeartbeatAck, MsgType, PinReq,
                       PinResp, Reason, ReplayWindow, SiteMode, dir_for, Dir, open_frame, peek_header, seal)
from .store import Store

log = logging.getLogger("lintel.controller")

TX_BLOCK = 64
SUPERVISE_S = 20.0           # door declared offline after this much silence
REJECT_LOG_INTERVAL_S = 10.0

REASON_TEXT = {
    Reason.OK: "granted", Reason.BAD_PIN: "PIN not recognised", Reason.REVOKED: "cardholder inactive or expired",
    Reason.DOOR_NOT_ALLOWED: "no access to this door", Reason.OUTSIDE_SCHEDULE: "outside schedule",
    Reason.LOCKDOWN: "site lockdown", Reason.LOCKED_OUT: "keypad locked out",
    Reason.UNKNOWN_CARD: "card not recognised", Reason.NO_MATCH: "face not recognised",
    Reason.MISMATCH: "credentials belong to different people", Reason.WRONG_MODE: "credential not accepted here",
    Reason.ENROLLED: "card enrolled",
}
FACE_RESULT_TTL_S = 30


def photo_key(door_key: bytes) -> bytes:
    """Key a panel uses to sign entry photos; derived from its door key."""
    return hmac.new(door_key, b"lintel-photo", hashlib.sha256).digest()


@dataclass
class DoorLink:
    id: int
    name: str
    key: bytes
    unlock_ms: int
    rx: ReplayWindow
    tx_next: int
    tx_ceiling: int
    online: bool = False
    last_seen: float = 0.0
    last_reject_log: float = 0.0
    rejects: int = 0


@dataclass
class Controller:
    store: Store
    engine: AccessEngine
    publish: Callable[[dict[str, Any]], None]
    doors: dict[int, DoorLink] = field(default_factory=dict)
    transport: asyncio.DatagramTransport | None = None
    # (door, ref) -> (cardholder or None, score, time, jpeg, error) from /api/door/{id}/face
    face_results: dict[tuple[int, int], tuple] = field(default_factory=dict)
    # door -> (command, command_id), handed over once in the next heartbeat ack
    commands: dict[int, tuple[int, int]] = field(default_factory=dict)
    next_command_id: int = field(default_factory=lambda: int(time.time()) & 0x7FFFFFFF)

    # ---- door table -----------------------------------------------------------

    def load_doors(self) -> None:
        for r in self.store.q("SELECT * FROM doors"):
            self.load_door(r["id"])

    def load_door(self, door_id: int) -> None:
        r = self.store.q1("SELECT * FROM doors WHERE id=?", (door_id,))
        if r is None:
            self.doors.pop(door_id, None)
            return
        old = self.doors.get(door_id)
        # Resume from the persisted ceiling: values below it may have been used.
        self.doors[door_id] = DoorLink(r["id"], r["name"], bytes(r["key"]), r["unlock_ms"],
                                       ReplayWindow(r["rx_highest"]), max(1, r["tx_ceiling"]), r["tx_ceiling"],
                                       online=old.online if old else False, last_seen=old.last_seen if old else 0.0)

    def _next_ctr(self, d: DoorLink) -> int:
        if d.tx_next >= d.tx_ceiling:
            d.tx_ceiling = d.tx_next + TX_BLOCK
            self.store.x("UPDATE doors SET tx_ceiling=? WHERE id=?", (d.tx_ceiling, d.id))
        c = d.tx_next
        d.tx_next += 1
        return c

    def _send(self, d: DoorLink, t: MsgType, payload: bytes, addr: tuple[str, int]) -> None:
        h = Header(t, 0, d.id, self._next_ctr(d))
        assert self.transport is not None
        self.transport.sendto(seal(d.key, self.store.secrets.net_id, h, payload), addr)

    # ---- datagram entry point ------------------------------------------------------

    def datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            h = peek_header(data)
        except FrameError:
            return
        d = self.doors.get(h.door_id)
        if d is None or dir_for(h.type) != Dir.DOOR_TO_CTRL:
            return
        now = time.time()
        if not d.rx.accepts(h.counter):
            self._reject(d, now, f"replayed frame ctr={h.counter} from {addr[0]}")
            return
        try:
            h, pt = open_frame(d.key, self.store.secrets.net_id, data)
        except FrameError:
            self._reject(d, now, f"forged or corrupted frame from {addr[0]}")
            return
        d.rx.commit(h.counter)
        self.store.x("UPDATE doors SET rx_highest=?, last_seen=?, last_ip=? WHERE id=?",
                     (d.rx.highest, now, addr[0], d.id))
        d.last_seen = now
        if not d.online:
            d.online = True
            ev = self.store.journal("door.online", door_id=d.id, detail=f"{d.name} connected from {addr[0]}")
            self._clear_alarms(d.id, "door.offline")
            self.publish({"type": "event", "event": ev})
            self.publish({"type": "doors"})

        try:
            if h.type == MsgType.PIN_REQ:
                self._on_pin(d, h, PinReq.decode(pt), addr, now)
            elif h.type == MsgType.CRED_REQ:
                self._on_cred(d, h, CredReq.decode(pt), addr, now)
            elif h.type == MsgType.DIAG:
                diag = asdict(Diag.decode(pt))
                self.store.x("UPDATE doors SET diag=?, diag_ts=? WHERE id=?", (json.dumps(diag), now, d.id))
                self.publish({"type": "diag", "door": d.id})
            elif h.type == MsgType.HEARTBEAT:
                hb = Heartbeat.decode(pt)
                self.store.x("UPDATE doors SET rssi=? WHERE id=?", (hb.last_rssi, d.id))
                cmd, cmd_id = self.commands.pop(d.id, (0, 0))
                ack = HeartbeatAck(self.engine.site_mode(), 0, int(now), h.counter, self.engine.door_mode(d.id),
                                   d.name, cmd, cmd_id)
                if cmd:
                    log.info("door %d: command %d (#%d) delivered", d.id, cmd, cmd_id)
                self._send(d, MsgType.HEARTBEAT_ACK, ack.encode(), addr)
        except FrameError as e:
            self._reject(d, now, f"malformed payload: {e}")

    on_face_evidence: Callable[[dict, bytes, str, str], None] | None = None

    def _reject(self, d: DoorLink, now: float, why: str) -> None:
        d.rejects += 1
        log.warning("door %d: %s", d.id, why)
        # Rate-limited so junk traffic cannot flood the journal.
        if now - d.last_reject_log >= REJECT_LOG_INTERVAL_S:
            d.last_reject_log = now
            ev = self.store.journal("link.rejected", door_id=d.id, detail=why)
            al = self.store.raise_alarm(2, "link.rejected", f"Rejected traffic at {d.name}", door_id=d.id,
                                        event_seq=ev["seq"])
            self.publish({"type": "event", "event": ev})
            self.publish({"type": "alarm", "alarm": al})

    def _on_cred(self, d: DoorLink, h: Header, req: CredReq, addr: tuple[str, int], now: float) -> None:
        face = None
        face_jpeg = None
        if req.face_ref:
            got = self.face_results.pop((d.id, req.face_ref), None)
            if got is None or now - got[2] > FACE_RESULT_TTL_S:
                face = (None, 0.0)  # no fresh, signed face image behind this reference
            else:
                face = (got[0], got[1])
                face_jpeg = got[3]
        v = self.engine.decide(d.id, pin=req.pin or None, card=req.uid or None, face=face, now=now,
                               enforce_mode=True)
        if face is not None:
            v.method = f"face {face[1]:.2f}" + (" + PIN" if req.pin else "")
        self._decided(d, h, v, addr, now, face_jpeg)

    def _on_pin(self, d: DoorLink, h: Header, req: PinReq, addr: tuple[str, int], now: float) -> None:
        self._decided(d, h, self.engine.decide_pin(d.id, req.pin, now), addr, now, None)

    def _decided(self, d: DoorLink, h: Header, v, addr: tuple[str, int], now: float, face_jpeg: bytes | None) -> None:
        ch = v.cardholder
        who = f"{ch['first_name']} {ch['last_name']}" if ch else None
        granted = v.decision == Decision.GRANT

        resp = PinResp(h.counter, v.decision, v.reason, d.unlock_ms if granted else 0, v.lockout_s,
                       ch["first_name"] if ch and granted else "")
        self._send(d, MsgType.PIN_RESP, resp.encode(), addr)

        # A duress grant is journalled as a normal grant; only the alarm says otherwise,
        # so nothing visible at the door gives the user away.
        kind = "credential.enrolled" if v.reason == Reason.ENROLLED else (
            "access.granted" if granted else "access.denied")
        via = f" ({v.method})" if v.method else ""
        ev = self.store.journal(kind, door_id=d.id,
                                cardholder_id=ch["id"] if ch else None, decision=v.decision.name.lower(),
                                reason=v.reason.name.lower(),
                                detail=f"{who or 'Unknown'} at {d.name}: {REASON_TEXT.get(v.reason, v.reason.name)}{via}",
                                req_ctr=h.counter)
        if face_jpeg is not None and self.on_face_evidence is not None:
            # The face image the decision was based on becomes the event photo.
            self.on_face_evidence(ev, face_jpeg, d.name, who or "unrecognised")
        self.publish({"type": "event", "event": ev})
        log.info("door %d pin -> %s (%s) %s", d.id, v.decision.name, v.reason.name, who or "")

        alarm = None
        if v.duress:
            alarm = self.store.raise_alarm(1, "duress", f"DURESS: {who} at {d.name}", door_id=d.id, event_seq=ev["seq"])
        elif v.lockout_started:
            # Treated as an attempted break-in: critical, with the panel's photo
            # of the person attached to this event when it arrives.
            alarm = self.store.raise_alarm(1, "keypad.lockout", f"Possible PIN guessing at {d.name}: keypad locked "
                                           f"for {v.lockout_s}s", door_id=d.id, event_seq=ev["seq"])
        if alarm:
            self.publish({"type": "alarm", "alarm": alarm})

    # ---- supervision ---------------------------------------------------------------------

    def supervise(self) -> None:
        now = time.time()
        for d in self.doors.values():
            if d.online and now - d.last_seen > SUPERVISE_S:
                d.online = False
                ev = self.store.journal("door.offline", door_id=d.id, detail=f"{d.name} stopped responding")
                al = self.store.raise_alarm(2, "door.offline", f"{d.name} offline", door_id=d.id,
                                            event_seq=ev["seq"])
                self.publish({"type": "event", "event": ev})
                self.publish({"type": "alarm", "alarm": al})
                self.publish({"type": "doors"})

    def _clear_alarms(self, door_id: int, kind: str) -> None:
        self.store.x("UPDATE alarms SET state='cleared' WHERE door_id=? AND kind=? AND state!='cleared'",
                     (door_id, kind))
        self.publish({"type": "alarms"})

    def queue_command(self, door_id: int, command: int) -> int:
        self.next_command_id = (self.next_command_id + 1) & 0x7FFFFFFF or 1
        self.commands[door_id] = (command, self.next_command_id)
        return self.next_command_id

    def set_mode(self, mode: SiteMode, operator: str) -> dict[str, Any]:
        self.store.set_setting("site_mode", str(int(mode)))
        ev = self.store.journal("site.mode", operator=operator, detail=f"site mode set to {mode.name.lower()}")
        if mode == SiteMode.LOCKDOWN:
            al = self.store.raise_alarm(1, "lockdown", f"Site lockdown started by {operator}", event_seq=ev["seq"])
            self.publish({"type": "alarm", "alarm": al})
        self.publish({"type": "event", "event": ev})
        self.publish({"type": "mode", "mode": int(mode)})
        return ev


class _Proto(asyncio.DatagramProtocol):
    def __init__(self, ctl: Controller) -> None:
        self.ctl = ctl

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.ctl.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            self.ctl.datagram(data, addr)
        except Exception:  # never let one bad packet stop the listener
            log.exception("datagram handling failed")


async def run_controller(ctl: Controller, host: str, port: int) -> None:
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: _Proto(ctl), local_addr=(host, port))
    log.info("door controller listening on udp/%d", port)
    while True:
        await asyncio.sleep(2)
        ctl.supervise()
