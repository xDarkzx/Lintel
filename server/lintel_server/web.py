"""Operator API and dashboard."""

from __future__ import annotations

import asyncio
import csv
import hashlib
import hmac
import io
import json
import secrets
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import adopt
from .controller import Controller, photo_key
from .photos import stamp_photo
from .protocol import COMMANDS, SiteMode
from .store import Store, check_password, hash_password

STATIC = Path(__file__).parent / "static"
SESSION_S = 12 * 3600
ROLES = {"viewer": 0, "operator": 1, "admin": 2}


class Hub:
    """Fans live updates out to every connected dashboard."""

    def __init__(self) -> None:
        self.queues: set[asyncio.Queue] = set()

    def publish(self, msg: dict[str, Any]) -> None:
        for q in list(self.queues):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass


# ---- request models ----------------------------------------------------------

class Login(BaseModel):
    username: str
    password: str


class DoorIn(BaseModel):
    id: int = Field(ge=1, le=31)
    name: str = Field(min_length=1, max_length=40)
    area: str = ""
    unlock_ms: int = Field(5000, ge=1000, le=30000)


class DoorPatch(BaseModel):
    name: str | None = None
    area: str | None = None
    unlock_ms: int | None = Field(None, ge=1000, le=30000)
    credential_mode: str | None = Field(None, pattern="^(pin|card|card_or_pin|card_and_pin)$")
    groups: list[int] | None = None


class CardholderIn(BaseModel):
    first_name: str = Field(min_length=1, max_length=40)
    last_name: str = Field("", max_length=40)
    department: str = ""
    email: str = ""
    pin: str | None = Field(None, pattern=r"^\d{4,6}$")
    duress_pin: str | None = Field(None, pattern=r"^\d{4,6}$")
    groups: list[int] = []
    override: bool = False
    active: bool = True
    valid_from: float | None = None
    valid_until: float | None = None
    notes: str = ""


class CardholderPatch(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    department: str | None = None
    email: str | None = None
    pin: str | None = Field(None, pattern=r"^\d{4,6}$")
    duress_pin: str | None = Field(None, pattern=r"^(\d{4,6})?$")
    groups: list[int] | None = None
    override: bool | None = None
    active: bool | None = None
    valid_from: float | None = None
    valid_until: float | None = None
    notes: str | None = None


class WindowIn(BaseModel):
    days: int = Field(ge=1, le=127)
    start_min: int = Field(ge=0, le=1440)
    end_min: int = Field(ge=0, le=1440)


class ScheduleIn(BaseModel):
    name: str = Field(min_length=1)
    windows: list[WindowIn]


class GroupIn(BaseModel):
    name: str = Field(min_length=1)
    schedule_id: int
    doors: list[int] = []


class Announce(BaseModel):
    serial: str = Field(pattern=r"^LNT-[0-9A-F]{12}$")
    pubkey: str = Field(pattern=r"^[0-9a-f]{64}$")
    mac: str = ""
    firmware: str = ""
    controller: str = ""
    door: int = 0
    seq: int = 0  # sequence number of the last assignment the panel applied


class AdoptIn(BaseModel):
    pairing_code: str = Field(pattern=r"^\d{6}$")
    door_id: int = Field(ge=1, le=31)
    name: str = Field("", max_length=40)
    area: str = ""
    unlock_ms: int = Field(5000, ge=1000, le=30000)
    groups: list[int] = []


class CommandIn(BaseModel):
    command: str = Field(pattern="^(reboot|identify|screenshot|test_photo)$")


class AlarmAction(BaseModel):
    note: str = ""


class ModeIn(BaseModel):
    mode: int = Field(ge=0, le=2)


class OperatorIn(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=10)
    role: str = Field(pattern="^(admin|operator|viewer)$")


def create_app(store: Store, ctl: Controller, hub: Hub, udp_port: int) -> FastAPI:
    app = FastAPI(title="Lintel Access Control", docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    # ---- auth ------------------------------------------------------------------

    def operator_from_token(token: str | None) -> dict | None:
        if not token:
            return None
        th = hashlib.sha256(token.encode()).hexdigest()
        r = store.q1("SELECT o.* FROM sessions s JOIN operators o ON o.id = s.operator_id "
                     "WHERE s.token_hash=? AND s.expires>? AND o.active=1", (th, time.time()))
        return dict(r) if r else None

    def need(role: str):
        def dep(request: Request) -> dict:
            op = operator_from_token(request.cookies.get("lintel_session"))
            if op is None:
                raise HTTPException(401, "not signed in")
            if ROLES[op["role"]] < ROLES[role]:
                raise HTTPException(403, f"{role} role required")
            return op
        return dep

    viewer, operator, admin = need("viewer"), need("operator"), need("admin")

    def journal(op: dict, kind: str, detail: str, **kw: Any) -> None:
        ev = store.journal(kind, operator=op["username"], detail=detail, **kw)
        hub.publish({"type": "event", "event": ev})

    @app.post("/api/login")
    def login(body: Login, response: Response) -> dict:
        r = store.q1("SELECT * FROM operators WHERE username=? AND active=1", (body.username,))
        if r is None or not check_password(body.password, r["pw_hash"]):
            store.journal("operator.login_failed", operator=body.username, detail="bad credentials")
            raise HTTPException(401, "invalid username or password")
        token = secrets.token_urlsafe(32)
        store.x("INSERT INTO sessions(token_hash, operator_id, expires) VALUES(?, ?, ?)",
                (hashlib.sha256(token.encode()).hexdigest(), r["id"], time.time() + SESSION_S))
        response.set_cookie("lintel_session", token, httponly=True, samesite="strict", max_age=SESSION_S)
        journal(dict(r), "operator.login", "signed in")
        return {"username": r["username"], "role": r["role"]}

    @app.post("/api/logout")
    def logout(request: Request, response: Response) -> dict:
        token = request.cookies.get("lintel_session")
        if token:
            store.x("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
        response.delete_cookie("lintel_session")
        return {"ok": True}

    @app.get("/api/me")
    def me(op: dict = Depends(viewer)) -> dict:
        return {"username": op["username"], "role": op["role"], "site_name": store.setting("site_name")}

    # ---- overview ----------------------------------------------------------------

    def door_rows() -> list[dict]:
        out = []
        for r in store.q("SELECT d.id, d.name, d.area, d.unlock_ms, d.credential_mode, d.last_seen, d.last_ip, "
                         "d.rssi, v.serial, v.mac, v.firmware, v.controller, v.adopted_at "
                         "FROM doors d LEFT JOIN devices v ON v.door_id = d.id ORDER BY d.id"):
            d = dict(r)
            link = ctl.doors.get(d["id"])
            d["online"] = bool(link and link.online)
            d["rejects"] = link.rejects if link else 0
            out.append(d)
        return out

    @app.get("/api/overview")
    def overview(op: dict = Depends(viewer)) -> dict:
        midnight = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        counts = {r["kind"]: r["n"] for r in store.q(
            "SELECT kind, COUNT(*) n FROM events WHERE ts>=? GROUP BY kind", (midnight,))}
        return {
            "site_name": store.setting("site_name"),
            "mode": int(store.setting("site_mode", "0")),
            "doors": door_rows(),
            "active_alarms": store.q1("SELECT COUNT(*) n FROM alarms WHERE state='active'")["n"],
            "cardholders": store.q1("SELECT COUNT(*) n FROM cardholders WHERE active=1")["n"],
            "granted_today": counts.get("access.granted", 0),
            "denied_today": counts.get("access.denied", 0),
        }

    @app.post("/api/mode")
    def set_mode(body: ModeIn, op: dict = Depends(operator)) -> dict:
        ctl.set_mode(SiteMode(body.mode), op["username"])
        return {"mode": body.mode}

    # ---- doors -----------------------------------------------------------------------

    @app.get("/api/doors")
    def doors(op: dict = Depends(viewer)) -> list[dict]:
        return door_rows()

    @app.post("/api/doors")
    def add_door(body: DoorIn, op: dict = Depends(admin)) -> dict:
        key = secrets.token_bytes(16)
        try:
            store.x("INSERT INTO doors(id, name, area, key, unlock_ms) VALUES(?, ?, ?, ?, ?)",
                    (body.id, body.name, body.area, key, body.unlock_ms))
        except sqlite3.IntegrityError:
            raise HTTPException(409, f"door {body.id} already exists")
        ctl.load_door(body.id)
        journal(op, "door.created", f"door {body.id} '{body.name}' created", door_id=body.id)
        hub.publish({"type": "doors"})
        # The key is shown exactly once, for provisioning the panel.
        return {"id": body.id, "net_id": f"{store.secrets.net_id:08x}", "key": key.hex(), "udp_port": udp_port}

    @app.post("/api/doors/{door_id}/rekey")
    def rekey(door_id: int, op: dict = Depends(admin)) -> dict:
        key = secrets.token_bytes(16)
        if store.x("UPDATE doors SET key=?, tx_ceiling=0, rx_highest=0 WHERE id=?", (key, door_id)) == 0:
            raise HTTPException(404, "no such door")
        ctl.load_door(door_id)
        dev = store.q1("SELECT * FROM devices WHERE door_id=?", (door_id,))
        journal(op, "door.rekeyed", f"door {door_id} key rotated" + (" and sent to the panel" if dev else ""),
                door_id=door_id)
        if dev:
            queue_blob(dev, door_id, key)
            return {"id": door_id, "auto": True}
        return {"id": door_id, "net_id": f"{store.secrets.net_id:08x}", "key": key.hex(), "udp_port": udp_port}

    @app.patch("/api/doors/{door_id}")
    def patch_door(door_id: int, body: DoorPatch, op: dict = Depends(admin)) -> dict:
        fields = body.model_dump(exclude_none=True)
        groups_ = fields.pop("groups", None)
        if groups_ is not None:
            store.x("DELETE FROM access_group_doors WHERE door_id=?", (door_id,))
            for g in groups_:
                store.x("INSERT INTO access_group_doors(group_id, door_id) VALUES(?, ?)", (g, door_id))
            if not fields:
                journal(op, "door.updated", f"door {door_id} access groups updated", door_id=door_id)
                return {"ok": True}
        if not fields:
            return {"ok": True}
        sets = ", ".join(f"{k}=?" for k in fields)
        if store.x(f"UPDATE doors SET {sets} WHERE id=?", (*fields.values(), door_id)) == 0:
            raise HTTPException(404, "no such door")
        ctl.load_door(door_id)
        journal(op, "door.updated", f"door {door_id} updated: {', '.join(fields)}", door_id=door_id)
        hub.publish({"type": "doors"})
        return {"ok": True}

    @app.delete("/api/doors/{door_id}")
    def delete_door(door_id: int, op: dict = Depends(admin)) -> dict:
        store.x("DELETE FROM doors WHERE id=?", (door_id,))
        ctl.load_door(door_id)
        journal(op, "door.deleted", f"door {door_id} deleted", door_id=door_id)
        hub.publish({"type": "doors"})
        return {"ok": True}

    # ---- schedules & access groups --------------------------------------------------------

    @app.get("/api/schedules")
    def schedules(op: dict = Depends(viewer)) -> list[dict]:
        out = []
        for s in store.q("SELECT * FROM schedules ORDER BY name"):
            ws = [dict(w) for w in store.q("SELECT days, start_min, end_min FROM schedule_windows "
                                           "WHERE schedule_id=? ORDER BY id", (s["id"],))]
            out.append({**dict(s), "windows": ws})
        return out

    def write_windows(sid: int, windows: list[WindowIn]) -> None:
        store.x("DELETE FROM schedule_windows WHERE schedule_id=?", (sid,))
        for w in windows:
            store.x("INSERT INTO schedule_windows(schedule_id, days, start_min, end_min) VALUES(?, ?, ?, ?)",
                    (sid, w.days, w.start_min, w.end_min))

    @app.post("/api/schedules")
    def add_schedule(body: ScheduleIn, op: dict = Depends(admin)) -> dict:
        try:
            sid = store.x("INSERT INTO schedules(name) VALUES(?)", (body.name,))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "schedule name already used")
        write_windows(sid, body.windows)
        journal(op, "schedule.created", f"schedule '{body.name}' created")
        return {"id": sid}

    @app.put("/api/schedules/{sid}")
    def put_schedule(sid: int, body: ScheduleIn, op: dict = Depends(admin)) -> dict:
        store.x("UPDATE schedules SET name=? WHERE id=?", (body.name, sid))
        write_windows(sid, body.windows)
        journal(op, "schedule.updated", f"schedule '{body.name}' updated")
        return {"ok": True}

    @app.delete("/api/schedules/{sid}")
    def del_schedule(sid: int, op: dict = Depends(admin)) -> dict:
        try:
            store.x("DELETE FROM schedules WHERE id=?", (sid,))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "schedule is used by an access group")
        journal(op, "schedule.deleted", f"schedule {sid} deleted")
        return {"ok": True}

    @app.get("/api/groups")
    def groups(op: dict = Depends(viewer)) -> list[dict]:
        out = []
        for g in store.q("SELECT g.*, s.name schedule FROM access_groups g JOIN schedules s ON s.id=g.schedule_id "
                         "ORDER BY g.name"):
            doors_ = [r["door_id"] for r in store.q("SELECT door_id FROM access_group_doors WHERE group_id=?",
                                                    (g["id"],))]
            members = store.q1("SELECT COUNT(*) n FROM cardholder_groups WHERE group_id=?", (g["id"],))["n"]
            out.append({**dict(g), "doors": doors_, "members": members})
        return out

    def write_group_doors(gid: int, doors_: list[int]) -> None:
        store.x("DELETE FROM access_group_doors WHERE group_id=?", (gid,))
        for d in doors_:
            store.x("INSERT INTO access_group_doors(group_id, door_id) VALUES(?, ?)", (gid, d))

    @app.post("/api/groups")
    def add_group(body: GroupIn, op: dict = Depends(admin)) -> dict:
        try:
            gid = store.x("INSERT INTO access_groups(name, schedule_id) VALUES(?, ?)", (body.name, body.schedule_id))
            write_group_doors(gid, body.doors)
        except sqlite3.IntegrityError:
            raise HTTPException(409, "name in use, or unknown schedule/door")
        journal(op, "group.created", f"access group '{body.name}' created")
        return {"id": gid}

    @app.put("/api/groups/{gid}")
    def put_group(gid: int, body: GroupIn, op: dict = Depends(admin)) -> dict:
        try:
            store.x("UPDATE access_groups SET name=?, schedule_id=? WHERE id=?", (body.name, body.schedule_id, gid))
            write_group_doors(gid, body.doors)
        except sqlite3.IntegrityError:
            raise HTTPException(409, "name in use, or unknown schedule/door")
        journal(op, "group.updated", f"access group '{body.name}' updated")
        return {"ok": True}

    @app.delete("/api/groups/{gid}")
    def del_group(gid: int, op: dict = Depends(admin)) -> dict:
        store.x("DELETE FROM access_groups WHERE id=?", (gid,))
        journal(op, "group.deleted", f"access group {gid} deleted")
        return {"ok": True}

    # ---- cardholders -----------------------------------------------------------------------

    def cardholder_out(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["has_pin"] = d.pop("pin_tag") is not None
        d["has_duress"] = d.pop("duress_tag") is not None
        d["groups"] = [g["group_id"] for g in store.q("SELECT group_id FROM cardholder_groups WHERE cardholder_id=?",
                                                     (d["id"],))]
        last = store.q1("SELECT ts, door_id FROM events WHERE cardholder_id=? AND kind='access.granted' "
                        "ORDER BY seq DESC LIMIT 1", (d["id"],))
        d["last_access"] = dict(last) if last else None
        return d

    @app.get("/api/cardholders")
    def cardholders(q: str = "", op: dict = Depends(viewer)) -> list[dict]:
        like = f"%{q}%"
        rows = store.q("SELECT * FROM cardholders WHERE first_name LIKE ? OR last_name LIKE ? OR department LIKE ? "
                       "OR email LIKE ? ORDER BY last_name, first_name", (like, like, like, like))
        return [cardholder_out(r) for r in rows]

    def check_pins(pin: str | None, duress: str | None, exclude: int | None = None) -> None:
        if pin and duress and pin == duress:
            raise HTTPException(400, "duress PIN must differ from the PIN")
        for p in (pin, duress):
            if not p:
                continue
            if len(set(p)) == 1 or p in "0123456789" or p in "9876543210":
                raise HTTPException(400, f"PIN {p[:1]}*** is too easy to guess")
            tag = store.pin_tag(p)
            clash = store.q1("SELECT id FROM cardholders WHERE (pin_tag=? OR duress_tag=?) AND id IS NOT ?",
                             (tag, tag, exclude))
            if clash:
                raise HTTPException(409, "that PIN is already assigned; choose another")

    def write_groups(cid: int, gs: list[int]) -> None:
        store.x("DELETE FROM cardholder_groups WHERE cardholder_id=?", (cid,))
        for g in gs:
            store.x("INSERT INTO cardholder_groups(cardholder_id, group_id) VALUES(?, ?)", (cid, g))

    @app.post("/api/cardholders")
    def add_cardholder(body: CardholderIn, op: dict = Depends(admin)) -> dict:
        check_pins(body.pin, body.duress_pin)
        cid = store.x(
            "INSERT INTO cardholders(first_name, last_name, department, email, pin_tag, duress_tag, override, active, "
            "valid_from, valid_until, notes, created) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (body.first_name, body.last_name, body.department, body.email,
             store.pin_tag(body.pin) if body.pin else None,
             store.pin_tag(body.duress_pin) if body.duress_pin else None,
             int(body.override), int(body.active), body.valid_from, body.valid_until, body.notes, time.time()))
        write_groups(cid, body.groups)
        journal(op, "cardholder.created", f"{body.first_name} {body.last_name} created", cardholder_id=cid)
        return cardholder_out(store.q1("SELECT * FROM cardholders WHERE id=?", (cid,)))

    @app.patch("/api/cardholders/{cid}")
    def patch_cardholder(cid: int, body: CardholderPatch, op: dict = Depends(admin)) -> dict:
        if store.q1("SELECT 1 FROM cardholders WHERE id=?", (cid,)) is None:
            raise HTTPException(404, "no such cardholder")
        f = body.model_dump(exclude_unset=True)
        check_pins(f.get("pin"), f.get("duress_pin") or None, exclude=cid)
        changed = []
        if "pin" in f:
            store.x("UPDATE cardholders SET pin_tag=? WHERE id=?", (store.pin_tag(f.pop("pin")), cid))
            changed.append("PIN")
        if "duress_pin" in f:
            dp = f.pop("duress_pin")
            store.x("UPDATE cardholders SET duress_tag=? WHERE id=?", (store.pin_tag(dp) if dp else None, cid))
            changed.append("duress PIN")
        if "groups" in f:
            write_groups(cid, f.pop("groups") or [])
            changed.append("groups")
        for k in ("override", "active"):
            if k in f:
                f[k] = int(bool(f[k]))
        if f:
            sets = ", ".join(f"{k}=?" for k in f)
            store.x(f"UPDATE cardholders SET {sets} WHERE id=?", (*f.values(), cid))
            changed += list(f)
        journal(op, "cardholder.updated", f"cardholder {cid} updated: {', '.join(changed)}", cardholder_id=cid)
        return cardholder_out(store.q1("SELECT * FROM cardholders WHERE id=?", (cid,)))

    @app.delete("/api/cardholders/{cid}")
    def delete_cardholder(cid: int, op: dict = Depends(admin)) -> dict:
        r = store.q1("SELECT first_name, last_name FROM cardholders WHERE id=?", (cid,))
        if r is None:
            raise HTTPException(404, "no such cardholder")
        store.x("DELETE FROM cardholders WHERE id=?", (cid,))
        journal(op, "cardholder.deleted", f"{r['first_name']} {r['last_name']} deleted", cardholder_id=cid)
        return {"ok": True}

    # ---- events, reports, journal ----------------------------------------------------------

    def event_query(limit: int, before: int | None, door: int | None, kind: str | None, cardholder: int | None,
                    since: float | None, until: float | None) -> list[dict]:
        where, args = ["1=1"], []
        for cond, val in (("e.seq<?", before), ("e.door_id=?", door), ("e.cardholder_id=?", cardholder),
                          ("e.ts>=?", since), ("e.ts<?", until)):
            if val is not None:
                where.append(cond)
                args.append(val)
        if kind:
            where.append("e.kind LIKE ?")
            args.append(kind.replace("*", "%"))
        rows = store.q("SELECT e.*, d.name door_name, c.first_name || ' ' || c.last_name cardholder_name "
                       "FROM events e LEFT JOIN doors d ON d.id=e.door_id "
                       "LEFT JOIN cardholders c ON c.id=e.cardholder_id "
                       f"WHERE {' AND '.join(where)} ORDER BY e.seq DESC LIMIT ?", (*args, limit))
        return [dict(r) for r in rows]

    @app.get("/api/events")
    def events(limit: int = 100, before: int | None = None, door: int | None = None, kind: str | None = None,
               cardholder: int | None = None, since: float | None = None, until: float | None = None,
               op: dict = Depends(viewer)) -> list[dict]:
        return event_query(min(limit, 1000), before, door, kind, cardholder, since, until)

    @app.get("/api/events.csv")
    def events_csv(door: int | None = None, kind: str | None = None, cardholder: int | None = None,
                   since: float | None = None, until: float | None = None, op: dict = Depends(viewer)):
        rows = event_query(100000, None, door, kind, cardholder, since, until)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["seq", "time", "kind", "door", "cardholder", "decision", "reason", "operator", "detail", "photo",
                    "link"])
        for r in rows:
            w.writerow([r["seq"], datetime.fromtimestamp(r["ts"]).isoformat(timespec="seconds"), r["kind"],
                        r["door_name"] or "", r["cardholder_name"] or "", r["decision"] or "", r["reason"] or "",
                        r["operator"] or "", r["detail"], "yes" if r["photo"] else "", r["link"]])
        journal(op, "report.exported", f"event report exported ({len(rows)} rows)")
        return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                                 headers={"Content-Disposition": "attachment; filename=lintel-events.csv"})

    @app.get("/api/journal/verify")
    def verify(op: dict = Depends(viewer)) -> dict:
        return store.verify_journal()

    # ---- alarms -------------------------------------------------------------------------------

    @app.get("/api/alarms")
    def alarms(state: str = "open", op: dict = Depends(viewer)) -> list[dict]:
        cond = "a.state!='cleared'" if state == "open" else "1=1"
        rows = store.q("SELECT a.*, d.name door_name FROM alarms a LEFT JOIN doors d ON d.id=a.door_id "
                       f"WHERE {cond} ORDER BY a.state='acknowledged', a.priority, a.id DESC LIMIT 200")
        return [dict(r) for r in rows]

    def alarm_action(aid: int, op: dict, new_state: str, note: str) -> dict:
        r = store.q1("SELECT * FROM alarms WHERE id=?", (aid,))
        if r is None:
            raise HTTPException(404, "no such alarm")
        store.x("UPDATE alarms SET state=?, ack_by=?, ack_ts=?, note=? WHERE id=?",
                (new_state, op["username"], time.time(), note or r["note"], aid))
        journal(op, f"alarm.{new_state}", f"alarm #{aid} '{r['title']}' {new_state}" + (f": {note}" if note else ""),
                door_id=r["door_id"])
        hub.publish({"type": "alarms"})
        return {"ok": True}

    @app.post("/api/alarms/{aid}/ack")
    def ack(aid: int, body: AlarmAction, op: dict = Depends(operator)) -> dict:
        return alarm_action(aid, op, "acknowledged", body.note)

    @app.post("/api/alarms/{aid}/clear")
    def clear(aid: int, body: AlarmAction, op: dict = Depends(operator)) -> dict:
        return alarm_action(aid, op, "cleared", body.note)

    # ---- operators -------------------------------------------------------------------------------

    @app.get("/api/operators")
    def operators(op: dict = Depends(admin)) -> list[dict]:
        return [dict(r) for r in store.q("SELECT id, username, role, active, created FROM operators ORDER BY username")]

    @app.post("/api/operators")
    def add_operator(body: OperatorIn, op: dict = Depends(admin)) -> dict:
        try:
            oid = store.x("INSERT INTO operators(username, pw_hash, role, created) VALUES(?, ?, ?, ?)",
                          (body.username, hash_password(body.password), body.role, time.time()))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "username taken")
        journal(op, "operator.created", f"operator '{body.username}' ({body.role}) created")
        return {"id": oid}

    @app.delete("/api/operators/{oid}")
    def del_operator(oid: int, op: dict = Depends(admin)) -> dict:
        if oid == op["id"]:
            raise HTTPException(400, "you cannot delete yourself")
        store.x("DELETE FROM operators WHERE id=?", (oid,))
        journal(op, "operator.deleted", f"operator {oid} deleted")
        return {"ok": True}

    # ---- photos ------------------------------------------------------------------------------------

    @app.post("/api/door/{door_id}/photo")
    async def upload_photo(door_id: int, request: Request) -> dict:
        """Called by a panel right after a grant. Signed with a key derived from
        the door key, and bound to the request counter of that grant."""
        link = ctl.doors.get(door_id)
        if link is None:
            raise HTTPException(404, "unknown door")
        body = await request.body()
        if not 0 < len(body) <= 2_000_000:
            raise HTTPException(413, "photo too large")
        try:
            req = int(request.headers["x-lintel-req"])
            mac = bytes.fromhex(request.headers["x-lintel-mac"])
        except (KeyError, ValueError):
            raise HTTPException(400, "missing signature")
        digest = hashlib.sha256(body).digest()
        want = hmac.new(photo_key(link.key), f"{door_id}:{req}:".encode() + digest, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, want):
            store.journal("photo.rejected", door_id=door_id, detail="bad signature")
            raise HTTPException(403, "bad signature")
        ev = store.q1("SELECT * FROM events WHERE door_id=? AND req_ctr=? AND kind='access.granted' "
                      "ORDER BY seq DESC LIMIT 1", (door_id, req))
        if ev is None or ev["photo"] or time.time() - ev["ts"] > 120:
            raise HTTPException(409, "no grant awaiting a photo")
        name = store.q1("SELECT first_name || ' ' || last_name n FROM cardholders WHERE id=?",
                        (ev["cardholder_id"],))
        rel = stamp_photo(store.data_dir / "photos", body, ev["seq"], ev["ts"], link.name,
                          name["n"] if name else "unknown")
        store.x("UPDATE events SET photo=? WHERE seq=?", (rel, ev["seq"]))
        # The photo's hash goes into the chain, so swapping the image later is detectable.
        pj = store.journal("photo.attached", door_id=door_id, cardholder_id=ev["cardholder_id"],
                           detail=f"entry photo for event #{ev['seq']} sha256={digest.hex()}", req_ctr=req)
        hub.publish({"type": "photo", "seq": ev["seq"]})
        hub.publish({"type": "event", "event": pj})
        return {"ok": True, "event": ev["seq"]}

    @app.post("/api/doors/{door_id}/command")
    def door_command(door_id: int, body: CommandIn, op: dict = Depends(operator)) -> dict:
        if door_id not in ctl.doors:
            raise HTTPException(404, "no such door")
        if body.command == "reboot" and op["role"] != "admin":
            raise HTTPException(403, "admin role required to reboot a panel")
        cid = ctl.queue_command(door_id, COMMANDS[body.command])
        journal(op, "door.command", f"{body.command.replace('_', ' ')} sent to door {door_id}", door_id=door_id)
        return {"ok": True, "command_id": cid}

    @app.post("/api/door/{door_id}/media")
    async def upload_media(door_id: int, request: Request, kind: str) -> dict:
        """Screenshots and test photos from a panel, signed like entry photos."""
        if kind not in ("screenshot", "test_photo"):
            raise HTTPException(400, "unknown media kind")
        link = ctl.doors.get(door_id)
        if link is None:
            raise HTTPException(404, "unknown door")
        body = await request.body()
        if not 0 < len(body) <= 3_000_000:
            raise HTTPException(413, "too large")
        try:
            ref = int(request.headers["x-lintel-req"])
            mac = bytes.fromhex(request.headers["x-lintel-mac"])
        except (KeyError, ValueError):
            raise HTTPException(400, "missing signature")
        want = hmac.new(photo_key(link.key), f"{kind}:{door_id}:{ref}:".encode() + hashlib.sha256(body).digest(),
                        hashlib.sha256).digest()
        if not hmac.compare_digest(mac, want):
            raise HTTPException(403, "bad signature")
        out = store.data_dir / "diag"
        out.mkdir(exist_ok=True)
        (out / f"door{door_id}_{kind}.jpg").write_bytes(body)
        store.x("UPDATE doors SET diag_ts=diag_ts WHERE id=?", (door_id,))
        hub.publish({"type": "media", "door": door_id, "kind": kind})
        return {"ok": True}

    @app.get("/api/doors/{door_id}/media/{kind}.jpg")
    def get_media(door_id: int, kind: str, op: dict = Depends(viewer)):
        f = store.data_dir / "diag" / f"door{door_id}_{kind}.jpg"
        if kind not in ("screenshot", "test_photo") or not f.exists():
            raise HTTPException(404, "none yet")
        return FileResponse(f, media_type="image/jpeg", headers={"Cache-Control": "no-store"})

    @app.get("/api/photos/{seq}.jpg")
    def photo(seq: int, op: dict = Depends(viewer)):
        r = store.q1("SELECT photo FROM events WHERE seq=?", (seq,))
        if r is None or not r["photo"]:
            raise HTTPException(404, "no photo")
        return FileResponse(store.data_dir / "photos" / r["photo"], media_type="image/jpeg")

    # ---- device adoption ------------------------------------------------------------------------

    def queue_blob(dev: Any, door_id: int, key: bytes) -> None:
        """Seal a door assignment (or, with door_id 0, an unassignment) to the
        panel's public key. The controller hands it over on the next announce."""
        seq = dev["adopt_seq"] + 1
        blob = adopt.seal(bytes(dev["pubkey"]), door_id, store.secrets.net_id, key, seq)
        store.x("UPDATE devices SET adopt_seq=?, pending_blob=?, pending_door=? WHERE serial=?",
                (seq, blob, door_id, dev["serial"]))

    def device_row(r: Any) -> dict:
        d = dict(r)
        d["pubkey"] = bytes(d["pubkey"]).hex()
        d["pending"] = d.pop("pending_blob") is not None
        d["online"] = time.time() - d["last_seen"] < 20
        return d

    @app.post("/api/devices/announce")
    def announce(body: Announce, request: Request) -> dict:
        """Called by door controllers for every panel they can see. No operator
        login: announcing only lists a device; adopting it needs an admin and
        the pairing code from the panel's own screen."""
        now = time.time()
        pk = bytes.fromhex(body.pubkey)
        dev = store.q1("SELECT * FROM devices WHERE serial=?", (body.serial,))
        controller = body.controller or (request.client.host if request.client else "")
        if dev is None:
            if store.q1("SELECT COUNT(*) n FROM devices WHERE door_id IS NULL")["n"] >= 64:
                raise HTTPException(429, "too many unassigned devices")
            store.x("INSERT INTO devices(serial, pubkey, mac, firmware, controller, first_seen, last_seen, "
                    "reported_door) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    (body.serial, pk, body.mac, body.firmware, controller, now, now, body.door))
            ev = store.journal("device.discovered", detail=f"{body.serial} ({body.mac}) seen via {controller}")
            hub.publish({"type": "event", "event": ev})
            hub.publish({"type": "devices"})
            return {"state": "unassigned"}
        if bytes(dev["pubkey"]) != pk:
            if dev["door_id"] is not None:
                ev = store.journal("device.identity_mismatch", door_id=dev["door_id"],
                                   detail=f"{body.serial} announced a different key: possible clone or swap")
                al = store.raise_alarm(1, "device.identity", f"Identity mismatch for {body.serial}",
                                       door_id=dev["door_id"], event_seq=ev["seq"])
                hub.publish({"type": "alarm", "alarm": al})
                raise HTTPException(409, "device identity does not match the adopted key")
            store.x("UPDATE devices SET pubkey=? WHERE serial=?", (pk, body.serial))
        store.x("UPDATE devices SET mac=?, firmware=?, controller=?, last_seen=?, reported_door=? WHERE serial=?",
                (body.mac, body.firmware, controller, now, body.door, body.serial))
        dev = store.q1("SELECT * FROM devices WHERE serial=?", (body.serial,))
        if dev["pending_blob"] is not None:
            if body.seq >= dev["adopt_seq"] and body.door == (dev["pending_door"] or 0):
                # The panel now reports the assignment we sent: delivered.
                store.x("UPDATE devices SET pending_blob=NULL, pending_door=NULL WHERE serial=?", (body.serial,))
                what = f"door {body.door}" if body.door else "unassignment"
                ev = store.journal("device.provisioned", door_id=body.door or None,
                                   detail=f"{body.serial} confirmed {what}")
                hub.publish({"type": "event", "event": ev})
                hub.publish({"type": "devices"})
                hub.publish({"type": "doors"})
            else:
                return {"state": "provisioning", "provision": bytes(dev["pending_blob"]).hex()}
        return {"state": "assigned" if dev["door_id"] else "unassigned"}

    @app.get("/api/devices")
    def devices(op: dict = Depends(viewer)) -> list[dict]:
        return [device_row(r) for r in store.q("SELECT * FROM devices ORDER BY door_id IS NOT NULL, first_seen DESC")]

    @app.post("/api/devices/{serial}/adopt")
    def adopt_device(serial: str, body: AdoptIn, op: dict = Depends(admin)) -> dict:
        dev = store.q1("SELECT * FROM devices WHERE serial=?", (serial,))
        if dev is None:
            raise HTTPException(404, "no such device")
        if dev["door_id"] is not None:
            raise HTTPException(409, "device is already assigned")
        if not hmac.compare_digest(adopt.pairing_code(bytes(dev["pubkey"])), body.pairing_code):
            store.journal("device.adopt_failed", operator=op["username"], detail=f"{serial}: wrong pairing code")
            raise HTTPException(400, "pairing code does not match the code on the panel")
        door = store.q1("SELECT * FROM doors WHERE id=?", (body.door_id,))
        if door is not None and store.q1("SELECT 1 FROM devices WHERE door_id=?", (body.door_id,)):
            raise HTTPException(409, f"door {body.door_id} already has a device")
        key = secrets.token_bytes(16)
        if door is None:
            store.x("INSERT INTO doors(id, name, area, key, unlock_ms) VALUES(?, ?, ?, ?, ?)",
                    (body.door_id, body.name or f"Door {body.door_id}", body.area, key, body.unlock_ms))
        else:
            store.x("UPDATE doors SET key=?, tx_ceiling=0, rx_highest=0 WHERE id=?", (key, body.door_id))
        for g in body.groups:
            store.x("INSERT OR IGNORE INTO access_group_doors(group_id, door_id) VALUES(?, ?)", (g, body.door_id))
        store.x("UPDATE devices SET door_id=?, adopted_at=? WHERE serial=?", (body.door_id, time.time(), serial))
        queue_blob(store.q1("SELECT * FROM devices WHERE serial=?", (serial,)), body.door_id, key)
        ctl.load_door(body.door_id)
        journal(op, "device.adopted", f"{serial} adopted as door {body.door_id}", door_id=body.door_id)
        hub.publish({"type": "devices"})
        hub.publish({"type": "doors"})
        return {"ok": True, "door_id": body.door_id}

    @app.post("/api/doors/{door_id}/unassign")
    def unassign(door_id: int, op: dict = Depends(admin)) -> dict:
        dev = store.q1("SELECT * FROM devices WHERE door_id=?", (door_id,))
        if dev is None:
            raise HTTPException(404, "no device on this door")
        # Rotate the door key so the detached panel's old key is worthless,
        # and tell the panel to forget its assignment.
        store.x("UPDATE doors SET key=?, tx_ceiling=0, rx_highest=0 WHERE id=?", (secrets.token_bytes(16), door_id))
        store.x("UPDATE devices SET door_id=NULL, adopted_at=NULL WHERE serial=?", (dev["serial"],))
        queue_blob(store.q1("SELECT * FROM devices WHERE serial=?", (dev["serial"],)), 0, bytes(16))
        ctl.load_door(door_id)
        journal(op, "device.unassigned", f"{dev['serial']} detached from door {door_id}", door_id=door_id)
        hub.publish({"type": "devices"})
        hub.publish({"type": "doors"})
        return {"ok": True}

    @app.delete("/api/devices/{serial}")
    def forget_device(serial: str, op: dict = Depends(admin)) -> dict:
        if store.q1("SELECT 1 FROM devices WHERE serial=? AND door_id IS NOT NULL", (serial,)):
            raise HTTPException(409, "unassign the device from its door first")
        store.x("DELETE FROM devices WHERE serial=?", (serial,))
        journal(op, "device.forgotten", f"{serial} removed from the inventory")
        hub.publish({"type": "devices"})
        return {"ok": True}

    @app.get("/api/doors/{door_id}")
    def door_detail(door_id: int, op: dict = Depends(viewer)) -> dict:
        row = next((d for d in door_rows() if d["id"] == door_id), None)
        if row is None:
            raise HTTPException(404, "no such door")
        row["groups"] = [dict(g) for g in store.q(
            "SELECT g.id, g.name, s.name schedule FROM access_group_doors gd JOIN access_groups g ON g.id = gd.group_id "
            "JOIN schedules s ON s.id = g.schedule_id WHERE gd.door_id=? ORDER BY g.name", (door_id,))]
        row["recent"] = event_query(15, None, door_id, None, None, None, None)
        extra = store.q1("SELECT diag, diag_ts FROM doors WHERE id=?", (door_id,))
        row["diag"] = json.loads(extra["diag"]) if extra and extra["diag"] else None
        row["diag_ts"] = extra["diag_ts"] if extra else None
        row["media"] = {k: (store.data_dir / "diag" / f"door{door_id}_{k}.jpg").exists()
                        for k in ("screenshot", "test_photo")}
        midnight = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        row["today"] = {r["kind"]: r["n"] for r in store.q(
            "SELECT kind, COUNT(*) n FROM events WHERE door_id=? AND ts>=? GROUP BY kind", (door_id, midnight))}
        return row

    # ---- live updates & page -----------------------------------------------------------------------------

    @app.websocket("/ws")
    async def ws(sock: WebSocket) -> None:
        if operator_from_token(sock.cookies.get("lintel_session")) is None:
            await sock.close(code=4401)
            return
        await sock.accept()
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        hub.queues.add(q)
        try:
            while True:
                await sock.send_json(await q.get())
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            hub.queues.discard(q)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return (STATIC / "index.html").read_text(encoding="utf-8")

    return app
