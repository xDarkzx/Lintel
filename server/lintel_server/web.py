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

from . import adopt, notify
from .controller import Controller, photo_key
from .photos import stamp_photo
from .protocol import COMMANDS, SiteMode
from .security import (SECURITY_HEADERS, BodyLimit, LoginThrottle, totp_new_secret, totp_uri, totp_verify)
from .store import Store, check_password, hash_password

STATIC = Path(__file__).parent / "static"
SESSION_S = 12 * 3600
IDLE_S = 30 * 60
WS_RECHECK_S = 30  # the live feed re-checks its session at least this often
COOKIE = "__Host-lintel_session"  # HTTPS only, host-locked, path=/
MAX_IMAGE_PIXELS = 24_000_000
# A PIN entry's face counts as someone else only when it is clearly a face
# and clearly unlike every face enrolled for that PIN (match threshold 0.42).
PLAN_MAX_SIDE = 4096  # floor plans are stored no larger than this on their long side
IDENTITY_MIN_DETECT = 0.90
IDENTITY_MISMATCH_BELOW = 0.25
DUMMY_HASH = hash_password("not-a-real-password")  # equalises sign-in timing for unknown users


def csv_safe(v: Any) -> Any:
    """Neutralise spreadsheet formulas in exported cells (CSV injection)."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v
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
    code: str = ""


class CodeIn(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


class SettingsIn(BaseModel):
    site_name: str | None = Field(None, min_length=1, max_length=60)
    photo_retention_days: int | None = Field(None, ge=1, le=3650)
    rekey_days: int | None = Field(None, ge=1, le=365)
    require_admin_mfa: bool | None = None
    tailgate_detection: bool | None = None


class PasswordIn(BaseModel):
    current: str
    new: str = Field(min_length=12)


class DoorIn(BaseModel):
    id: int = Field(ge=1, le=31)
    name: str = Field(min_length=1, max_length=40)
    area: str = ""
    unlock_ms: int = Field(5000, ge=1000, le=30000)


class DoorPatch(BaseModel):
    name: str | None = None
    area: str | None = None
    unlock_ms: int | None = Field(None, ge=1000, le=30000)
    credential_mode: str | None = Field(None, pattern="^(pin|card|card_or_pin|card_and_pin|face|face_and_pin)$")
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
    observe_holidays: bool = True


class HolidayIn(BaseModel):
    day: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    name: str = Field(min_length=1, max_length=60)


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
    command: str = Field(pattern="^(reboot|identify|screenshot|test_photo|unlock)$")
    reason: str = Field("", max_length=200)


class BackupIn(BaseModel):
    passphrase: str = Field(min_length=16, max_length=200)
    password: str
    include_photos: bool = False


class AlarmAction(BaseModel):
    note: str = ""


class ModeIn(BaseModel):
    mode: int = Field(ge=0, le=2)


class OperatorIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=12, max_length=200)
    role: str = Field(pattern="^(admin|operator|viewer)$")


class OperatorPatch(BaseModel):
    role: str | None = Field(None, pattern="^(admin|operator|viewer)$")
    active: bool | None = None
    password: str | None = Field(None, min_length=12, max_length=200)
    reset_mfa: bool = False


class WebhookIn(BaseModel):
    url: str = Field("", max_length=500, pattern=r"^(https://\S+)?$")
    min_priority: int = Field(1, ge=1, le=4)


class CardEnrolIn(BaseModel):
    door_id: int = Field(ge=1, le=31)


class FloorIn(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    level: int = Field(0, ge=-10, le=200)


class LocationIn(BaseModel):
    floor_id: int | None = None  # None takes the door off the map
    x: float = Field(0.5, ge=0, le=1)
    y: float = Field(0.5, ge=0, le=1)


class LockIn(BaseModel):
    locked: bool


def create_app(store: Store, ctl: Controller, hub: Hub, udp_port: int, faces: Any = None,
               people: Any = None, live: Any = None) -> FastAPI:
    import os
    docs = os.environ.get("LINTEL_API_DOCS") == "1"  # the API map is only published when asked for
    app = FastAPI(title="Lintel Access Control", docs_url="/api/docs" if docs else None, redoc_url=None,
                  openapi_url="/api/openapi.json" if docs else None)
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    throttle = LoginThrottle()
    watch = None
    if people is not None:
        from .tailgate import WatchManager
        watch = WatchManager(store, people, hub.publish, stamp_photo)
    enrolment = None
    if faces is not None and live is not None:
        from .liveness import EnrolmentService
        enrolment = EnrolmentService(faces, live)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        # Cross-site request defence in depth (cookies are SameSite=Strict too):
        # a state-changing call carrying an Origin must come from this host.
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin and origin.split("://", 1)[-1] != request.headers.get("host", ""):
                return Response('{"detail":"cross-origin request refused"}', status_code=403,
                                media_type="application/json")
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            if k == "Content-Security-Policy" and request.url.path.startswith("/api/docs"):
                continue  # Swagger UI loads its own assets
            response.headers.setdefault(k, v)
        if request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if request.url.path.startswith("/api/"):
            # Cardholder data, photos and audit records never go into a browser or proxy cache.
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.add_middleware(BodyLimit)

    def controller_auth(request: Request) -> None:
        """Door controllers present the site's controller token."""
        got = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not got or not hmac.compare_digest(got, store.secrets.controller_token):
            raise HTTPException(401, "controller token required")

    # ---- auth ------------------------------------------------------------------

    def operator_from_token(token: str | None, touch: bool = True) -> dict | None:
        """The signed-in operator, or None. `touch` counts this as activity for
        the idle timeout; a background re-check must not keep a session alive."""
        if not token:
            return None
        th = hashlib.sha256(token.encode()).hexdigest()
        now = time.time()
        r = store.q1("SELECT o.*, s.last_seen FROM sessions s JOIN operators o ON o.id = s.operator_id "
                     "WHERE s.token_hash=? AND s.expires>? AND o.active=1", (th, now))
        if r is None:
            return None
        if r["last_seen"] and now - r["last_seen"] > IDLE_S:
            store.x("DELETE FROM sessions WHERE token_hash=?", (th,))
            return None
        if touch:
            store.x("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, th))
        return dict(r)

    def session_token(request: Request) -> str | None:
        return request.cookies.get(COOKIE) or request.cookies.get("lintel_session")

    def need(role: str):
        def dep(request: Request) -> dict:
            op = operator_from_token(session_token(request))
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
    def login(body: Login, request: Request, response: Response) -> dict:
        ip = request.client.host if request.client else "?"
        keys = (f"user:{body.username.lower()}", f"ip:{ip}")
        wait = throttle.blocked(*keys)
        if wait:
            raise HTTPException(429, f"too many failed sign-ins; try again in {wait // 60 + 1} min")
        r = store.q1("SELECT * FROM operators WHERE username=? AND active=1", (body.username,))
        # Always run one scrypt so a missing account is not faster than a wrong password.
        ok = check_password(body.password, r["pw_hash"] if r is not None else DUMMY_HASH) and r is not None
        if ok and r["totp_secret"]:
            if not body.code:
                return {"mfa_required": True}
            step = totp_verify(store.totp_secret(r["id"], r["totp_secret"]), body.code)
            ok = step is not None and step > r["totp_last_step"]  # each code works once
            if ok:
                store.x("UPDATE operators SET totp_last_step=? WHERE id=?", (step, r["id"]))
        if not ok:
            store.journal("operator.login_failed", operator=body.username, detail=f"bad credentials from {ip}")
            if throttle.fail(*keys):
                ev = store.journal("operator.login_locked", operator=body.username,
                                   detail=f"sign-in locked after repeated failures from {ip}")
                al = store.raise_alarm(2, "operator.bruteforce", f"Repeated failed sign-ins for '{body.username}'",
                                       event_seq=ev["seq"])
                hub.publish({"type": "alarm", "alarm": al})
            raise HTTPException(401, "invalid username, password or code")
        throttle.succeed(*keys)
        token = secrets.token_urlsafe(32)
        now = time.time()
        store.x("INSERT INTO sessions(token_hash, operator_id, expires, last_seen) VALUES(?, ?, ?, ?)",
                (hashlib.sha256(token.encode()).hexdigest(), r["id"], now + SESSION_S, now))
        store.x("UPDATE operators SET last_login=? WHERE id=?", (now, r["id"]))
        if request.url.scheme == "https":
            response.set_cookie(COOKIE, token, httponly=True, samesite="strict", max_age=SESSION_S, secure=True,
                                path="/")
        else:  # local development and tests only; production serves HTTPS exclusively
            response.set_cookie("lintel_session", token, httponly=True, samesite="strict", max_age=SESSION_S)
        journal(dict(r), "operator.login", f"signed in from {ip}" + (" with 2FA" if r["totp_secret"] else ""))
        nudge = r["role"] == "admin" and not r["totp_secret"] and store.setting("require_admin_mfa") == "1"
        return {"username": r["username"], "role": r["role"], "mfa_setup_required": nudge}

    @app.post("/api/me/mfa/setup")
    def mfa_setup(op: dict = Depends(viewer)) -> dict:
        if op["totp_secret"]:
            raise HTTPException(409, "two-factor sign-in is already on")
        secret = totp_new_secret()
        store.set_setting(f"pending_totp:{op['id']}", secret)
        uri = totp_uri(secret, op["username"])
        svg = ""
        try:
            import qrcode
            import qrcode.image.svg
            img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
            svg = img.to_string(encoding="unicode")
        except ImportError:
            pass
        return {"secret": secret, "uri": uri, "qr_svg": svg}

    @app.post("/api/me/mfa/confirm")
    def mfa_confirm(body: CodeIn, op: dict = Depends(viewer)) -> dict:
        secret = store.setting(f"pending_totp:{op['id']}")
        step = totp_verify(secret, body.code) if secret else None
        if step is None:
            raise HTTPException(400, "that code does not match; check the time on your phone")
        store.x("UPDATE operators SET totp_secret=?, totp_last_step=? WHERE id=?",
                (store.seal_totp(op["id"], secret), step, op["id"]))
        store.x("DELETE FROM settings WHERE key=?", (f"pending_totp:{op['id']}",))
        journal(op, "operator.mfa_enabled", "two-factor sign-in turned on")
        return {"ok": True}

    @app.post("/api/me/mfa/disable")
    def mfa_disable(body: CodeIn, op: dict = Depends(viewer)) -> dict:
        if not op["totp_secret"] or totp_verify(store.totp_secret(op["id"], op["totp_secret"]), body.code) is None:
            raise HTTPException(400, "a current code is required to turn two-factor off")
        store.x("UPDATE operators SET totp_secret=NULL WHERE id=?", (op["id"],))
        journal(op, "operator.mfa_disabled", "two-factor sign-in turned off")
        return {"ok": True}

    @app.post("/api/me/password")
    def change_password(body: PasswordIn, op: dict = Depends(viewer)) -> dict:
        if not check_password(body.current, op["pw_hash"]):
            raise HTTPException(400, "current password is wrong")
        store.x("UPDATE operators SET pw_hash=? WHERE id=?", (hash_password(body.new), op["id"]))
        store.x("DELETE FROM sessions WHERE operator_id=?", (op["id"],))
        journal(op, "operator.password_changed", "password changed; other sessions signed out")
        return {"ok": True}

    @app.get("/api/settings/webhook")
    def get_webhook(op: dict = Depends(admin)) -> dict:
        return {"url": store.setting("alarm_webhook"), "min_priority": int(store.setting("alarm_webhook_priority", "1"))}

    @app.put("/api/settings/webhook")
    def put_webhook(body: WebhookIn, op: dict = Depends(admin)) -> dict:
        if body.url:
            try:
                notify.resolve_webhook(body.url)
            except notify.WebhookError as e:
                raise HTTPException(400, str(e))
        store.set_setting("alarm_webhook", body.url)
        store.set_setting("alarm_webhook_priority", str(body.min_priority))
        journal(op, "settings.updated", "alarm webhook " + ("set" if body.url else "cleared"))
        return {"ok": True}

    @app.post("/api/settings/webhook/test")
    def test_webhook(op: dict = Depends(admin)) -> dict:
        if not store.setting("alarm_webhook"):
            raise HTTPException(400, "no webhook configured")
        ok, detail = notify.send(store, {"priority": 3, "title": "Test alarm from Lintel", "kind": "test",
                                         "door": None, "time": time.time()}, force=True)
        if not ok:
            raise HTTPException(502, f"webhook failed: {detail}")
        return {"ok": True}

    @app.post("/api/backup")
    def download_backup(body: BackupIn, op: dict = Depends(admin)):
        """Encrypted with a passphrase the admin chooses now and the server never keeps.
        Re-checks the admin's password: a walked-away session cannot export the site."""
        from .backup import BackupError, create_backup
        if not check_password(body.password, op["pw_hash"]):
            raise HTTPException(403, "password is wrong")

        class _Proxy:  # sqlite backup through the store's lock
            def backup(self, dst):
                store.backup_to(dst)

        try:
            blob = create_backup(store.data_dir, _Proxy(), body.passphrase, body.include_photos)
        except BackupError as e:
            raise HTTPException(400, str(e))
        store.set_setting("last_backup", str(time.time()))
        journal(op, "system.backup", f"encrypted backup downloaded ({len(blob) // 1024} KB"
                + (", with photos)" if body.include_photos else ")"))
        name = f"lintel-backup-{datetime.now():%Y%m%d-%H%M}.lbk"
        return Response(blob, media_type="application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})

    @app.get("/api/settings")
    def get_settings(op: dict = Depends(viewer)) -> dict:
        return {"site_name": store.setting("site_name"),
                "photo_retention_days": int(store.setting("photo_retention_days", "90")),
                "rekey_days": int(store.setting("rekey_days", "30")),
                "require_admin_mfa": store.setting("require_admin_mfa") == "1",
                "tailgate_detection": store.setting("tailgate_detection", "1") == "1",
                "tailgate_available": watch is not None,
                "last_backup": float(store.setting("last_backup") or 0) or None,
                "controller_token_hint": store.secrets.controller_token[:6] + "...",
                "tls_fingerprint": getattr(app.state, "tls_fingerprint", None)}

    @app.patch("/api/settings")
    def put_settings(body: SettingsIn, op: dict = Depends(admin)) -> dict:
        changed = []
        for k, v in body.model_dump(exclude_none=True).items():
            store.set_setting(k, ("1" if v else "0") if isinstance(v, bool) else str(v))
            changed.append(k)
        journal(op, "settings.updated", f"changed: {', '.join(changed)}")
        return {"ok": True}

    @app.post("/api/logout")
    def logout(request: Request, response: Response) -> dict:
        token = session_token(request)
        if token:
            store.x("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
        response.delete_cookie(COOKIE, path="/", secure=True)
        response.delete_cookie("lintel_session")
        return {"ok": True}

    @app.get("/api/me")
    def me(op: dict = Depends(viewer)) -> dict:
        return {"username": op["username"], "role": op["role"], "site_name": store.setting("site_name"),
                "mfa": bool(op["totp_secret"]), "require_admin_mfa": store.setting("require_admin_mfa") == "1"}

    # ---- overview ----------------------------------------------------------------

    def door_rows() -> list[dict]:
        out = []
        for r in store.q("SELECT d.id, d.name, d.area, d.unlock_ms, d.credential_mode, d.last_seen, d.last_ip, "
                         "d.rssi, d.floor_id, d.map_x, d.map_y, d.map_locked, "
                         "v.serial, v.mac, v.firmware, v.controller, v.adopted_at "
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
            store.x("INSERT INTO doors(id, name, area, key, unlock_ms, key_created) VALUES(?, ?, ?, ?, ?, ?)",
                    (body.id, body.name, body.area, store.seal_door_key(body.id, key), body.unlock_ms, time.time()))
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
        if store.x("UPDATE doors SET key=?, tx_ceiling=0, rx_highest=0, key_created=? WHERE id=?",
                   (store.seal_door_key(door_id, key), time.time(), door_id)) == 0:
            raise HTTPException(404, "no such door")
        ctl.load_door(door_id)
        dev = store.q1("SELECT * FROM devices WHERE door_id=?", (door_id,))
        journal(op, "door.rekeyed", f"door {door_id} key rotated" + (" and sent to the panel" if dev else ""),
                door_id=door_id)
        if dev:
            queue_blob(dev, door_id, key)
            return {"id": door_id, "auto": True}
        return {"id": door_id, "net_id": f"{store.secrets.net_id:08x}", "key": key.hex(), "udp_port": udp_port}

    def auto_rekey(door_id: int) -> None:
        dev = store.q1("SELECT * FROM devices WHERE door_id=?", (door_id,))
        if dev is None:
            return
        key = secrets.token_bytes(16)
        store.x("UPDATE doors SET key=?, tx_ceiling=0, rx_highest=0, key_created=? WHERE id=?",
                (store.seal_door_key(door_id, key), time.time(), door_id))
        ctl.load_door(door_id)
        queue_blob(dev, door_id, key)
        ev = store.journal("door.rekeyed", door_id=door_id, operator="system",
                           detail=f"scheduled key rotation sent to {dev['serial']}")
        hub.publish({"type": "event", "event": ev})

    app.state.auto_rekey = auto_rekey

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
            sid = store.x("INSERT INTO schedules(name, observe_holidays) VALUES(?, ?)",
                          (body.name, int(body.observe_holidays)))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "schedule name already used")
        write_windows(sid, body.windows)
        journal(op, "schedule.created", f"schedule '{body.name}' created")
        return {"id": sid}

    @app.put("/api/schedules/{sid}")
    def put_schedule(sid: int, body: ScheduleIn, op: dict = Depends(admin)) -> dict:
        store.x("UPDATE schedules SET name=?, observe_holidays=? WHERE id=?",
                (body.name, int(body.observe_holidays), sid))
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

    @app.get("/api/holidays")
    def holidays(op: dict = Depends(viewer)) -> list[dict]:
        return [dict(r) for r in store.q("SELECT * FROM holidays ORDER BY day")]

    @app.post("/api/holidays")
    def add_holiday(body: HolidayIn, op: dict = Depends(admin)) -> dict:
        try:
            datetime.strptime(body.day, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(422, "not a real date")
        try:
            hid = store.x("INSERT INTO holidays(day, name) VALUES(?, ?)", (body.day, body.name))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "that date is already a holiday")
        journal(op, "schedule.holiday_added", f"{body.day} {body.name}")
        return {"id": hid}

    @app.delete("/api/holidays/{hid}")
    def del_holiday(hid: int, op: dict = Depends(admin)) -> dict:
        r = store.q1("SELECT * FROM holidays WHERE id=?", (hid,))
        store.x("DELETE FROM holidays WHERE id=?", (hid,))
        if r:
            journal(op, "schedule.holiday_removed", f"{r['day']} {r['name']}")
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
        d["has_card"] = d.pop("card_tag", None) is not None
        d["faces"] = store.q1("SELECT COUNT(*) n FROM face_templates WHERE cardholder_id=?", (d["id"],))["n"]
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

    @app.post("/api/cardholders/import")
    async def import_cardholders(request: Request, op: dict = Depends(admin)) -> dict:
        """CSV with a header row: first_name,last_name,department,email,groups
        (groups separated by ';', matched by name). PINs are never imported:
        they are set individually so they never sit in a spreadsheet."""
        raw = (await request.body())[:2_000_000].decode("utf-8-sig", errors="replace")
        gid = {g["name"].lower(): g["id"] for g in store.q("SELECT id, name FROM access_groups")}
        added, skipped = 0, []
        for n, row in enumerate(csv.DictReader(io.StringIO(raw)), start=2):
            first = (row.get("first_name") or "").strip()
            if not first:
                skipped.append(f"line {n}: no first_name")
                continue
            groups_ = []
            for gname in (row.get("groups") or "").split(";"):
                if gname.strip():
                    if gname.strip().lower() not in gid:
                        skipped.append(f"line {n}: unknown group '{gname.strip()}'")
                        continue
                    groups_.append(gid[gname.strip().lower()])
            cid = store.x("INSERT INTO cardholders(first_name, last_name, department, email, created) "
                          "VALUES(?, ?, ?, ?, ?)", (first[:40], (row.get("last_name") or "").strip()[:40],
                                                    (row.get("department") or "").strip()[:60],
                                                    (row.get("email") or "").strip()[:120], time.time()))
            write_groups(cid, groups_)
            added += 1
        journal(op, "cardholder.imported", f"{added} cardholders imported" + (f", {len(skipped)} issues" if skipped else ""))
        return {"added": added, "issues": skipped[:50]}

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

    # ---- credentials: cards and faces ------------------------------------------------------

    def check_image(data: bytes) -> None:
        """Reject decompression bombs before any decoder allocates for them."""
        from PIL import Image, UnidentifiedImageError
        try:
            with Image.open(io.BytesIO(data)) as im:
                if im.width * im.height > MAX_IMAGE_PIXELS:
                    raise HTTPException(413, "image dimensions too large")
                if im.format not in ("JPEG", "PNG"):
                    raise HTTPException(415, "JPEG or PNG only")
        except (UnidentifiedImageError, OSError):
            raise HTTPException(400, "not a readable image")

    def need_faces() -> Any:
        if faces is None:
            raise HTTPException(503, "face recognition is not available: face models are not installed")
        return faces

    def templates() -> list[tuple[int, Any]]:
        import numpy as np
        return [(r["cardholder_id"], np.frombuffer(store.template(r["cardholder_id"], r["embedding"]), dtype=np.float32))
                for r in store.q("SELECT t.cardholder_id, t.embedding FROM face_templates t "
                                 "JOIN cardholders c ON c.id = t.cardholder_id WHERE c.active=1")]

    def enrol_face(cid: int, jpeg: bytes, source: str, op: dict) -> dict:
        from .faces import FaceError
        if store.q1("SELECT 1 FROM cardholders WHERE id=?", (cid,)) is None:
            raise HTTPException(404, "no such cardholder")
        check_image(jpeg)
        try:
            r = need_faces().analyse(jpeg)
        except FaceError as e:
            raise HTTPException(400, str(e))
        # Refuse a face that already matches someone else: one face, one identity.
        other, score = need_faces().best_match(r.embedding, [t for t in templates() if t[0] != cid])
        if other is not None:
            raise HTTPException(409, f"this face already matches another cardholder ({score:.2f})")
        store.x("INSERT INTO face_templates(cardholder_id, embedding, source, created) VALUES(?, ?, ?, ?)",
                (cid, store.seal_template(cid, r.embedding.tobytes()), source, time.time()))
        journal(op, "cardholder.face_enrolled", f"face template added from {source}", cardholder_id=cid)
        n = store.q1("SELECT COUNT(*) n FROM face_templates WHERE cardholder_id=?", (cid,))["n"]
        return {"ok": True, "faces": n, "detect_score": round(r.detect_score, 3)}

    @app.post("/api/cardholders/{cid}/faces")
    async def add_face(cid: int, request: Request, op: dict = Depends(admin)) -> dict:
        body = await request.body()
        if not 0 < len(body) <= 8_000_000:
            raise HTTPException(413, "image too large")
        return enrol_face(cid, body, "upload", op)

    @app.post("/api/cardholders/{cid}/faces/from-event/{seq}")
    def add_face_from_event(cid: int, seq: int, op: dict = Depends(admin)) -> dict:
        r = store.q1("SELECT photo FROM events WHERE seq=?", (seq,))
        if r is None or not r["photo"]:
            raise HTTPException(404, "that event has no photo")
        return enrol_face(cid, (store.data_dir / "photos" / r["photo"]).read_bytes(), f"event #{seq}", op)

    @app.post("/api/cardholders/{cid}/faces/enrolment")
    def start_enrolment(cid: int, op: dict = Depends(admin)) -> dict:
        """Guided enrolment: the server sets the steps, judges every frame and
        enrols only a live face that completed them all."""
        if enrolment is None:
            raise HTTPException(503, "guided enrolment unavailable: face or anti-spoofing models are not installed")
        if store.q1("SELECT 1 FROM cardholders WHERE id=?", (cid,)) is None:
            raise HTTPException(404, "no such cardholder")
        return enrolment.start(cid, op["username"]).view()

    def save_enrolment(e: Any, op: dict) -> None:
        from .liveness import REAL_MIN, EnrolmentService
        embs = EnrolmentService.chosen_templates(e)
        other, score = need_faces().best_match(embs[0], [t for t in templates() if t[0] != e.cardholder_id])
        if other is not None:
            e.state, e.message = "failed", "This face already matches another cardholder."
            journal(op, "cardholder.face_enrol_refused", f"live enrolment refused: face matches cardholder {other} "
                    f"({score:.2f})", cardholder_id=e.cardholder_id)
            return
        for emb in embs:
            store.x("INSERT INTO face_templates(cardholder_id, embedding, source, created) VALUES(?, ?, ?, ?)",
                    (e.cardholder_id, store.seal_template(e.cardholder_id, emb.tobytes()), "live enrolment", time.time()))
        live_scores = [s for s in e.real_scores if s >= REAL_MIN]
        journal(op, "cardholder.face_enrolled",
                f"guided enrolment with liveness: {len(embs)} templates, steps {' > '.join(e.steps)}, "
                f"{e.frames} frames, lowest live score {min(live_scores):.2f}", cardholder_id=e.cardholder_id)
        e.state, e.message = "saved", f"Face enrolled ({len(embs)} templates)"

    @app.post("/api/faces/enrolment/{sid}/frame")
    async def enrolment_frame(sid: str, request: Request, op: dict = Depends(admin)) -> dict:
        from starlette.concurrency import run_in_threadpool
        e = enrolment.get(sid) if enrolment is not None else None
        if e is None or e.operator != op["username"]:
            raise HTTPException(404, "no such enrolment session")
        body = await request.body()
        if not 0 < len(body) <= 2_000_000:
            raise HTTPException(413, "frame too large")
        check_image(body)

        def step() -> dict:
            # One frame at a time per session: judging a frame and saving the
            # result must not interleave, or two frames could both save.
            with e.lock:
                enrolment.frame(e, body)
                if e.state == "done":
                    save_enrolment(e, op)
                elif e.state == "failed" and not e.logged:
                    e.logged = True
                    journal(op, "cardholder.face_enrol_failed", f"live enrolment failed: {e.message}",
                            cardholder_id=e.cardholder_id)
                return e.view()

        return await run_in_threadpool(step)

    @app.delete("/api/cardholders/{cid}/faces")
    def clear_faces(cid: int, op: dict = Depends(admin)) -> dict:
        store.x("DELETE FROM face_templates WHERE cardholder_id=?", (cid,))
        journal(op, "cardholder.face_removed", "all face templates removed", cardholder_id=cid)
        return {"ok": True}

    @app.get("/api/cardholders/{cid}/photos")
    def cardholder_photos(cid: int, op: dict = Depends(viewer)) -> list[dict]:
        """Recent entry photos of this person, to enrol a face from."""
        return [dict(r) for r in store.q(
            "SELECT seq, ts, door_id FROM events WHERE cardholder_id=? AND photo IS NOT NULL "
            "ORDER BY seq DESC LIMIT 12", (cid,))]

    @app.post("/api/cardholders/{cid}/card/enrol")
    def enrol_card(cid: int, body: CardEnrolIn, op: dict = Depends(admin)) -> dict:
        if store.q1("SELECT 1 FROM cardholders WHERE id=?", (cid,)) is None:
            raise HTTPException(404, "no such cardholder")
        ctl.engine.start_card_enrolment(body.door_id, cid)
        journal(op, "cardholder.card_enrolment", f"waiting for a card at door {body.door_id}",
                cardholder_id=cid, door_id=body.door_id)
        return {"ok": True, "expires_in": 60}

    @app.delete("/api/cardholders/{cid}/card")
    def remove_card(cid: int, op: dict = Depends(admin)) -> dict:
        store.x("UPDATE cardholders SET card_tag=NULL WHERE id=?", (cid,))
        journal(op, "cardholder.card_removed", "card removed", cardholder_id=cid)
        return {"ok": True}

    @app.post("/api/door/{door_id}/face", dependencies=[Depends(controller_auth)])
    async def door_face(door_id: int, request: Request) -> dict:
        """A panel's face scan, relayed by its controller and signed like photos.
        The result is held for the CredReq that follows; the controller learns
        only whether a face was usable, never who it was."""
        from starlette.concurrency import run_in_threadpool
        from .faces import FaceError
        link = ctl.doors.get(door_id)
        if link is None:
            raise HTTPException(404, "unknown door")
        body = await request.body()
        if not 0 < len(body) <= 2_000_000:
            raise HTTPException(413, "face image too large")
        try:
            ref = int(request.headers["x-lintel-req"])
            mac = bytes.fromhex(request.headers["x-lintel-mac"])
        except (KeyError, ValueError):
            raise HTTPException(400, "missing signature")
        want = hmac.new(photo_key(link.key), f"face:{door_id}:{ref}:".encode() + hashlib.sha256(body).digest(),
                        hashlib.sha256).digest()
        if not hmac.compare_digest(mac, want) or ref == 0:
            raise HTTPException(403, "bad signature")
        check_image(body)
        # Model inference off the event loop, which also answers every keypad.
        try:
            r = await run_in_threadpool(need_faces().analyse, body)
        except FaceError as e:
            ctl.hold_face(door_id, ref, (None, 0.0, time.time(), body, str(e)))
            return {"ok": True, "face": False, "why": str(e)}
        cid, score = need_faces().best_match(r.embedding, templates())
        ctl.hold_face(door_id, ref, (cid, score, time.time(), body, None))
        return {"ok": True, "face": True}

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
            w.writerow([csv_safe(x) for x in (
                r["seq"], datetime.fromtimestamp(r["ts"]).isoformat(timespec="seconds"), r["kind"],
                r["door_name"] or "", r["cardholder_name"] or "", r["decision"] or "", r["reason"] or "",
                r["operator"] or "", r["detail"], "yes" if r["photo"] else "", r["link"])])
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
        return [dict(r) for r in store.q("SELECT id, username, role, active, created, last_login, "
                                         "totp_secret IS NOT NULL mfa FROM operators ORDER BY username")]

    @app.post("/api/operators")
    def add_operator(body: OperatorIn, op: dict = Depends(admin)) -> dict:
        try:
            oid = store.x("INSERT INTO operators(username, pw_hash, role, created) VALUES(?, ?, ?, ?)",
                          (body.username, hash_password(body.password), body.role, time.time()))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "username taken")
        journal(op, "operator.created", f"operator '{body.username}' ({body.role}) created")
        return {"id": oid}

    def admins_left(excluding: int) -> int:
        return store.q1("SELECT COUNT(*) n FROM operators WHERE role='admin' AND active=1 AND id!=?",
                        (excluding,))["n"]

    @app.delete("/api/operators/{oid}")
    def del_operator(oid: int, op: dict = Depends(admin)) -> dict:
        if oid == op["id"]:
            raise HTTPException(400, "you cannot delete yourself")
        target = store.q1("SELECT * FROM operators WHERE id=?", (oid,))
        if target is None:
            raise HTTPException(404, "no such operator")
        if target["role"] == "admin" and admins_left(oid) == 0:
            raise HTTPException(409, "cannot remove the last admin")
        store.x("DELETE FROM operators WHERE id=?", (oid,))
        journal(op, "operator.deleted", f"operator '{target['username']}' deleted")
        return {"ok": True}

    @app.patch("/api/operators/{oid}")
    def patch_operator(oid: int, body: OperatorPatch, op: dict = Depends(admin)) -> dict:
        target = store.q1("SELECT * FROM operators WHERE id=?", (oid,))
        if target is None:
            raise HTTPException(404, "no such operator")
        losing_admin = target["role"] == "admin" and (
            (body.role is not None and body.role != "admin") or body.active is False)
        if losing_admin and admins_left(oid) == 0:
            raise HTTPException(409, "cannot demote or disable the last admin")
        changed = []
        if body.role is not None and body.role != target["role"]:
            store.x("UPDATE operators SET role=? WHERE id=?", (body.role, oid))
            changed.append(f"role {target['role']} -> {body.role}")
        if body.active is not None and int(body.active) != target["active"]:
            store.x("UPDATE operators SET active=? WHERE id=?", (int(body.active), oid))
            changed.append("enabled" if body.active else "disabled")
        if body.password:
            store.x("UPDATE operators SET pw_hash=? WHERE id=?", (hash_password(body.password), oid))
            changed.append("password reset")
        if body.reset_mfa:
            store.x("UPDATE operators SET totp_secret=NULL WHERE id=?", (oid,))
            changed.append("two-factor reset")
        if changed:
            # Any change to an account ends its sessions.
            store.x("DELETE FROM sessions WHERE operator_id=?", (oid,))
            journal(op, "operator.updated", f"'{target['username']}': {', '.join(changed)}")
        return {"ok": True}

    # ---- photos ------------------------------------------------------------------------------------

    @app.post("/api/door/{door_id}/photo", dependencies=[Depends(controller_auth)])
    async def upload_photo(door_id: int, request: Request) -> dict:
        """Called by a panel right after a grant. Signed with a key derived from
        the door key, and bound to the request counter of that grant."""
        link = ctl.doors.get(door_id)
        if link is None:
            raise HTTPException(404, "unknown door")
        body = await request.body()
        if not 0 < len(body) <= 2_000_000:
            raise HTTPException(413, "photo too large")
        check_image(body)
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
        # Every attempt at the keypad is photographed: grants, denials and lockouts.
        ev = store.q1("SELECT * FROM events WHERE door_id=? AND req_ctr=? AND kind IN "
                      "('access.granted', 'access.denied', 'credential.enrolled') ORDER BY seq DESC LIMIT 1",
                      (door_id, req))
        if ev is None or ev["photo"] or time.time() - ev["ts"] > 120:
            raise HTTPException(409, "no attempt awaiting a photo")
        name = store.q1("SELECT first_name || ' ' || last_name n FROM cardholders WHERE id=?",
                        (ev["cardholder_id"],))
        rel = stamp_photo(store.data_dir / "photos", body, ev["seq"], ev["ts"], link.name,
                          name["n"] if name else ("LOCKOUT - unidentified" if ev["reason"] == "locked_out"
                                                  else "unrecognised"))
        store.x("UPDATE events SET photo=? WHERE seq=?", (rel, ev["seq"]))
        # The photo's hash goes into the chain, so swapping the image later is detectable.
        pj = store.journal("photo.attached", door_id=door_id, cardholder_id=ev["cardholder_id"],
                           detail=f"entry photo for event #{ev['seq']} sha256={digest.hex()}", req_ctr=req)
        hub.publish({"type": "photo", "seq": ev["seq"]})
        hub.publish({"type": "event", "event": pj})
        if faces is not None and ev["kind"] == "access.granted" and ev["cardholder_id"] is not None:
            import threading
            threading.Thread(target=check_identity, args=(dict(ev), body, link.name), daemon=True).start()
        return {"ok": True, "event": ev["seq"]}

    def check_identity(ev: dict, jpeg: bytes, door: str) -> None:
        """On a PIN grant, compare the face in the entry photo with the faces
        enrolled for that PIN's owner. A clear face that is plainly someone
        else suggests a shared or stolen PIN. Unclear photos are not evidence,
        so they never raise anything."""
        import logging
        from .faces import FaceError
        own = [t for t in templates() if t[0] == ev["cardholder_id"]]
        if not own:
            return
        try:
            r = faces.analyse(jpeg)
        except FaceError:
            return
        except Exception:
            logging.getLogger("lintel.faces").exception("identity check failed for event #%d", ev["seq"])
            return
        if r.detect_score < IDENTITY_MIN_DETECT:
            return
        _, score = faces.best_match(r.embedding, own)
        if score >= IDENTITY_MISMATCH_BELOW:
            return
        who = store.q1("SELECT first_name || ' ' || last_name n FROM cardholders WHERE id=?", (ev["cardholder_id"],))
        name = who["n"] if who else f"cardholder {ev['cardholder_id']}"
        mj = store.journal("access.face_mismatch", door_id=ev["door_id"], cardholder_id=ev["cardholder_id"],
                           req_ctr=ev["req_ctr"],
                           detail=f"face at {door} does not match {name}'s enrolled face (similarity {score:.2f}) "
                                  f"for event #{ev['seq']}: PIN may be shared or stolen")
        al = store.raise_alarm(3, "access.face_mismatch", f"{name}'s PIN used by someone else at {door}",
                               door_id=ev["door_id"], event_seq=ev["seq"])
        hub.publish({"type": "event", "event": mj})
        hub.publish({"type": "alarm", "alarm": al})

    @app.post("/api/door/{door_id}/watch", dependencies=[Depends(controller_auth)])
    async def upload_watch(door_id: int, request: Request) -> dict:
        """One frame of the burst a panel records while its door is open after a
        grant, for tailgating detection. Signed like entry photos, with the
        frame's index, the burst length and its capture time inside the
        signature, so a relaying controller cannot add, drop or reorder frames."""
        from .tailgate import MAX_FRAME_MS, MAX_FRAMES
        link = ctl.doors.get(door_id)
        if link is None:
            raise HTTPException(404, "unknown door")
        body = await request.body()
        if not 0 < len(body) <= 2_000_000:
            raise HTTPException(413, "frame too large")
        try:
            req = int(request.headers["x-lintel-req"])
            index, total = (int(v) for v in request.headers["x-lintel-frame"].split("/"))
            ms = int(request.headers["x-lintel-ms"])
            mac = bytes.fromhex(request.headers["x-lintel-mac"])
        except (KeyError, ValueError):
            raise HTTPException(400, "missing signature")
        if not (0 < total <= MAX_FRAMES and 0 <= index < total and 0 <= ms <= MAX_FRAME_MS):
            raise HTTPException(400, "frame index or time out of range")
        want = hmac.new(photo_key(link.key), f"watch:{door_id}:{req}:{index}:{total}:{ms}:".encode()
                        + hashlib.sha256(body).digest(), hashlib.sha256).digest()
        if not hmac.compare_digest(mac, want):
            store.journal("photo.rejected", door_id=door_id, detail="door frame with a bad signature")
            raise HTTPException(403, "bad signature")
        check_image(body)
        ev = store.q1("SELECT * FROM events WHERE door_id=? AND req_ctr=? AND kind='access.granted' "
                      "ORDER BY seq DESC LIMIT 1", (door_id, req))
        if ev is None or time.time() - ev["ts"] > 120:
            raise HTTPException(409, "no grant awaiting door frames")
        if store.setting("tailgate_detection", "1") != "1":
            return {"ok": True, "analysed": False, "why": "tailgating detection is turned off"}
        if watch is None:
            raise HTTPException(503, "tailgating detection unavailable: the person model is not installed")
        if not watch.add_frame(door_id, link.name, dict(ev), req, index, total, ms, body):
            raise HTTPException(409, "frame already received")
        return {"ok": True, "analysed": True}

    @app.post("/api/doors/{door_id}/command")
    def door_command(door_id: int, body: CommandIn, op: dict = Depends(operator)) -> dict:
        if door_id not in ctl.doors:
            raise HTTPException(404, "no such door")
        if body.command == "reboot" and op["role"] != "admin":
            raise HTTPException(403, "admin role required to reboot a panel")
        if body.command == "unlock" and not body.reason.strip():
            raise HTTPException(400, "a reason is required to unlock a door remotely")
        cid = ctl.queue_command(door_id, COMMANDS[body.command])
        if body.command == "unlock":
            ev = store.journal("door.remote_unlock", door_id=door_id, operator=op["username"],
                               detail=f"door released remotely by {op['username']}: {body.reason.strip()}")
            hub.publish({"type": "event", "event": ev})
        else:
            journal(op, "door.command", f"{body.command.replace('_', ' ')} sent to door {door_id}", door_id=door_id)
        return {"ok": True, "command_id": cid}

    @app.post("/api/door/{door_id}/media", dependencies=[Depends(controller_auth)])
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

    # ---- floor plans ------------------------------------------------------------------------------

    def floor_rows() -> list[dict]:
        out = []
        for f in store.q("SELECT * FROM floors ORDER BY level, id"):
            d = dict(f)
            d["has_plan"] = bool(d.pop("plan"))
            d["doors"] = store.q1("SELECT COUNT(*) n FROM doors WHERE floor_id=?", (f["id"],))["n"]
            out.append(d)
        return out

    @app.get("/api/floors")
    def floors(op: dict = Depends(viewer)) -> dict:
        """Every floor, and every door with where it is (or is not yet) placed."""
        return {"floors": floor_rows(), "doors": door_rows()}

    @app.post("/api/floors")
    def add_floor(body: FloorIn, op: dict = Depends(admin)) -> dict:
        fid = store.x("INSERT INTO floors(name, level, created) VALUES(?, ?, ?)", (body.name, body.level, time.time()))
        journal(op, "map.floor_created", f"floor '{body.name}' (level {body.level}) created")
        hub.publish({"type": "maps"})
        return {"id": fid}

    @app.patch("/api/floors/{fid}")
    def patch_floor(fid: int, body: FloorIn, op: dict = Depends(admin)) -> dict:
        if store.x("UPDATE floors SET name=?, level=? WHERE id=?", (body.name, body.level, fid)) == 0:
            raise HTTPException(404, "no such floor")
        journal(op, "map.floor_updated", f"floor {fid} now '{body.name}' (level {body.level})")
        hub.publish({"type": "maps"})
        return {"ok": True}

    @app.delete("/api/floors/{fid}")
    def delete_floor(fid: int, op: dict = Depends(admin)) -> dict:
        f = store.q1("SELECT * FROM floors WHERE id=?", (fid,))
        if f is None:
            raise HTTPException(404, "no such floor")
        store.x("UPDATE doors SET floor_id=NULL, map_x=NULL, map_y=NULL, map_locked=0 WHERE floor_id=?", (fid,))
        store.x("DELETE FROM floors WHERE id=?", (fid,))
        if f["plan"]:
            (store.data_dir / "plans" / f["plan"]).unlink(missing_ok=True)
        journal(op, "map.floor_deleted", f"floor '{f['name']}' deleted; its doors were taken off the map")
        hub.publish({"type": "maps"})
        return {"ok": True}

    @app.put("/api/floors/{fid}/plan")
    async def upload_plan(fid: int, request: Request, op: dict = Depends(admin)) -> dict:
        """A floor plan image. Re-encoded to PNG so only pixels are kept: no
        metadata, scripts or polyglot payloads survive the upload."""
        from PIL import Image
        f = store.q1("SELECT * FROM floors WHERE id=?", (fid,))
        if f is None:
            raise HTTPException(404, "no such floor")
        body = await request.body()
        if not 0 < len(body) <= 20_000_000:
            raise HTTPException(413, "plan too large (20 MB at most)")
        check_image(body)
        with Image.open(io.BytesIO(body)) as im:
            im = im.convert("RGB")
            im.thumbnail((PLAN_MAX_SIDE, PLAN_MAX_SIDE))
            out = store.data_dir / "plans"
            out.mkdir(exist_ok=True)
            name = f"floor{fid}.png"
            im.save(out / name, "PNG", optimize=True)
            w, h = im.size
        store.x("UPDATE floors SET plan=?, width=?, height=? WHERE id=?", (name, w, h, fid))
        journal(op, "map.plan_uploaded", f"plan for '{f['name']}' uploaded ({w}x{h})")
        hub.publish({"type": "maps"})
        return {"ok": True, "width": w, "height": h}

    @app.get("/api/floors/{fid}/plan.png")
    def get_plan(fid: int, op: dict = Depends(viewer)):
        f = store.q1("SELECT plan FROM floors WHERE id=?", (fid,))
        if f is None or not f["plan"]:
            raise HTTPException(404, "no plan uploaded")
        return FileResponse(store.data_dir / "plans" / f["plan"], media_type="image/png",
                            headers={"Cache-Control": "private, no-cache"})

    @app.put("/api/doors/{door_id}/location")
    def place_door(door_id: int, body: LocationIn, op: dict = Depends(admin)) -> dict:
        d = store.q1("SELECT * FROM doors WHERE id=?", (door_id,))
        if d is None:
            raise HTTPException(404, "no such door")
        if d["map_locked"]:
            raise HTTPException(409, "this door is locked in place on the map; unlock it first")
        if body.floor_id is None:
            store.x("UPDATE doors SET floor_id=NULL, map_x=NULL, map_y=NULL WHERE id=?", (door_id,))
            journal(op, "map.door_removed", f"'{d['name']}' taken off the map", door_id=door_id)
        else:
            f = store.q1("SELECT name FROM floors WHERE id=?", (body.floor_id,))
            if f is None:
                raise HTTPException(404, "no such floor")
            store.x("UPDATE doors SET floor_id=?, map_x=?, map_y=? WHERE id=?",
                    (body.floor_id, round(body.x, 5), round(body.y, 5), door_id))
            journal(op, "map.door_placed", f"'{d['name']}' placed on '{f['name']}'", door_id=door_id)
        hub.publish({"type": "maps"})
        return {"ok": True}

    @app.put("/api/doors/{door_id}/location/lock")
    def lock_door_location(door_id: int, body: LockIn, op: dict = Depends(admin)) -> dict:
        d = store.q1("SELECT * FROM doors WHERE id=?", (door_id,))
        if d is None:
            raise HTTPException(404, "no such door")
        if body.locked and d["floor_id"] is None:
            raise HTTPException(409, "place the door on a floor before locking it")
        store.x("UPDATE doors SET map_locked=? WHERE id=?", (int(body.locked), door_id))
        journal(op, "map.door_locked" if body.locked else "map.door_unlocked",
                f"'{d['name']}' {'locked in place' if body.locked else 'unlocked'} on the map", door_id=door_id)
        hub.publish({"type": "maps"})
        return {"ok": True}

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

    @app.post("/api/devices/announce", dependencies=[Depends(controller_auth)])
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
                    (body.door_id, body.name or f"Door {body.door_id}", body.area,
                     store.seal_door_key(body.door_id, key), body.unlock_ms))
        else:
            store.x("UPDATE doors SET key=?, tx_ceiling=0, rx_highest=0 WHERE id=?",
                    (store.seal_door_key(body.door_id, key), body.door_id))
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
        store.x("UPDATE doors SET key=?, tx_ceiling=0, rx_highest=0 WHERE id=?",
                (store.seal_door_key(door_id, secrets.token_bytes(16)), door_id))
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
        origin = sock.headers.get("origin")
        if origin and origin.split("://", 1)[-1] != sock.headers.get("host", ""):
            await sock.close(code=4403)  # cross-site WebSocket hijacking
            return
        token = sock.cookies.get(COOKIE) or sock.cookies.get("lintel_session")
        if operator_from_token(token) is None:
            await sock.close(code=4401)
            return
        await sock.accept()
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        hub.queues.add(q)
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=WS_RECHECK_S)
                except asyncio.TimeoutError:
                    msg = None
                # Signing out, an expired or idle session, or a disabled account
                # ends the live feed too, not just the next page load.
                if operator_from_token(token, touch=False) is None:
                    await sock.close(code=4401)
                    return
                if msg is not None:
                    await sock.send_json(msg)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            hub.queues.discard(q)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return (STATIC / "index.html").read_text(encoding="utf-8")

    return app
