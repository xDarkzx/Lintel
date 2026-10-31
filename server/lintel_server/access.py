"""Access decisions. Pure policy: given a door, the credentials presented and
the time, decide. Every factor must resolve to the same cardholder."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime

from .protocol import CredMode, Decision, Reason, SiteMode
from .store import Store

LOCKOUT_THRESHOLD = 5        # failed attempts in a row at one keypad
LOCKOUT_BASE_S = 30          # first lockout; doubles on each repeat
LOCKOUT_MAX_S = 15 * 60
ENROL_TTL_S = 60

# Which combinations of factors each door mode accepts.
MODE_FACTORS: dict[CredMode, list[frozenset[str]]] = {
    CredMode.PIN: [frozenset({"pin"})],
    CredMode.CARD: [frozenset({"card"})],
    CredMode.CARD_OR_PIN: [frozenset({"card"}), frozenset({"pin"})],
    CredMode.CARD_AND_PIN: [frozenset({"card", "pin"})],
    CredMode.FACE: [frozenset({"face"})],
    CredMode.FACE_AND_PIN: [frozenset({"face", "pin"})],
}


@dataclass
class Verdict:
    decision: Decision
    reason: Reason
    cardholder: dict | None = None
    duress: bool = False
    lockout_s: int = 0
    lockout_started: bool = False
    method: str = ""


@dataclass
class KeypadGuard:
    """Brute-force protection for one door."""
    failures: int = 0
    strikes: int = 0
    locked_until: float = 0.0

    def locked(self, now: float) -> int:
        return max(0, int(self.locked_until - now + 0.999))

    def fail(self, now: float) -> bool:
        self.failures += 1
        if self.failures < LOCKOUT_THRESHOLD:
            return False
        self.failures = 0
        self.locked_until = now + min(LOCKOUT_MAX_S, LOCKOUT_BASE_S * 2 ** self.strikes)
        self.strikes += 1
        return True

    def succeed(self) -> None:
        self.failures = 0
        self.strikes = 0


def window_allows(days: int, start: int, end: int, weekday: int, minute: int) -> bool:
    """Same rule as Schedule::allows in the C++ core."""
    if start == end:
        return False
    if start < end:
        return bool(days & (1 << weekday)) and start <= minute < end
    if minute >= start:
        return bool(days & (1 << weekday))
    if minute < end:
        return bool(days & (1 << ((weekday + 6) % 7)))
    return False


@dataclass
class AccessEngine:
    store: Store
    guards: dict[int, KeypadGuard] = field(default_factory=dict)
    enrol: dict[int, tuple[int, float]] = field(default_factory=dict)  # door -> (cardholder, expires)

    def site_mode(self) -> SiteMode:
        return SiteMode(int(self.store.setting("site_mode", "0")))

    def door_mode(self, door_id: int) -> CredMode:
        r = self.store.q1("SELECT credential_mode FROM doors WHERE id=?", (door_id,))
        return CredMode.from_name(r["credential_mode"]) if r else CredMode.PIN

    def start_card_enrolment(self, door_id: int, cardholder_id: int, now: float | None = None) -> None:
        self.enrol[door_id] = (cardholder_id, (time.time() if now is None else now) + ENROL_TTL_S)

    def _schedule_allows(self, schedule_id: int, when: datetime) -> bool:
        minute = when.hour * 60 + when.minute
        for w in self.store.q("SELECT days, start_min, end_min FROM schedule_windows WHERE schedule_id=?",
                              (schedule_id,)):
            if window_allows(w["days"], w["start_min"], w["end_min"], when.weekday(), minute):
                return True
        return False

    def decide_pin(self, door_id: int, pin: str, now: float | None = None) -> Verdict:
        return self.decide(door_id, pin=pin, now=now)

    def decide(self, door_id: int, *, pin: str | None = None, card: bytes | None = None,
               face: tuple[int | None, float] | None = None, now: float | None = None,
               enforce_mode: bool = False) -> Verdict:
        now = time.time() if now is None else now
        guard = self.guards.setdefault(door_id, KeypadGuard())
        left = guard.locked(now)
        if left:
            return Verdict(Decision.DENY, Reason.LOCKED_OUT, lockout_s=left)

        presented = frozenset(k for k, v in (("pin", pin), ("card", card), ("face", face)) if v is not None)
        method = " + ".join(sorted(presented)).replace("pin", "PIN")

        # Card enrolment: the next card at this door is captured for the waiting cardholder.
        session = self.enrol.get(door_id)
        if card is not None and session and session[1] > now:
            del self.enrol[door_id]
            tag = self.store.card_tag(card)
            clash = self.store.q1("SELECT id FROM cardholders WHERE card_tag=? AND id!=?", (tag, session[0]))
            ch = self.store.q1("SELECT * FROM cardholders WHERE id=?", (session[0],))
            if clash or ch is None:
                return Verdict(Decision.DENY, Reason.MISMATCH, dict(ch) if ch else None, method="card enrolment")
            self.store.x("UPDATE cardholders SET card_tag=? WHERE id=?", (tag, session[0]))
            return Verdict(Decision.DENY, Reason.ENROLLED, dict(ch), method="card enrolment")

        if enforce_mode and presented not in MODE_FACTORS[self.door_mode(door_id)]:
            return Verdict(Decision.DENY, Reason.WRONG_MODE, method=method)

        # Resolve every factor to a cardholder.
        ids: list[int] = []
        duress = False
        failed = None
        if pin is not None:
            tag = self.store.pin_tag(pin)
            r = self.store.q1("SELECT id, duress_tag FROM cardholders WHERE pin_tag=? OR duress_tag=?", (tag, tag))
            if r is None:
                failed = Reason.BAD_PIN
            else:
                ids.append(r["id"])
                duress = r["duress_tag"] == tag
        if card is not None and failed is None:
            r = self.store.q1("SELECT id FROM cardholders WHERE card_tag=?", (self.store.card_tag(card),))
            if r is None:
                failed = Reason.UNKNOWN_CARD
            else:
                ids.append(r["id"])
        if face is not None and failed is None:
            if face[0] is None:
                failed = Reason.NO_MATCH
            else:
                ids.append(face[0])
        if failed is None and len(set(ids)) > 1:
            failed = Reason.MISMATCH
        if failed is not None:
            started = guard.fail(now)
            return Verdict(Decision.DENY, Reason.LOCKED_OUT if started else failed,
                           lockout_s=guard.locked(now), lockout_started=started, method=method)

        ch = dict(self.store.q1("SELECT * FROM cardholders WHERE id=?", (ids[0],)))
        guard.succeed()  # a recognised person is not a guessing attempt, even if refused below

        if not ch["active"] or (ch["valid_from"] and now < ch["valid_from"]) or (
                ch["valid_until"] and now > ch["valid_until"]):
            return Verdict(Decision.DENY, Reason.REVOKED, ch, duress, method=method)

        groups = self.store.q(
            "SELECT g.schedule_id FROM cardholder_groups cg JOIN access_groups g ON g.id = cg.group_id "
            "JOIN access_group_doors gd ON gd.group_id = g.id WHERE cg.cardholder_id=? AND gd.door_id=?",
            (ch["id"], door_id))
        if not groups:
            return Verdict(Decision.DENY, Reason.DOOR_NOT_ALLOWED, ch, duress, method=method)

        mode = self.site_mode()
        if mode == SiteMode.LOCKDOWN and not ch["override"]:
            return Verdict(Decision.DENY, Reason.LOCKDOWN, ch, duress, method=method)

        when = datetime.fromtimestamp(now)
        if mode != SiteMode.FREE_ACCESS and not any(self._schedule_allows(g["schedule_id"], when) for g in groups):
            return Verdict(Decision.DENY, Reason.OUTSIDE_SCHEDULE, ch, duress, method=method)

        # A duress PIN opens the door like normal; the alarm is raised silently by the caller.
        return Verdict(Decision.GRANT, Reason.OK, ch, duress, method=method)
