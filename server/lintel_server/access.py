"""Access decisions. Pure policy: given a door, a PIN and the time, decide."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime

from .protocol import Decision, Reason, SiteMode
from .store import Store

LOCKOUT_THRESHOLD = 5        # wrong PINs in a row at one keypad
LOCKOUT_BASE_S = 30          # first lockout; doubles on each repeat
LOCKOUT_MAX_S = 15 * 60


@dataclass
class Verdict:
    decision: Decision
    reason: Reason
    cardholder: dict | None = None
    duress: bool = False
    lockout_s: int = 0
    lockout_started: bool = False


@dataclass
class KeypadGuard:
    """Brute-force protection for one keypad."""
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

    def site_mode(self) -> SiteMode:
        return SiteMode(int(self.store.setting("site_mode", "0")))

    def _schedule_allows(self, schedule_id: int, when: datetime) -> bool:
        minute = when.hour * 60 + when.minute
        for w in self.store.q("SELECT days, start_min, end_min FROM schedule_windows WHERE schedule_id=?",
                              (schedule_id,)):
            if window_allows(w["days"], w["start_min"], w["end_min"], when.weekday(), minute):
                return True
        return False

    def decide_pin(self, door_id: int, pin: str, now: float | None = None) -> Verdict:
        now = time.time() if now is None else now
        guard = self.guards.setdefault(door_id, KeypadGuard())
        left = guard.locked(now)
        if left:
            return Verdict(Decision.DENY, Reason.LOCKED_OUT, lockout_s=left)

        tag = self.store.pin_tag(pin)
        row = self.store.q1("SELECT * FROM cardholders WHERE pin_tag=? OR duress_tag=?", (tag, tag))
        if row is None:
            started = guard.fail(now)
            return Verdict(Decision.DENY, Reason.LOCKED_OUT if started else Reason.BAD_PIN,
                           lockout_s=guard.locked(now), lockout_started=started)

        ch = dict(row)
        duress = ch["duress_tag"] == tag
        guard.succeed()  # a known PIN is not a guessing attempt, even if refused below

        if not ch["active"] or (ch["valid_from"] and now < ch["valid_from"]) or (
                ch["valid_until"] and now > ch["valid_until"]):
            return Verdict(Decision.DENY, Reason.REVOKED, ch, duress)

        groups = self.store.q(
            "SELECT g.schedule_id FROM cardholder_groups cg JOIN access_groups g ON g.id = cg.group_id "
            "JOIN access_group_doors gd ON gd.group_id = g.id WHERE cg.cardholder_id=? AND gd.door_id=?",
            (ch["id"], door_id))
        if not groups:
            return Verdict(Decision.DENY, Reason.DOOR_NOT_ALLOWED, ch, duress)

        mode = self.site_mode()
        if mode == SiteMode.LOCKDOWN and not ch["override"]:
            return Verdict(Decision.DENY, Reason.LOCKDOWN, ch, duress)

        when = datetime.fromtimestamp(now)
        if mode != SiteMode.FREE_ACCESS and not any(self._schedule_allows(g["schedule_id"], when) for g in groups):
            return Verdict(Decision.DENY, Reason.OUTSIDE_SCHEDULE, ch, duress)

        # A duress PIN opens the door like normal; the alarm is raised silently by the caller.
        return Verdict(Decision.GRANT, Reason.OK, ch, duress)
