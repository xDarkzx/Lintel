"""Walk-through passages at Lintel Vision doors.

A passage is one opening of the door: a group walks up, each tracked person's
face is checked (one CredReq per person, citing a face ref), the door opens on
the first authorised person, and when it closes the unit reports who crossed.
The face ref carries the passage in its upper bits and the track in its low
byte, so every decision can be tied back to the passage it belongs to.

Reconciling the crossing report against the decisions finds the people who
went through without being authorised: tracks that were refused or never
recognised, and crossings the unit could not tie to any tracked face (for
example a person the overhead camera counted but the front camera never saw).
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from .protocol import Crossing

PASSAGE_TTL_S = 120    # a passage nobody reports a crossing for is forgotten after this
PASSAGES_MAX = 1024    # across every door: tracks that never cross cannot grow memory


def passage_of(ref: int) -> int:
    return ref & ~0xFF


@dataclass
class TrackResult:
    ref: int
    granted: bool
    cardholder: dict | None
    jpeg: bytes | None


@dataclass
class Reconciliation:
    authorised: list[TrackResult]
    tailgaters: list[TrackResult]
    anonymous: int  # crossings not tied to any tracked face

    @property
    def unauthorised(self) -> int:
        return len(self.tailgaters) + self.anonymous


@dataclass
class _Passage:
    seen: float
    tracks: dict[int, TrackResult] = field(default_factory=dict)


class PassageBook:
    """Not thread-safe on its own: the controller calls it under its lock."""

    def __init__(self) -> None:
        self._passages: OrderedDict[tuple[int, int], _Passage] = OrderedDict()  # oldest activity first

    def record(self, door_id: int, ref: int, granted: bool, cardholder: dict | None, jpeg: bytes | None,
               now: float) -> None:
        self._prune(now)
        key = (door_id, passage_of(ref))
        p = self._passages.get(key)
        if p is None:
            p = self._passages[key] = _Passage(now)
        p.seen = now
        self._passages.move_to_end(key)
        old = p.tracks.get(ref)
        if old is None or (granted and not old.granted):
            p.tracks[ref] = TrackResult(ref, granted, cardholder, jpeg if jpeg is not None or old is None
                                        else old.jpeg)
        elif not old.granted and old.jpeg is None and jpeg is not None:
            old.jpeg = jpeg  # a retry may bring the photo the first attempt lacked
        # A grant is never undone by a later denial: a retry after a lost reply
        # finds its face already used and is refused, but the person was let in.
        while len(self._passages) > PASSAGES_MAX:
            self._passages.popitem(last=False)

    def reconcile(self, door_id: int, c: Crossing, now: float) -> Reconciliation:
        self._prune(now)
        p = self._passages.pop((door_id, c.passage), None)
        tracks = p.tracks if p else {}
        authorised, tailgaters = [], []
        listed = list(dict.fromkeys(c.refs))  # each listed person once
        for ref in listed:
            t = tracks.get(ref)
            if t is not None and t.granted:
                authorised.append(t)
            else:
                tailgaters.append(t or TrackResult(ref, False, None, None))
        return Reconciliation(authorised, tailgaters, max(0, c.entered - len(listed)))

    def size(self) -> int:
        return len(self._passages)

    def _prune(self, now: float) -> None:
        while self._passages:
            key, p = next(iter(self._passages.items()))
            if now - p.seen < PASSAGE_TTL_S:
                break
            del self._passages[key]
