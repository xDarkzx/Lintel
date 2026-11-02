# Lintel Vision (server side and simulated unit) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Lintel server support walk-through doors (groups recognised by face, each person journalled, a P1 alarm for an unauthorised person) and prove it end to end with a simulated Lintel Vision unit, before the hardware exists.

**Architecture:** The unit identifies each tracked person with the existing face pattern (signed HTTPS upload of a face crop, then a sealed `CredReq` citing it), extended with a 16-bit depth patch the server judges for liveness. A new walk-through credential mode accepts face or PIN. A new sealed uplink `Crossing` reports who crossed while the door was open; the server reconciles it against the per-track decisions and answers with a sealed `CrossingAck` so the unit can warn. The simulator speaks the real protocol.

**Tech Stack:** Python 3.12, FastAPI, numpy, Pillow, pytest; existing `protocol.py` frame format (AES-128-CCM).

**Spec:** `docs/superpowers/specs/2026-11-03-lintel-vision-design.md`

## Global Constraints

- The server remains the only place access decisions are made; nothing on the unit or network can open a door without a server grant.
- Every new message type is sealed with the door key and covered by the replay window; every new decoder rejects every malformed length, count and padding.
- Free egress: nothing here locks anyone in or out.
- The door opens as soon as one track is authorised, without waiting for the rest of the group.
- One P1 alarm for a stranger and for an enrolled person without access here; the alarm names an enrolled tailgater, otherwise says "unrecognised".
- The door stays in service after an alarm.
- A face that matches nobody is discarded at once; only "unrecognised" is kept.
- The keypad C++ core and firmware are unchanged: the walk-through mode (6) is only ever sent to Vision units (`messages.cpp:118` rejects modes above 5).
- Works on SQLite and PostgreSQL; full test suite runs unfiltered (no skip, deselect or weakened assertion to get a pass).

## Review Focus

1. **A unit that rebooted mid-passage** reports a `Crossing` for a passage the server never saw: people entered with no authorised track, so it must raise the unauthorised-person alarm, not crash or ignore it. Test in Task 5.
2. **A track presented twice** (the unit retries after a dropped reply): a later `NO_FACE` for an already-granted ref must not turn that person into a tailgater, and they must be journalled once. Test in Task 5.
3. **A `Crossing` arriving at a door not in walk-through mode** (mode changed mid-passage): rejected as a malformed frame, with the existing rate-limited rejection alarm. Test in Task 6.
4. **Flooding the server with passages** (many tracks, never crossed): passage memory stays bounded and expires. Test in Task 5.
5. **A printed photo or screen held to the camera** with a plausible face: refused for liveness, journalled, and raised as a P2 alarm, never matched. Test in Task 4.

---

### Task 1: Protocol: walk-through mode, Crossing and CrossingAck

**Files:**
- Modify: `server/lintel_server/protocol.py`
- Modify: `server/lintel_server/web.py:131` (`credential_mode` pattern)
- Test: `server/tests/test_protocol.py`

**Interfaces:**
- Produces: `CredMode.FACE_GROUP = 6` (name `"face_group"` via `CredMode.from_name`); `MsgType.CROSSING = 12` (uplink, door to server); `MsgType.CROSSING_ACK = 13` (downlink); `CROSSING_REFS_MAX = 8`;
  `@dataclass Crossing(passage: int, entered: int, overhead: bool, refs: tuple[int, ...])` with `encode() -> bytes` and `@staticmethod decode(p: bytes) -> Crossing`;
  `@dataclass CrossingAck(passage: int, unauthorised: int)` with `encode()` and `decode()`.
- Wire layouts (little-endian): `Crossing` = `<I passage><B entered><B overhead><B n_refs>` + 8 × `<I ref>` = 39 bytes, unused refs zero; `CrossingAck` = `<I passage><B unauthorised>` = 5 bytes.

- [ ] **Step 1: Write the failing tests**

```python
def test_crossing_round_trips_and_rejects_malformed():
    c = Crossing(passage=0x1200, entered=3, overhead=True, refs=(0x1201, 0x1202))
    assert Crossing.decode(c.encode()) == c and len(c.encode()) == 39
    good = c.encode()
    for bad in (good[:-1], good + b"\0",
                good[:6] + bytes([9]) + good[7:],              # more refs than 8
                good[:4] + bytes([16]) + good[5:],             # entered above 15
                good[:5] + bytes([2]) + good[6:],              # overhead not 0/1
                good[:-4] + b"\1\0\0\0",                       # padding after the listed refs
                good[:7] + b"\0\0\0\0" + good[11:]):           # a listed ref of 0
        with pytest.raises(FrameError):
            Crossing.decode(bad)
    assert dir_for(MsgType.CROSSING) == Dir.DOOR_TO_CTRL and dir_for(MsgType.CROSSING_ACK) == Dir.CTRL_TO_DOOR
    assert CrossingAck.decode(CrossingAck(0x1200, 1).encode()) == CrossingAck(0x1200, 1)
    assert CredMode.from_name("face_group") == CredMode.FACE_GROUP == 6
```

- [ ] **Step 2: Run, expect failure:** `cd server; python -m pytest -q tests/test_protocol.py -k crossing` → FAIL (ImportError on `Crossing`).
- [ ] **Step 3: Implement** the enum values, the two dataclasses and add `MsgType.CROSSING` to `_UPLINK`. `entered` is 0–15; `refs` holds only the first `n_refs` values, each non-zero; every unused ref slot must be zero. Extend the `credential_mode` regex in `DoorPatch` to include `face_group`.
- [ ] **Step 4: Run** `python -m pytest -q tests/test_protocol.py` → all pass.
- [ ] **Step 5: Commit** `feat(protocol): walk-through mode and crossing messages`.

### Task 2: Depth liveness

**Files:**
- Create: `server/lintel_server/depth.py`
- Test: `server/tests/test_depth.py`

**Interfaces:**
- Produces: `read_depth_patch(png: bytes) -> np.ndarray` (uint16 millimetres; raises `ValueError` unless a 16-bit greyscale PNG of at most 128 × 128); `judge_depth(depth: np.ndarray) -> tuple[bool, str]` returning `(True, "")` or `(False, why)`.
- Values (spec leaves them to the builder; fixed here): valid pixels (non-zero) ≥ 60 %; median distance 300–2500 mm; residual RMS from the least-squares plane through the valid pixels ≥ 4 mm (below: "flat, like a photo or screen"); 5th-to-95th percentile depth span ≤ 150 mm (above: "not a single face").

- [ ] **Step 1: Write the failing tests** using synthetic patches built with numpy (64 × 64):

```python
def face(dist=800, bump=40):      # an ellipsoid nose-and-cheek relief
    y, x = np.mgrid[-1:1:64j, -1:1:64j]
    return (dist - bump * np.sqrt(np.clip(1 - x**2 - y**2, 0, 1))).astype(np.uint16)

def test_a_real_face_shape_passes():
    assert judge_depth(face()) == (True, "")

def test_a_flat_tilted_photo_is_refused():
    y, x = np.mgrid[0:64, 0:64]
    ok, why = judge_depth((700 + 2 * x + y).astype(np.uint16))
    assert not ok and "flat" in why

def test_too_far_mostly_empty_or_not_a_face_are_refused():
    assert judge_depth(face(dist=4000))[0] is False
    sparse = face(); sparse[:, :40] = 0
    assert judge_depth(sparse)[0] is False
    deep = face(); deep[:, 32:] += 600
    assert judge_depth(deep)[0] is False

def test_patch_format_is_checked():
    with pytest.raises(ValueError):
        read_depth_patch(png8bit)        # 8-bit greyscale PNG built in the test
    with pytest.raises(ValueError):
        read_depth_patch(png16(np.zeros((200, 200), np.uint16)))
    assert read_depth_patch(png16(face())).dtype == np.uint16
```

- [ ] **Step 2: Run** `python -m pytest -q tests/test_depth.py` → FAIL (module missing).
- [ ] **Step 3: Implement** with Pillow (`mode "I;16"`) and `numpy.linalg.lstsq` for the plane.
- [ ] **Step 4: Run** → pass.
- [ ] **Step 5: Commit** `feat(server): depth liveness for walk-through faces`.

### Task 3: Access engine accepts walk-through doors

**Files:**
- Modify: `server/lintel_server/access.py` (`MODE_FACTORS`, `decide`)
- Test: `server/tests/test_walkthrough.py` (new)

**Interfaces:**
- Consumes: `CredMode.FACE_GROUP` (Task 1).
- Produces: `MODE_FACTORS[CredMode.FACE_GROUP] == [frozenset({"face"}), frozenset({"pin"})]`. On a walk-through door, `Reason.NO_MATCH` from a face does not call `guard.fail`: an unrecognised passer-by is not guessing. Wrong PINs still count.

- [ ] **Step 1: Write the failing tests** (engine driven directly, door set to `face_group` with `store.x`):

```python
def test_walk_through_accepts_face_or_pin_and_strangers_do_not_lock_the_door(engine_door):
    engine, door = engine_door
    for _ in range(LOCKOUT_THRESHOLD + 2):
        v = engine.decide(door, face=(None, 0.1, None), enforce_mode=True)
        assert v.reason == Reason.NO_MATCH
    assert engine.decide(door, face=(ana_id, 0.9, None), enforce_mode=True).decision == Decision.GRANT
    assert engine.decide(door, pin="2468", enforce_mode=True).decision == Decision.GRANT
    assert engine.decide(door, card=b"\1\2\3\4", enforce_mode=True).reason == Reason.WRONG_MODE
```

- [ ] **Step 2: Run** `python -m pytest -q tests/test_walkthrough.py` → FAIL (`KeyError: FACE_GROUP`).
- [ ] **Step 3: Implement** the factor entry and the no-lockout rule.
- [ ] **Step 4: Run** → pass; also `python -m pytest -q tests/test_server.py` → pass.
- [ ] **Step 5: Commit** `feat(server): walk-through credential mode`.

### Task 4: Walk-through face endpoint with depth liveness

**Files:**
- Modify: `server/lintel_server/web.py` (new route beside `door_face`)
- Test: `server/tests/test_walkthrough.py`

**Interfaces:**
- Consumes: `read_depth_patch`, `judge_depth` (Task 2); `ctl.hold_face(door_id, ref, (cid, score, time, jpeg, error))` (existing).
- Produces: `POST /api/door/{door_id}/walk/face`, controller token required. Headers `x-lintel-req` (the face ref, non-zero), `x-lintel-mac` = hex HMAC-SHA256 with `photo_key(door_key)` over `f"walkface:{door_id}:{ref}:".encode() + sha256(jpeg) + sha256(depth_png)`. Body = `struct.pack("<I", len(jpeg)) + jpeg + depth_png`. Responses: 200 `{"ok": true, "face": bool}`; 400 missing or malformed signature or body; 403 bad signature; 404 unknown door; 409 door not in walk-through mode; 413 body over 2 MB.
- On a liveness refusal: `hold_face(..., (None, 0.0, now, jpeg, "not a live face"))`, journal `face.spoof` (detail includes the `why`), raise a P2 alarm kind `face.spoof` titled `Possible face spoof at {door name}`, publish both, and do not run matching.

- [ ] **Step 1: Write the failing tests** (FakeFaces from `test_enrolment`, template inserted with `store.seal_template`):

```python
def test_walk_face_matches_a_live_face_and_refuses_a_flat_one(walk_env):
    ...  # post with face() depth: 200, face True; then CredReq citing the ref grants Ana
    ...  # post with the flat plane: 200, face False; CredReq citing it → Reason.NO_FACE
    assert any(a["kind"] == "face.spoof" and a["priority"] == 2 for a in client.get("/api/alarms").json())

def test_walk_face_checks_signature_mode_and_size(walk_env):
    ...  # wrong mac → 403; ref 0 → 403; door switched to "pin" → 409; truncated container → 400
```

- [ ] **Step 2: Run** → FAIL (404 route missing).
- [ ] **Step 3: Implement**: parse and authenticate before any decoding; `check_image(jpeg)`; liveness first; inference via `run_in_threadpool` as `door_face` does.
- [ ] **Step 4: Run** → pass.
- [ ] **Step 5: Commit** `feat(server): walk-through face upload with depth liveness`.

### Task 5: Passages and reconciliation

**Files:**
- Create: `server/lintel_server/walkthrough.py`
- Test: `server/tests/test_walkthrough.py`

**Interfaces:**
- Produces:
  - A face ref encodes its passage: `passage_of(ref: int) -> int` returns `ref & ~0xFF`; track number is `ref & 0xFF` (1–255).
  - `@dataclass TrackResult(ref: int, granted: bool, cardholder: dict | None, jpeg: bytes | None)`.
  - `class PassageBook` with `record(door_id: int, ref: int, granted: bool, cardholder: dict | None, jpeg: bytes | None, now: float) -> None` (a grant is never overwritten by a later denial for the same ref; the first cardholder and jpeg seen are kept) and `reconcile(door_id: int, c: Crossing, now: float) -> Reconciliation` (removes the passage).
  - `@dataclass Reconciliation(authorised: list[TrackResult], tailgaters: list[TrackResult], anonymous: int)` with property `unauthorised -> int` = `len(tailgaters) + anonymous`. Rules: a listed ref with a grant is authorised; a listed ref without one (denied, unrecognised or never seen) is a tailgater; `anonymous = max(0, c.entered - len(c.refs))`.
  - Limits: `PASSAGE_TTL_S = 120`, `PASSAGES_MAX = 1024` across all doors, oldest dropped first.

- [ ] **Step 1: Write the failing tests** for the book alone:

```python
def test_reconcile_names_authorised_and_tailgaters():
    b = PassageBook()
    b.record(1, 0x1201, True, ana, None, 0); b.record(1, 0x1202, False, None, jpg, 0)
    r = b.reconcile(1, Crossing(0x1200, 3, False, (0x1201, 0x1202)), 1)
    assert [t.cardholder["id"] for t in r.authorised] == [ana["id"]]
    assert [t.ref for t in r.tailgaters] == [0x1202] and r.anonymous == 1 and r.unauthorised == 2

def test_a_retry_never_turns_a_granted_person_into_a_tailgater():
    b = PassageBook(); b.record(1, 0x1201, True, ana, None, 0); b.record(1, 0x1201, False, None, None, 1)
    assert b.reconcile(1, Crossing(0x1200, 1, False, (0x1201,)), 2).unauthorised == 0

def test_an_unknown_passage_with_entries_is_all_unauthorised():
    r = PassageBook().reconcile(1, Crossing(0x9900, 2, True, ()), 0)
    assert r.authorised == [] and r.anonymous == 2

def test_passages_are_bounded_and_expire():
    b = PassageBook()
    for i in range(PASSAGES_MAX + 50):
        b.record(1, ((i + 1) << 8) | 1, True, ana, None, 0)
    assert b.size() <= PASSAGES_MAX
    b.record(2, 0x0101, True, ana, None, PASSAGE_TTL_S + 1)
    assert b.size() == 1
```

- [ ] **Step 2: Run** → FAIL (module missing).
- [ ] **Step 3: Implement** with an `OrderedDict` keyed `(door_id, passage)`, pruned on every `record`, as `LoginThrottle` does.
- [ ] **Step 4: Run** → pass.
- [ ] **Step 5: Commit** `feat(server): walk-through passages and reconciliation`.

### Task 6: Controller wiring

**Files:**
- Modify: `server/lintel_server/controller.py` (`Controller` fields, `_datagram`, `_on_cred`, new `_on_crossing`)
- Test: `server/tests/test_walkthrough.py`

**Interfaces:**
- Consumes: `PassageBook`, `Reconciliation` (Task 5); `Crossing`, `CrossingAck` (Task 1).
- Produces:
  - `Controller.passages: PassageBook` field.
  - In `_on_cred`, on a walk-through door with a face ref: `passages.record(door, ref, granted, verdict.cardholder, face_jpeg, now)` after the decision (the existing per-request journal entry stays the per-person log).
  - `MsgType.CROSSING` handled by `_on_crossing`: on a door not in walk-through mode, `_reject(d, now, "crossing report at a door not in walk-through mode")`. Otherwise reconcile. When `unauthorised > 0`: journal kind `door.unauthorised_person` (detail lists authorised names, tailgater names or "unrecognised", the anonymous count, and whether the overhead camera counted); raise a P1 alarm, kind `door.unauthorised_person`, title `Unauthorised person at {door}: {names or "unrecognised"}`; call `on_face_evidence(event, jpeg, door_name, "UNAUTHORISED PERSON")` with the first tailgater's jpeg when there is one; publish event and alarm. Always answer with a sealed `CrossingAck(passage, unauthorised)`.

- [ ] **Step 1: Write the failing tests** by driving `ctl.datagram` with frames sealed in the test (as `test_server.Panel` does):
  - two granted refs cross, `entered=2` → no alarm, `CrossingAck(p, 0)`;
  - a granted ref and a denied one cross → one P1 `door.unauthorised_person` alarm, `CrossingAck(p, 1)`;
  - the same `Crossing` frame sent twice → the second is dropped by the replay window (one alarm only);
  - `Crossing` on a `pin`-mode door → no ack, a `link.rejected` event.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `python -m pytest -q tests/test_walkthrough.py tests/test_server.py tests/test_resilience.py` → pass.
- [ ] **Step 5: Commit** `feat(server): crossing reports raise the unauthorised-person alarm`.

### Task 7: Simulated Lintel Vision unit and end-to-end scenarios

**Files:**
- Create: `server/lintel_server/vision_sim.py`
- Test: `server/tests/test_vision_sim.py`

**Interfaces:**
- Consumes: the routes and messages of Tasks 1–6.
- Produces: `class VisionUnit(door_id: int, key: bytes, net_id: int, deliver: Callable[[bytes], bytes | None], post: Callable[[str, bytes, dict[str, str]], tuple[int, dict]])` speaking the real protocol, with:
  - `start_passage() -> int` (new passage id, a multiple of 256, never reused in this unit's life);
  - `present(track: int, jpeg: bytes, depth_png: bytes) -> PinResult` (uploads the face, then sends the `CredReq`; `PinResult(decision, reason, name, unlock_ms)`);
  - `pin(pin: str) -> PinResult`;
  - `crossed(entered: int, tracks: list[int], overhead: bool = False) -> CrossingAck`;
  - module helpers `depth_face_png(dist_mm: int = 800) -> bytes` and `depth_flat_png() -> bytes`.
  - The in-process wiring for tests: `deliver` calls `ctl.datagram` on a `FakeTransport` and returns the reply; `post` calls the `TestClient` with the controller token.

- [ ] **Step 1: Write the failing scenario tests** (FakeFaces; Ana, Ben enrolled with access; Cat enrolled without access to this door):

```python
def test_three_staff_walk_through_and_each_is_logged(sim):          # Ana, Ben, Cat-with-access
    ...  # door opens on the first present(); crossed(3, [1, 2, 3]) → CrossingAck unauthorised 0
    ...  # three access.granted events, each naming its person; no alarm

def test_a_stranger_behind_two_staff_raises_the_alarm(sim):
    ...  # stranger's present() → DENY NO_MATCH; crossed(3, [1, 2, 3]) → unauthorised 1
    ...  # one P1 door.unauthorised_person alarm titled "... unrecognised", with a photo

def test_staff_without_access_following_is_named(sim):
    ...  # Cat (no access here) follows Ana: alarm title names "Cat"

def test_overhead_counts_a_person_hidden_from_the_front_camera(sim):
    ...  # present Ana only; crossed(2, [1], overhead=True) → unauthorised 1, "unrecognised"

def test_a_photo_held_up_opens_nothing(sim):
    ...  # present(…, depth_flat_png()) → DENY NO_FACE; a face.spoof P2 alarm

def test_pin_fallback_opens_for_someone_not_recognised(sim):
    ...  # pin("2468") → GRANT for its holder
```

- [ ] **Step 2: Run** → FAIL (module missing).
- [ ] **Step 3: Implement** `VisionUnit`, reusing `seal`, `open_frame`, `photo_key`.
- [ ] **Step 4: Run** the full suite: `python -m pytest -q tests -p no:cacheprovider` → every test passes; report any failure as it is.
- [ ] **Step 5: Commit** `feat: simulated Lintel Vision unit and walk-through scenarios`.

### Task 8: Console and documentation

**Files:**
- Modify: `server/lintel_server/static/app.js` (door credential mode select: add `face_group` labelled "Walk-through: faces, groups, PIN fallback")
- Modify: `docs/SECURITY.md` (threat rows for walk-through tailgating and depth liveness with their tests; rewrite the bystander statement: walk-through doors compare every face with enrolled templates, keep no result unless it raised an alarm, and need notice and consent under the NZ Biometric Processing Privacy Code)
- Modify: `docs/hardware.md` (a "Lintel Vision prototype" section with the parts table from the spec)

- [ ] **Step 1:** Make the edits; `node --check server/lintel_server/static/app.js` → no output.
- [ ] **Step 2:** Every test name cited in `docs/SECURITY.md` exists: `for t in $(grep -oE '\`test_[a-z0-9_]+\`' docs/SECURITY.md | tr -d '\`' | sort -u); do grep -rqE "def $t\b" server/tests || echo MISSING $t; done` → only the pre-existing file names `test_frame` and `test_protocol`.
- [ ] **Step 3:** Full suite unfiltered → pass.
- [ ] **Step 4: Commit** `docs: walk-through doors in the console, threat model and hardware notes`.

## Not in this plan (needs the hardware)

Jetson service, Gemini 335 capture, people tracking, crossing detection from depth, screen, speaker, LED ring, relay, reed switch, exit button, adoption of a Vision unit over the network, clip recording, enrolment at the unit, enclosure. A follow-on plan covers these once the parts arrive; the simulator in Task 7 defines the behaviour that service must reproduce.
