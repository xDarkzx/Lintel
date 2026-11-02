# Lintel Vision: walk-through face access with tailgating detection

Date: 2026-11-03
Status: draft for review

## Intent

People should walk up to a door and through it without badging, typing a PIN
or queuing, even in a group. The door recognises each person by face, opens
for them, and logs every one of them by name. Someone who walks through with
the group but is not an enrolled, authorised person is caught: their photo and
a clip go to security as an alarm, and the door tells them, on screen and out
loud, that they are not authorised.

The reference is Alcatraz AI's Rock: one wall unit with a depth camera that
recognises enrolled faces, refuses photos and screens, and detects
tailgating. Lintel Vision aims for the same experience, built on Lintel's
existing security model (the server decides; every door message is sealed).

Why a new device: the current keypads cannot host a depth camera or the
compute that tracks several people at once.

## Goals

- Walk-through entry for one to five people without any of them stopping.
- Every person who goes through is identified and journalled against the door.
- An unrecognised or unauthorised person in the group raises an alarm with an
  evidence photo and clip, and a spoken and on-screen warning at the door.
- Photos, printouts and screens cannot be enrolled or used to open the door
  (depth liveness), so face-only doors become a secure tier, not a convenience.
- A PIN pad on the unit's touchscreen as a fallback, for people whose face is
  not enrolled or not recognised.
- An optional overhead depth camera per door for doors where a person hidden
  directly behind another must not be missed.

## Non-goals

- Physically stopping a tailgater. That needs a turnstile, security revolving
  door or interlocked mantrap; Lintel Vision detects and responds.
- Identifying people who are not enrolled.
- Replacing the existing keypads. They stay; Lintel Vision is a new reader type
  that doors can use instead.
- Counting or watching people leaving. Exit stays free (request-to-exit).

## Anti-goals (a failure even if it technically works)

- Trapping anyone, or locking authorised people out because a stranger was
  near them. Fire egress is never restricted.
- Face templates or images leaving the server, or being kept for people who
  never enrolled.
- The door unit, or anything on the network, being able to decide that a door
  opens. The server decides, as today.
- Making people stop and pose. If the experience needs queuing, it has failed.

## Hardware (prototype)

Prices are rough 2026 US figures from conflicting sources; confirm with NZ
resellers before ordering.

| Part | Choice | Approx. | Notes |
|---|---|---|---|
| Front depth camera | Orbbec Gemini 335 | $330 | Stereo depth + colour, 90° x 65° depth view, USB 3 |
| Door computer | NVIDIA Jetson Orin Nano Super dev kit | $249 | Runs both cameras, tracking and face detection at the door |
| Screen | 7" touchscreen (DSI or HDMI + USB touch) | $60-80 | Messages, pairing code, PIN pad |
| Speaker | Small USB or I2S speaker | $20 | Spoken messages |
| Status light | Addressable LED ring | $10 | Green granted, red denied, amber checking |
| Lock output | Relay module or logic-level MOSFET on a Jetson GPIO | $5 | Fail-secure strike, as the keypad wiring does today |
| Door position | Reed switch on the door | $5 | Knows when the door is open, so crossings are counted against the open window |
| Request to exit | Exit button input | $10 | Free egress, never counted as entry |
| Overhead (high-security doors) | Second Orbbec Gemini 335, ceiling mounted looking down | $330 | 3-5 m active USB 3 cable |
| Enclosure | 3D printed, designed around the parts | — | Can be drawn in FreeCAD once parts are in hand |

About $700 for a standard door, $1,000 with the overhead camera.

Rejected: Intel RealSense D435i (higher price, product line future unclear);
Raspberry Pi 5 + AI HAT+ (cheaper, but tight for two depth streams); Milesight
VS133 overhead counter (closed box; possible later integration for sites that
own one).

## How it works

### Parts and trust

```
 Lintel Vision unit (Jetson)                                   Server
 ┌─────────────────────────────────────┐   UDP sealed frames   ┌────────────────────────────┐
 │ depth camera(s) · tracker            │◄────────────────────►│ face matching · liveness    │
 │ face detect · liveness measurements  │   HTTPS (pinned)      │ group decision · alarms     │
 │ screen · speaker · LEDs · relay      │◄────────────────────►│ journal · console           │
 └─────────────────────────────────────┘                       └────────────────────────────┘
```

- The unit replaces both the keypad and the Pi Zero controller at that door:
  it talks to the server over the network and drives the relay itself.
- The unit is adopted exactly like a keypad today: it shows a pairing code on
  its own screen, has its own X25519 identity, and receives its door key sealed
  to that identity. All door messages use the existing frame format (AES-128-CCM,
  replay window, persisted counters). The Python implementation in
  `server/lintel_server/protocol.py` already speaks this format and can run on
  the Jetson.
- The unit never holds face templates and never learns who someone is beyond
  the first name the server chooses to display.
- Face crops, depth patches and evidence frames go to the server over HTTPS
  with the pinned certificate and a per-door HMAC, as keypad photos do today.

### Door mode

A new credential mode, **walk-through** (`CredMode.FACE_GROUP`), alongside the
existing modes. A door in this mode accepts faces for a group, and a PIN on the
unit's touchscreen as a fallback. The door's other settings (schedules, groups,
lockdown, override) apply to every person in the group exactly as they apply
to one person today.

### Walk-through, step by step

1. **Approach.** The front camera tracks every person in the approach zone (in
   front of the door, within a set distance) in 3D, each with a track id. For
   each track it picks the best face frame and measures liveness from depth
   (the face has real 3D shape and sits at a plausible distance).
2. **Identify.** For each track the unit sends the server a face crop, the
   matching depth patch and the track id. The server runs liveness on the depth
   patch (the server decides, not the unit), then matches the face against
   enrolled templates. A face that matches nobody is discarded at once; only
   "unrecognised" is kept.
3. **Decide.** The server answers per track: authorised (with a first name to
   show), not authorised (recognised but no access here and now), or
   unrecognised. The door opens as soon as one track is authorised, without
   waiting for the rest of the group (as Alcatraz's Rock does: the door is
   never slowed down by the people behind).
4. **Keep identifying.** Tracks that arrive after the door opened are
   identified the same way while the door is open, so everyone who crosses has
   a result by the time it closes.
5. **Cross.** While the door is open (reed switch), the unit counts people
   crossing the threshold inward: from the front camera's tracks, and, when
   fitted, from the overhead camera, which cannot be blocked by a person in
   front. Each crossing is tied to a track where possible.
6. **Reconcile.** When the door closes, the unit reports the crossings. The
   server compares them with the authorised tracks:
   - every crossing matches an authorised person: each is journalled
     (`access.granted`, method "face, walk-through", with their name);
   - more crossings than authorised people, or a crossing by a track that was
     unrecognised or not authorised: a **P1 tailgating alarm, "unauthorised
     person"**, with the best photo of that person outlined and a short clip,
     and the authorised people in the group journalled as normal. The same
     alarm is raised for a stranger and for an enrolled person without access
     here; when the tailgater is enrolled, the alarm names them, otherwise it
     says "unrecognised".
7. **Respond at the door.** On an unauthorised person the unit turns its light
   red, shows "Access denied: unauthorised person", and speaks it. Security gets
   the alarm in the console and through the alarm webhook.
8. **Carry on.** The door keeps working normally for the next people; the
   alarm is handled in the console. (Alcatraz's Rock reports the tailgating
   event and leaves the door in service.)

### Fallback PIN

An unrecognised person can tap the screen and enter a PIN. The PIN is checked
by the server as today (including duress PINs, lockout and the door's
schedule). On a door in walk-through mode, the PIN holder's face, when the
server can see one, is compared with the faces enrolled for that PIN, as PIN
doors do today, and a mismatch raises the existing P3 alarm.

### Enrolment

Faces are enrolled as today: guided enrolment in the console, with the
existing anti-spoofing and head-turn steps. In addition, a person can enrol at
a Lintel Vision unit once, after the server confirms their PIN there: the unit
captures face and depth frames and the server runs the same guided checks.
Enrolment stays opt-in.

### Privacy

- The NZ Biometric Processing Privacy Code applies: recognising people by face
  at a door is biometric processing. Enrolled people get notice and give
  consent at enrolment; doors in walk-through mode carry a sign.
- Unenrolled people: deciding that someone is "unrecognised" requires comparing
  their face with enrolled templates. That comparison happens on the server and
  its result is discarded unless it raised an alarm; no template is kept and no
  identity is sought. Their photo and clip are kept only as alarm evidence, and
  follow the site's photo retention setting.
- `docs/SECURITY.md` currently says tailgating detection does not process
  bystanders' biometrics. That statement changes for walk-through doors and
  must be rewritten with this feature.

### Console

- Door settings: walk-through mode; whether an overhead camera is fitted; the
  approach distance.
- Activity: a walk-through entry shows the group together, each person named,
  with an unauthorised person flagged.
- Alarm: the evidence photo with the person outlined, and the clip.
- Doors and devices: Lintel Vision units adopt and show diagnostics like keypads.

## Constraints

- The server remains the only place access decisions are made; nothing on the
  unit or network can open a door without a server grant.
- Every new message type is sealed with the door key and covered by the replay
  window, and every new decoder is fuzzed, as the existing ones are.
- Free egress: the unit never locks anyone in, and request-to-exit always opens.
- Fail-secure strike by default, as today.
- Evidence frames are signed with index, count and capture time, as tailgating
  frames are today, so a relaying network cannot add, drop or reorder them.
- Works with SQLite and PostgreSQL servers; one server per site.

## Phases

1. **Unit bring-up:** Jetson, Gemini 335, screen, speaker, LEDs, relay, reed
   switch and exit button; adoption; sealed link; one-person face entry with
   depth liveness; PIN fallback.
2. **Walk-through with the front camera:** tracking several people, per-track
   identification while the door is open, crossing count, reconciliation, unauthorised
   person alarm with clip, spoken warning, per-person journal.
3. **Overhead camera:** ceiling mount, crossing count from above, merged with
   front tracks.
4. **Enrolment at the unit, enclosure, console polish.**

Each phase ends in a working door.

## Decided in conversation

- Walk-through with no badges, PINs or queuing for groups (the user).
- As close to Alcatraz AI's Rock as practical (the user).
- A new device; the existing keypads cannot host this (the user).
- Front depth camera on every walk-through door; overhead depth camera as an
  add-on for high-security doors (agreed after discussion).
- A PIN pad on the touchscreen as a fallback (the user said yes).
- Unenrolled people are never identified, only flagged (proposed and accepted).
- Detect and respond; never trap or lock anyone out (agreed).
- Behave as Alcatraz's Rock does (the user): open on the first authorised
  person without holding for the group; one tailgating alarm for strangers and
  for enrolled people without access, naming the enrolled; the door stays in
  service after an alarm. This follows Alcatraz's public material as I
  understand it, not a verified specification.

## My calls (check these)

- Orbbec Gemini 335 and Jetson Orin Nano Super for the prototype.
- The unit replaces the Pi Zero controller at its door and talks to the server
  directly.
- The unit runs Python, reusing `protocol.py`.
- Liveness is judged on the server from a depth patch the unit sends.
- The door opens when at least one person is authorised; an unauthorised person
  who crosses raises a P1 alarm and the door's response, and authorised people
  are not penalised.
- Reed switch and exit button are part of the unit's wiring.

## Left to the builder

- Tracking and face-detection models on the Jetson, and their thresholds.
- How depth liveness is measured, within "the server decides".
- Clip length and encoding.
- Exact message layouts, within the existing frame format.
- Enclosure design.
