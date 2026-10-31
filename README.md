# Lintel

An access control system built end to end: a touchscreen door keypad on an
ESP32-P4, a door controller that wires it to the network, and an operator
server with a web console. Designed the way commercial systems are, with the
security decisions written down and tested.

```
 Keypad (ESP32-P4, 4.3" touch, camera)          Door controller (Pi Zero class)            Server (Docker)
 ┌───────────────────────────────┐   USB    ┌──────────────────────────────┐  UDP + HTTPS  ┌────────────────────────────┐
 │ PIN pad · lockout · photos     │◄────────►│ keyless relay                │◄─────────────►│ decisions · cardholders     │
 │ X25519 identity · AES-CCM      │  CDC-ACM │ pinned TLS · controller token│               │ alarms · audit chain        │
 │ fail-secure lock output        │          │ photo / screenshot uplink    │               │ web console · face matching │
 └───────────────────────────────┘          └──────────────────────────────┘               └────────────────────────────┘
```

The keypad has no network of its own and holds no PINs. Every message between
keypad and server is sealed with that door's AES-128 key, so the controller in
the middle, or anyone who takes it over, can relay traffic but cannot read it
or forge a grant.

## What it does

**At the door**
- PIN entry on a standard keypad; the server decides, the panel never stores PINs
- Three wrong PINs lock the keypad (30 s, doubling to 15 min), raise a critical
  alarm and photograph the person; every attempt is photographed
- Duress PIN: opens normally, silently raises a critical alarm
- Screen follows the door's mode (PIN, card, card + PIN, face, face + PIN),
  name and site lockdown, all delivered from the server
- Fail-secure lock relay output; remote unlock from the console with a reason

**Commissioning**
- New keypads announce themselves and appear in the console as unassigned,
  with serial and MAC address
- Adoption needs the 6-digit pairing code shown on the keypad's screen; the
  door key is then sealed to the keypad's own X25519 key, so it never crosses
  the network in the clear and never has to be typed
- Key rotation and unassignment are delivered the same way

**Operations console**
- Live monitor, alarm queue with acknowledgement notes, searchable activity
  with CSV export, cardholders, access groups, schedules with holidays,
  doors and devices, operators, settings, audit trail
- Diagnostics per keypad: uptime, last reset reason, memory, chip
  temperature, camera, link errors, rejected frames, decision latency,
  remote screenshot, test photo, identify, reboot
- Face enrolment from entry photos; card enrolment by tapping at a door
- Encrypted backup; alarm webhook to Teams, Slack or a pager

## Security model

The full threat model is in [docs/SECURITY.md](docs/SECURITY.md). In short:

| Layer | Mechanism |
|---|---|
| Keypad ↔ server | AES-128-CCM per door, 64-frame replay window, reboot-safe counters, every reply bound to the request it answers |
| Commissioning | X25519 + HMAC-derived key, pairing code checked by a person, monotonic sequence against rollback |
| Credentials | PINs and card UIDs stored only as keyed HMACs; the key lives outside the database |
| Audit | HMAC-SHA256 hash chain over every decision, alarm, operator action and photo hash |
| Console | HTTPS only, TOTP two-factor, sign-in throttling with alarm, `__Host-` cookies, CSP, Origin checks, roles |
| Controller | Pins the server certificate, presents a site token, holds no door keys |
| Deployment | Read-only container, all capabilities dropped, non-root, dependencies audited with pip-audit |

## Repository

| Path | What |
|---|---|
| `components/lintel_core` | Portable C++ protocol core: frames, counters, adoption, messages, policy, audit chain |
| `firmware/panel` | ESP32-P4 keypad firmware (ESP-IDF 5.4, LVGL 8) |
| `server/lintel_server` | FastAPI server, door controller relay, web console |
| `test/host` | GoogleTest suite for the core, run in Docker |
| `server/tests` | pytest suite for the server and controller |
| `firmware/door` | Earlier LoRa door node (Heltec ESP32-S3), kept for reference |

Shared golden vectors make the C++ firmware and the Python server prove they
produce byte-identical frames and adoption messages.

## Running it

```sh
# Server (generates admin credentials, TLS certificate and controller.env in server/data)
cd server && docker compose up -d --build        # https://localhost:8443

# Door controller, on the machine the keypad is plugged into
python -m lintel_server.door_controller --server <server-ip> --env server/data/controller.env

# Tests
scripts/host_test.sh                              # C++ core, also --asan
cd server && python -m pytest -q tests            # server

# Keypad firmware
.\scripts\idf.ps1 panel build
.\scripts\idf.ps1 panel '-p' COM4 flash
```

Hardware: Guition JC4880P443C (ESP32-P4 + ESP32-C6, 480×800 touch, OV02C10
camera). The keypad's high-speed USB socket is the controller link; the other
socket is for flashing and logs.

## Status

Verified on hardware: keypad UI and PIN decisions end to end through the
controller, entry and lockout photos, adoption with pairing codes, remote
diagnostics and screenshots, server-side face detection and matching on real
entry photos.

Next: RC522 card reader driver (wiring on JP1 is documented in
[docs/hardware.md](docs/hardware.md)), the keypad's face-scan flow, and
production firmware protection ([docs/production-hardening.md](docs/production-hardening.md)).
