# Security model

This document states what Lintel defends against, how, and where the limits
are. Each defence listed here has a test that fails if it is removed.

## Assets

- **Door keys** (AES-128, one per door): whoever holds one can speak for that door.
- **The PIN pepper** (HMAC key in `secrets.json`): turns PINs and card UIDs into tags.
- **The audit key**: makes the journal tamper-evident.
- **Cardholder data and entry photos**: personal information.
- **Operator accounts**: control over who gets in.

## Trust boundaries

```
keypad ──USB── door controller ──LAN── server ──HTTPS── operator browser
  (secure side of the door)      (untrusted)   (trusted)   (authenticated)
```

The network and the door controller are treated as hostile. The keypad is
trusted only for its own door. The server is the only place decisions are made.

## Threats and defences

| Threat | Defence | Test |
|---|---|---|
| Sniffing PINs on the wire | AES-128-CCM per door; the controller relays sealed frames only | `test_frame`, `test_protocol` |
| Replaying a recorded grant or request | 64-frame replay window; replies carry the counter of the request they answer; late replies are dropped | `ReplayedGrantDoesNotOpenDoor`, `test_replayed_and_forged_frames_get_no_reply` |
| Replay across reboots | Counters persisted in blocks (reserve-ahead) on both ends | `TxCounter.NeverReusesAcrossReboots`, `test_controller_counters_survive_restart` |
| Reflecting a frame back at its sender | Direction is part of the nonce | `Frame.DirectionIsBoundIntoNonce` |
| Rogue or cloned keypad adopted | Pairing code read from the physical screen; identity key mismatch on an adopted serial raises a P1 alarm | `test_identity_change_on_adopted_device_raises_alarm` |
| Door key exposed during setup | Key sealed to the keypad's X25519 public key; never typed, logged or shown | `Adopt.GoldenBlobMatchesServer`, `test_discover_adopt_deliver_and_use` |
| Rolling a keypad back to an old key | Monotonic adoption sequence | `SealOpenRoundTripAndTamper`, firmware `on_provision` |
| PIN guessing at the door | 3 failures lock the keypad, doubling to 15 min; P1 alarm with photo | `test_bad_pin_then_lockout_and_alarm` |
| Tailgating on someone else's entry | After a grant the keypad records the open door; more people than credentials, near the door, in two or more frames raises a P2 alarm with an outlined evidence photo | `test_tailgate.py` |
| Faking or hiding door frames | Each frame is signed by the keypad with its index, burst length and capture time; a relaying controller cannot add, drop or reorder frames, and missing frames are reported | `test_frames_are_signed_ordered_and_bound_to_a_grant`, `test_missing_frames_are_analysed_after_the_timeout` |
| Enrolling a photo, screen or video as someone's face | Guided enrolment judged on the server: anti-spoofing models on every frame, head-turn steps in a random order, the same face throughout; templates only when every step passes | `test_enrolment.py` |
| A shared or stolen PIN | On PIN doors, a clear face unlike every face enrolled for that PIN raises a P3 alarm; face + PIN doors refuse it outright | `test_someone_else_using_a_pin_raises_an_alarm`, `test_face_and_pin_door_needs_the_pin_owners_face` |
| Bypassing a door's credential mode | Every request, including a bare PIN, is checked against what the door accepts | `test_a_bare_pin_respects_the_doors_mode` |
| Coercion | Duress PIN grants normally and raises a silent P1 alarm | `test_duress_grants_silently_but_raises_critical_alarm` |
| Stolen database | PINs and card UIDs stored as HMAC tags keyed outside the database | `test_backup_restores_a_working_site` |
| Editing history | HMAC-SHA256 hash chain; photo hashes are chained too | `test_journal_detects_tampering`, `Audit.*` |
| Operator password guessing | 5 failures lock name and address for 15 min with an alarm; constant-time for unknown users | `test_operator_two_factor_and_login_lockout` |
| Stolen operator password | TOTP second factor, single-use codes, optional admin enforcement | `test_operator_two_factor_and_login_lockout` |
| Session theft, CSRF, clickjacking | `__Host-` HttpOnly SameSite=Strict cookie, Origin checks, 30 min idle timeout, CSP `frame-ancestors 'none'` | `test_cross_origin_writes_are_refused`, `test_security_headers_present` |
| Server impersonation to controllers | Controllers pin the server certificate's SHA-256 | door controller `post()` |
| Fake controller on the LAN | Controller endpoints require the site token; door photos also carry a per-door HMAC | `test_controller_endpoints_need_the_token` |
| Malicious uploads | Image dimension limit before decode; 2–8 MB caps; JPEG/PNG only | `test_image_bomb_rejected_before_decoding` |
| CSV formula injection | Exported cells starting with `= + - @` are neutralised | `test_csv_export_neutralises_formulas` |
| Locking everyone out | The last admin cannot be deleted, demoted or disabled | `test_last_admin_cannot_be_removed_or_demoted` |
| Losing the server | Encrypted backup (scrypt + AES-256-GCM); restore verifies the chain and refuses path escapes | `test_backup.py` |
| Vulnerable dependencies | Pinned versions audited with `pip-audit` | CI |

## Known limits

- **Single-camera face recognition can be fooled by a good photo.** Face-only
  doors are labelled a convenience tier; face + PIN is the secure tier.
- **Enrolment liveness is not certified.** The anti-spoofing models
  (Minivision Silent-Face) and random head-turn steps stop printed photos,
  screens and most replayed videos; they have not been tested by an
  ISO/IEC 30107-3 lab, and a good 3D mask could pass.
- **A keypad camera can miss a tailgater hidden directly behind the first
  person**, as can any reader-mounted camera. An overhead camera covers that
  case. Tailgating detection counts people with a general person detector
  (YOLOX-S); it does not identify them, so it is not biometric processing of
  bystanders under the NZ Biometric Processing Privacy Code.
- **RC522 cards are read by UID**, which inexpensive cards let an attacker
  clone. Use card + PIN, or NTAG 424 DNA cards with a PN532 reader (supported
  in `lintel_core/sdm`), where each tap is cryptographically fresh.
- **A stolen keypad's flash holds its door key** until production protection
  is enabled; see [production-hardening.md](production-hardening.md). Rotating
  or unassigning the door in the console voids the stolen key immediately.
- **Truncating the newest journal records** is not detectable from the chain
  alone; the console shows the head hash so it can be recorded elsewhere.
