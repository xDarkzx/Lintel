# Built with AI agents

Lintel was built in one long working session with an AI coding agent (Claude
Code) writing almost all of the code, and me setting direction, testing on the
hardware on my desk, and deciding what "done" meant. This is the honest
account: what the agent was good at, where it was confidently wrong, and the
habits that caught it.

The short version: **the agent is fast and usually right, so the job is
building the checks that catch the times it is wrong.** Most of the defects
below were found by a test, by real hardware, or by the device reporting on
itself. Very few were found by reading the code.

## How the work was set up

- **Tests before trust.** Every security property has a test that fails if the
  property is removed (see [SECURITY.md](SECURITY.md)). The agent writes the
  test alongside the feature; a claim without a test does not go in the README.
- **Golden vectors across languages.** The keypad firmware is C++ and the
  server is Python. Fixed test frames must come out byte-identical from both,
  so a silent wire-format drift fails CI instead of failing at the door.
- **Let the device testify.** I added a remote screenshot command early, so
  UI work was checked against what the panel actually drew, not what the
  layout code implied. Boot logs, `addr2line` and the panel's own diagnostics
  settled arguments that reading code could not.
- **Small commits, real messages.** Each change is one reviewable step, which
  made it easy to back out the two wrong turns below.

## Where the agent was wrong, and what caught it

**Built the wrong thing.** Asked for a door access system, the agent started
with LoRa radios and a relay board, a nice design that this job did not need.
I redirected it to a wired keypad, a door controller and a server. It also
"improved" the keypad by shuffling the digits on every entry; real users
wanted a normal number pad. *Lesson: product judgement stays with the human.
The agent optimises for what it was told, not for who will use it.*

**Trusted the wrong source of truth (three times).** To bring up Wi-Fi on the
keypad's co-processor it first copied the library version from the vendor's
demo (hung), then inferred a version from an old build log (worked, with a
warning). The co-processor's own boot log said a third version entirely. Later
it assumed the panel's stored state matched the server's, so a hand-provisioned
panel never showed its pairing code. *Caught by: the device's own logs, and
me noticing the screen did not match the console. Fix: the server is now the
source of truth for assignment, and the device's self-report beats any file.*

**Reset loop the code review would never find.** The panel rebooted every few
seconds on a cyan screen. The agent decoded the crash dump with `addr2line`:
FreeRTOS's idle task overflowed its 1.5 KB stack while tearing down the
finished `app_main`. A second crash had the Wi-Fi driver exhausting internal
RAM before `app_main` even ran. *Caught by: hardware. Fix: keep the main task
parked, enlarge the idle stack, move driver buffers to PSRAM.*

**"Online" and "offline" at the same time.** After a protocol change, the
dashboard showed the door online while the keypad said the server was offline.
The firmware had been updated but the server container had not, so every reply
was one field short and silently discarded. *Caught by: two screens
disagreeing. Fix: a test that pins the exact reply length to the C++ constant,
alongside the golden vectors.*

**A test caught a real security bug.** Key rotation was marked "delivered" as
soon as the panel reported its door number, which had not changed, so a new
key could be considered installed when the panel was still using the old one.
*Caught by: the adoption test the agent had written itself. Fix: delivery is
confirmed by a monotonic sequence number the panel reports.*

**Knowing when the test is wrong instead.** Several first-run failures were
test mistakes, not code mistakes: a heartbeat assumed in the first three
seconds when the first uplink is a boot event, and a lockout count that forgot
an earlier failed attempt from the same address. The agent had to argue each
one from the system's behaviour rather than make the test pass. *Rule: change
a test only with an explanation of why the system is right.*

**Its own tooling corrupted files.** Shell here-documents mangled escape
sequences, once writing a literal NUL byte into a Python test. *Caught by:
pytest refusing to collect the file. Fix: edits go through small script files,
never inline shell strings.*

**Committed what it should not have.** A 38 MB face model slipped into a
commit. *Caught by: reviewing `git show --stat` before pushing. Fix: removed
before publishing, models are fetched and hash-checked in the Docker build.*
It also installed server dependencies into my global Python, breaking the
image library another tool on my machine pinned. *Fix: restored the version,
per-project virtual environments from then on.*

**Pinned vulnerable versions.** The agent chose dependency versions from its
own memory. `pip-audit` found published vulnerabilities in four of them,
including the web framework. *Fix: upgraded, audit runs in CI.*

**Assumed instead of measured.** The face detector found no face in a real
entry photo; the doorway was backlit. Measuring the detector's confidence at
several scales showed 0.36; contrast equalisation plus a smaller working size
lifted it to 0.90. The keypad grid was laid out on paper to end at y = 804 on an
800-pixel screen, which the on-device screenshot made obvious. A remote unlock
followed by a screenshot silently lost the unlock, because the server held one
pending command per door; found while testing on hardware, fixed with a queue
and a test.

## What it was genuinely good at

- Writing the protocol core, X25519 adoption and TOTP against published test
  vectors (RFC 3610, 4231, 4493, 7748, 4226, NXP AN12196) and getting them
  right first time.
- Security review of its own server when asked to look for it: it found the
  sign-in timing leak, CSV formula injection, decompression bombs and
  last-admin lockout without prompting on each.
- Porting proven code from my earlier projects (camera pipeline, USB link)
  rather than reinventing it.
- Turning vague feedback ("the UI looks generic") into a concrete design system
  quickly, then iterating against screenshots.

## What I would do the same next time

Decide the architecture myself before the first line of code. Give the agent a
way to see the real output (screenshots, logs, the device's own report) as
early as possible. Treat every "fixed" as unproven until a test or the hardware
says so. Keep commits small so wrong turns are cheap to undo.
