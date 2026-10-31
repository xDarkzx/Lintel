# Building Lintel

Lintel has three parts that build separately: the server (Python, Docker), the
door controller (Python, runs next to the keypad) and the keypad firmware
(ESP-IDF). A shared C++ protocol core is tested on the host.

## Server

Requirements: Docker with Compose.

```sh
cd server
docker compose up -d --build
```

The console is at `https://<host>:8443`. On first start the server writes to
`server/data/`:

| File | What |
|---|---|
| `initial_admin.txt` | First administrator's user name and password. Sign in, enable two-factor, then delete the file. |
| `tls/` | Self-signed P-256 certificate. Replace with your own for production. |
| `controller.env` | Site token and certificate pin for door controllers. |
| `secrets.json` | Credential pepper and audit chain key, wrapped by the master key. |
| `keyring.json` | The data key that encrypts door keys, two-factor secrets, face templates and the webhook URL, wrapped by the master key. |
| `master.key` | Development only: the master key, created when none is supplied. Production keeps it out of this folder (below). |

`server/data/` is never committed.

### Master key

Door keys, operators' two-factor secrets, face templates and the alarm
webhook URL are encrypted in the database with a data key, which is stored
only wrapped by a master key. Anyone who copies the database or a disk
snapshot without the master key gets ciphertext.

In development the server creates `data/master.key` and logs a warning: a key
beside the data protects only against a leaked database file. In production
supply it from outside the data folder, as a Docker secret or a file a KMS or
TPM unlocks at boot:

```sh
openssl rand -base64 32 > lintel_master_key        # keep it off the server's disk if you can
```

```yaml
# compose.yaml
services:
  lintel:
    secrets: [lintel_master_key]
    environment:
      LINTEL_MASTER_KEY_FILE: /run/secrets/lintel_master_key
secrets:
  lintel_master_key:
    file: ./lintel_master_key
```

Rotate it with the server stopped; only `keyring.json` is rewritten:

```sh
python -m lintel_server rotate-master-key --new-key-file new_master_key
```

A wrong master key stops the server; there is no unencrypted fallback.
Backups include the keyring, and include `master.key` only when the key is
kept beside the data, so restoring a production backup needs the same master
key.

Ports: 8443/tcp (HTTPS console and controller uploads) and 47800/udp (sealed keypad
traffic).

To run outside Docker, use a virtual environment:

```sh
cd server
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt     # .venv\Scripts\pip on Windows
.venv/bin/python -m lintel_server                 # --data, --http-port, --udp-port
```

Face matching needs the OpenCV YuNet and SFace models in `server/models/`
(or the directory in `LINTEL_MODELS`); the Dockerfile downloads them and
checks their SHA-256 hashes, so copy the URLs and hashes from there.

Restore an encrypted backup made from the console:

```sh
python -m lintel_server restore backup.lbk [--force]
```

## Door controller

Runs on the machine the keypad's USB cable is plugged into (a Pi Zero class
board in a real install). It holds no door keys.

```sh
cd server
python -m lintel_server.door_controller --server <server-ip> --env data/controller.env
```

`--port` selects the keypad's serial port; by default the TinyUSB CDC device
is detected. Copy `controller.env` from the server to the controller machine.

## Keypad firmware

Hardware: Guition JC4880P443C (ESP32-P4 with ESP32-C6, 480×800 touch,
OV02C10 camera). Requirements: ESP-IDF v5.4.2.

```sh
idf.py -C firmware/panel set-target esp32p4 build
idf.py -C firmware/panel -p <port> flash monitor
```

On Windows, `scripts/idf.ps1` exports ESP-IDF first (it uses `IDF_PATH`, or
`C:\esp\esp-idf`):

```powershell
.\scripts\idf.ps1 panel build
.\scripts\idf.ps1 panel '-p' COM4 flash
```

Flash and read logs through the UART USB socket. The high-speed USB-OTG
socket is the link to the door controller. The lock output pin is set by
`CONFIG_PANEL_LOCK_GPIO` in `idf.py menuconfig`; wiring is in
[docs/hardware.md](docs/hardware.md).

A new keypad shows a pairing code and appears in the console under
Doors & devices as unassigned. Adopt it there with the code shown on its
screen.

## Tests

```sh
scripts/host_test.sh            # C++ core in a Linux container (GoogleTest)
scripts/host_test.sh --asan     # with AddressSanitizer and UBSan
cd server && python -m pytest -q tests
```

CI runs the C++ suite with sanitizers, the server suite, `pip-audit`, a
gitleaks secret scan and a firmware build on every push and pull request.

## Regenerated assets

| Asset | Command |
|---|---|
| Console icon sprite | `python server/tools/build_icons.py <@tabler/icons package>/icons/outline` |
| Keypad fonts | `firmware/panel/tools/build_fonts.sh` (needs Node.js) |
| README screenshots | `python server/tools/capture_console.py <out dir> [--url URL]` |
| README walkthrough GIF | `python server/tools/record_walkthrough.py <out.gif> [--url URL]` |

The capture tools need Playwright with Microsoft Edge, a running server, and
for the walkthrough a keypad attached through the door controller.
Cardholder names are replaced and entry photos blurred in every capture.
