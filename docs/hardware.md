# Keypad hardware

Guition JC4880P443C: ESP32-P4 with an ESP32-C6 co-processor, 480×800 IPS touch
panel (ST7701, GT911), OV02C10 MIPI camera, two USB-C sockets.

## USB sockets

| Socket | Shows up as | Use |
|---|---|---|
| USB-Serial-JTAG | `303A:1001` | Flashing, logs, provisioning console |
| High-speed USB-OTG | `303A:4001` (TinyUSB CDC) | Link to the door controller |

## JP1 expansion header

| JP1 pin | Signal | Lintel use |
|---|---|---|
| 13 | GPIO49 | Lock relay output (fail-secure, active high) |
| 8 | GPIO33 | RC522 SDA / SS |
| 14 | GPIO29 | RC522 SCK |
| 12 | GPIO30 | RC522 MOSI |
| 10 | GPIO31 | RC522 MISO |
| 19 | GPIO32 | RC522 RST |
| 18 | 3.3 V | RC522 3.3 V |
| 16 | GND | RC522 and relay ground |

GPIO 28–33 and 49–52 are not used by the display, touch, audio, SD card or
camera. Drive the strike through a relay module or a logic-level MOSFET; the
GPIO cannot power a strike directly.

## Lintel Vision prototype (walk-through doors)

A wall unit at head height beside the door that recognises people as they walk
up, with an optional overhead camera for doors where a person hidden behind
another must not be missed.
Prices are rough 2026 US figures; confirm with NZ resellers.

| Part | Choice | Approx. | Notes |
|---|---|---|---|
| Front depth camera | Orbbec Gemini 335 | $330 | Stereo depth + colour, USB 3 |
| Door computer | NVIDIA Jetson Orin Nano Super dev kit | $249 | Runs both cameras and the tracking |
| Screen | 7" touchscreen | $60-80 | Messages, pairing code, PIN pad |
| Speaker | Small USB or I2S speaker | $20 | Spoken messages |
| Status light | Addressable LED ring | $10 | Green, red, amber |
| Lock output | Relay module or logic-level MOSFET on a Jetson GPIO | $5 | Fail-secure strike |
| Door position | Reed switch | $5 | Crossings are counted while the door is open |
| Request to exit | Exit button | $10 | Free egress, never counted |
| Overhead (high-security doors) | Second Orbbec Gemini 335, looking down | $330 | 3-5 m active USB 3 cable |

About $700 for a standard door, $1,000 with the overhead camera. Until the
hardware arrives, `server/lintel_server/vision_sim.py` plays the unit's part
against a real server, and defines what the unit's software must send.
