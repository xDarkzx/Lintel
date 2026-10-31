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
