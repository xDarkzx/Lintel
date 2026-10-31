# Production hardening for keypads

Development boards run without flash protection so they can be reflashed
freely. A keypad installed on a real door should have its door key protected
against someone who removes it from the wall and reads its flash.

These steps burn eFuses on the ESP32-P4. **They are permanent.** Do them on
production units, not on a development board you want to keep reflashing.

## 1. Flash encryption (release mode)

Encrypts the firmware and NVS (where the door key and identity key live) with
a key generated inside the chip and never readable over JTAG or USB.

```
idf.py menuconfig
  Security features -> Enable flash encryption on boot          [*]
  Security features -> Enable usage mode                        (Release)
  Component config -> NVS -> Enable NVS encryption               [*]
```

The first boot encrypts the flash in place. In release mode, plaintext
reflashing over serial is disabled afterwards.

## 2. Secure Boot V2

Only firmware signed with your key will boot, so a replaced binary cannot
exfiltrate keys.

```
espsecure.py generate_signing_key --version 2 --scheme rsa3072 secure_boot_signing_key.pem
idf.py menuconfig
  Security features -> Enable hardware Secure Boot in bootloader [*]
  Security features -> Secure Boot V2                            (RSA)
```

Keep the signing key offline. Losing it means no further firmware updates.

## 3. Disable debug access

```
espefuse.py burn_efuse DIS_USB_JTAG 1
espefuse.py burn_efuse DIS_PAD_JTAG 1
```

## 4. Physical

- Mount the keypad with tamper screws; route the USB link and lock wiring
  inside the wall to the door controller on the secure side.
- Use a fail-secure strike (locked when unpowered) unless fire code requires
  fail-safe on that door.
- If a keypad is stolen, unassign its door in the console: the door gets a new
  key and the stolen unit's key stops working at once.
