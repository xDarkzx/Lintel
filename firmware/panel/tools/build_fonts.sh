#!/usr/bin/env bash
# Regenerates the LVGL fonts in main/fonts/ from Inter and Tabler Icons.
#   tools/build_fonts.sh   (needs node + npm)
set -euo pipefail
cd "$(dirname "$0")/.."
SRC=$(mktemp -d)
(cd "$SRC" && npm pack -q @tabler/icons-webfont@3.31.0 @fontsource/inter@5.1.1 >/dev/null \
  && for f in *.tgz; do tar xzf "$f" --one-top-level="${f%.tgz}"; done)
INTER="$SRC/fontsource-inter-5.1.1/package/files"
TABLER="$SRC/tabler-icons-webfont-3.31.0/package/dist/fonts/tabler-icons.ttf"
CONV="npx -y lv_font_conv@1.5.2 --bpp 4 --format lvgl --no-compress --lv-include lvgl.h"
ASCII=0x20-0x7E,0xB7

# Text: Inter 500 / 600
$CONV --size 15 --font "$INTER/inter-latin-500-normal.woff" -r $ASCII -o main/fonts/inter_15.c
$CONV --size 18 --font "$INTER/inter-latin-500-normal.woff" -r $ASCII -o main/fonts/inter_18.c
$CONV --size 22 --font "$INTER/inter-latin-600-normal.woff" -r $ASCII -o main/fonts/inter_22.c
$CONV --size 30 --font "$INTER/inter-latin-600-normal.woff" -r $ASCII -o main/fonts/inter_30.c
$CONV --size 34 --font "$INTER/inter-latin-500-normal.woff" -r 0x30-0x39 -o main/fonts/inter_keys.c
$CONV --size 84 --font "$INTER/inter-latin-500-normal.woff" -r 0x30-0x3A -o main/fonts/inter_clock.c

# Icons (Tabler, MIT): lock, lock-open, lock-exclamation, nfc, face-id, fingerprint,
# backspace, check, x, alert-triangle, plug-connected-x, refresh, user-scan
ICONS=0xEAE2,0xEAE1,0xF92B,0xEEB7,0xEA9B,0xEBD1,0xEA2D,0xEA5E,0xEB55,0xEA06,0xF0A0,0xEB13,0xFCAF
$CONV --size 18 --font "$TABLER" -r $ICONS -o main/fonts/icons_18.c
$CONV --size 32 --font "$TABLER" -r $ICONS -o main/fonts/icons_32.c
$CONV --size 96 --font "$TABLER" -r $ICONS -o main/fonts/icons_96.c
rm -rf "$SRC"
echo "fonts written to main/fonts/"
