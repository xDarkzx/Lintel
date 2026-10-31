"""Builds static/icons.svg, a sprite of the Tabler icons (MIT) the dashboard uses.

    python tools/build_icons.py <path to @tabler/icons package>/icons/outline
"""

import re
import sys
from pathlib import Path

ICONS = """
layout-dashboard bell alert-triangle alert-octagon list-details users users-group calendar-time door door-enter
settings shield-check user-shield search lock lock-open logout chevron-down chevron-right x check camera photo
refresh power eye download plus trash key nfc face-id fingerprint id-badge-2 cpu temperature clock
plug-connected plug-connected-x sun moon filter user-scan building activity device-desktop arrows-exchange
shield-lock dots user broadcast info-circle circle-check circle-x hourglass report history lock-access
map map-pin upload minus pencil current-location
""".split()


def main(src: Path, out: Path) -> None:
    symbols = []
    for name in ICONS:
        svg = (src / f"{name}.svg").read_text(encoding="utf-8")
        inner = re.search(r"<svg[^>]*>(.*)</svg>", svg, re.S).group(1)
        inner = re.sub(r'<path stroke="none" d="M0 0h24v24H0z" fill="none"\s*/>', "", inner).strip()
        symbols.append(f'<symbol id="i-{name}" viewBox="0 0 24 24">{inner}</symbol>')
    out.write_text('<svg xmlns="http://www.w3.org/2000/svg" style="display:none">' + "".join(symbols) + "</svg>\n",
                   encoding="utf-8")
    print(f"{len(symbols)} icons -> {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(__file__).resolve().parent.parent / "lintel_server" / "static" / "icons.svg")
