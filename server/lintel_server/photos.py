"""Entry photos: burn a timestamp caption in and file them by date."""

from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def stamp_photo(root: Path, jpeg: bytes, seq: int, ts: float, door: str, person: str) -> str:
    img = Image.open(io.BytesIO(jpeg)).convert("RGB")
    w, h = img.size
    when = datetime.fromtimestamp(ts).astimezone()
    caption = f"{door}  |  {when:%Y-%m-%d %H:%M:%S %Z}  |  {person}  |  event #{seq}"
    size = max(14, h // 28)
    font = ImageFont.load_default(size=size)
    bar = size + size // 2 + 8
    draw = ImageDraw.Draw(img, "RGBA")
    draw.rectangle([0, h - bar, w, h], fill=(0, 0, 0, 170))
    draw.text((12, h - bar + (bar - size) // 2 - 2), caption, font=font, fill=(255, 255, 255, 255))
    draw.text((w - 12, 10), "LINTEL", font=font, fill=(96, 165, 250, 230), anchor="ra")

    rel = Path(f"{when:%Y/%m/%d}") / f"{when:%H%M%S}_event{seq}.jpg"
    out = root / rel
    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out, "JPEG", quality=88)
    return rel.as_posix()

