"""Records a console walkthrough against the live system and turns it into a
GIF for the README. Needs a keypad attached through the door controller, since
the walkthrough asks the real panel for a screenshot. Cardholder names are
masked and entry photos blurred, as in capture_console.py.

    .venv/Scripts/python tools/record_walkthrough.py <out.gif> [--url URL]

The walkthrough uses the first online door.
"""

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

from capture_console import BLUR, DATA, args, login, mask_script

SIZE = {"width": 1280, "height": 800}


def record(video_dir: Path, base: str) -> Path:
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        ctx = browser.new_context(viewport=SIZE, ignore_https_errors=True, record_video_dir=str(video_dir), record_video_size=SIZE)
        ctx.add_init_script(mask_script())
        ctx.add_init_script(f"addEventListener('DOMContentLoaded', () => {{ const s = document.createElement('style'); s.textContent = {BLUR!r}; document.head.append(s); }});")
        page = ctx.new_page()
        pause = lambda s: page.wait_for_timeout(int(s * 1000))  # noqa: E731

        login(page, base)
        page.wait_for_selector("#stats .stat")
        door = page.evaluate("fetch('/api/doors').then(r => r.json()).then(ds => (ds.find(d => d.online) || {}).id)")
        if door is None:
            raise SystemExit("no door is online: attach a keypad through the door controller first")
        shot_file = DATA / "diag" / f"door{door}_screenshot.jpg"
        pause(3)

        page.goto(f"{base}/#doors"); page.wait_for_selector(f"tr.click[data-id='{door}']"); pause(1.5)
        page.click(f"tr.click[data-id='{door}']"); page.wait_for_selector(".tabs button"); pause(2)
        page.click(".tabs button:nth-child(3)"); page.wait_for_selector(".shots"); pause(1.5)
        before = shot_file.stat().st_mtime if shot_file.exists() else 0
        page.click("[data-cmd=screenshot]")
        # The panel answers on its next heartbeat; wait for the fresh capture to be stored.
        deadline = time.time() + 30
        while time.time() < deadline and (not shot_file.exists() or shot_file.stat().st_mtime == before):
            pause(0.5)
        pause(0.5)
        page.click(".tabs button:nth-child(3)"); page.wait_for_selector(".shots")
        pause(3.5)
        page.keyboard.press("Escape"); pause(0.8)

        page.goto(f"{base}/#cardholders"); page.wait_for_selector("#rows tr"); pause(1.5)
        page.click("#rows tr.click"); page.wait_for_selector(".tabs button"); pause(1.5)
        page.click(".tabs button:nth-child(2)"); page.wait_for_selector(".cred-row"); pause(2.5)
        page.keyboard.press("Escape"); pause(0.8)

        page.goto(f"{base}/#schedules"); page.wait_for_selector(".week"); pause(2.5)
        page.goto(f"{base}/#audit"); page.wait_for_selector("#run"); pause(1)
        page.click("#run"); page.wait_for_selector(".verify b:has-text('Chain')"); pause(3)

        video = Path(page.video.path())
        ctx.close()
        browser.close()
    return video


def to_gif(video: Path, out: Path, width: int = 960, fps: int = 10) -> None:
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise SystemExit("ffmpeg is required to build the GIF")
    vf = f"fps={fps},scale={width}:-1:flags=lanczos,split[a][b];[a]palettegen=stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle"
    subprocess.run([ffmpeg, "-y", "-loglevel", "error", "-i", str(video), "-vf", vf, "-loop", "0", str(out)], check=True)


def main(out: Path, base: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        video = record(Path(tmp), base)
        out.parent.mkdir(parents=True, exist_ok=True)
        to_gif(video, out)
    print(f"saved {out} ({out.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    a = args("Record the console walkthrough GIF for the README.", "output GIF")
    main(a.out, a.url.rstrip("/"))
