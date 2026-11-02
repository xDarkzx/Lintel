"""Records the demo console for the README: a video of the showcase (the
demo's first minute, every scenario once), then a GIF made from it.

    docker compose -f demo/compose.yaml up --build     (with LINTEL_DEMO_START_DELAY=25)
    python tools/record_demo.py out/ --url https://localhost:8443 --password <demo admin password>
    -> out/demo.webm, out/demo.gif

The demo's people are cartoons, so nothing is masked or blurred.
Needs Playwright with Edge, and ffmpeg on PATH.
"""

import argparse
import shutil
import subprocess
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

# Seconds after the showcase starts, and where the console should be then.
# The showcase runs: group, tailgater, PIN, photo spoof, contractor, server
# room, PIN guessing, hidden person, duress - one every 6 s.
TIMELINE = (
    (0, "#monitor"),     # a group walks through, then a stranger tailgates: P1 alarm
    (16, "#alarms"),     # the alarm queue with the unauthorised person
    (24, "#activity"),   # every person logged by name; spoof and contractor arrive
    (34, "#doors"),      # three doors online, the lab in walk-through mode
    (40, "#monitor"),    # PIN guessing locks the server room; a hidden person; duress
    (56, "#audit"),      # the hash chain verified
)
END_S = 64


def record(out: Path, base: str, password: str) -> tuple[Path, float]:
    """Returns the video and the second in it where the showcase started."""
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        ctx = browser.new_context(viewport={"width": 1280, "height": 760}, ignore_https_errors=True,
                                  record_video_dir=str(out), record_video_size={"width": 1280, "height": 760})
        page = ctx.new_page()
        t0 = time.monotonic()
        page.goto(base)
        page.fill("[name=username]", "admin")
        page.fill("[name=password]", password)
        page.click("button[type=submit]")
        page.wait_for_selector("#app:not(.hidden)")
        page.goto(f"{base}/#monitor")
        page.wait_for_selector("#stats .stat")
        # The showcase starts with a walk-through entry at the lab.
        # page.evaluate waits for the fetch (a bare Promise would count as true to wait_for_function).
        deadline = time.monotonic() + 120
        while not page.evaluate("async () => (await (await fetch('/api/events?kind=access.granted&door=3&limit=1'))"
                                ".json()).length > 0"):
            if time.monotonic() > deadline:
                raise TimeoutError("the demo showcase never started")
            time.sleep(0.25)
        start = time.monotonic()
        for at, view in TIMELINE:
            time.sleep(max(0.0, start + at - time.monotonic()))
            page.goto(f"{base}/{view}")
            if view == "#audit":
                page.click("#run")
        time.sleep(max(0.0, start + END_S - time.monotonic()))
        video = Path(page.video.path())
        ctx.close()
        browser.close()
    final = out / "demo.webm"
    shutil.move(video, final)
    return final, start - t0


def to_gif(video: Path, skip_s: float, gif: Path, speed: float = 1.6, width: int = 960, fps: int = 10) -> None:
    """A palette-optimised GIF of the showcase, sped up so it loops in about 40 s."""
    vf = f"setpts=PTS/{speed},fps={fps},scale={width}:-1:flags=lanczos"
    common = ["ffmpeg", "-y", "-loglevel", "error", "-ss", f"{max(0.0, skip_s - 1):.2f}", "-t", str(END_S + 1),
              "-i", str(video)]
    palette = gif.with_suffix(".png")
    subprocess.run(common + ["-vf", f"{vf},palettegen=max_colors=128:stats_mode=diff", str(palette)], check=True)
    subprocess.run(common + ["-i", str(palette), "-lavfi",
                             f"{vf}[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle",
                             str(gif)], check=True)
    palette.unlink()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Record the demo showcase and make the README GIF.")
    ap.add_argument("out", type=Path)
    ap.add_argument("--url", default="https://localhost:8443")
    ap.add_argument("--password", required=True, help="the demo admin password from the demo's log")
    a = ap.parse_args()
    video, skip = record(a.out, a.url.rstrip("/"), a.password)
    to_gif(video, skip, a.out / "demo.gif")
    print(f"saved {video} and {a.out / 'demo.gif'} (showcase starts at {skip:.1f} s)")
