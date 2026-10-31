"""Captures console screenshots for the README with Playwright and the
installed Edge. Entry photos are blurred: they are real people.

    .venv/Scripts/python tools/capture_console.py <out dir> [--url URL]

Signs in with the account in data/initial_admin.txt. The console URL comes
from --url, else LINTEL_URL, else the local default from compose.yaml.
"""

import argparse
import json
import os
import re
import sqlite3
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

DATA = Path(__file__).resolve().parent.parent / "data"
DEFAULT_URL = os.environ.get("LINTEL_URL", "https://localhost:8443")
BLUR = ".thumb, .pick img, .shot:nth-child(2) img { filter: blur(9px) saturate(.6); }"
# Real cardholders are shown under placeholder names ("Employee 1", ...), read
# from the local database at capture time: every rendered text node, input
# value and avatar is rewritten before it is painted.
MASK = r"""
(() => {
  const names = __NAMES__.map(([from, to]) => [new RegExp("\\b" + from + "\\b", "g"), to]);
  const avatars = __AVATARS__;
  const fix = (t) => names.reduce((s, [re, to]) => s.replace(re, to), t);
  const walk = (root) => {
    const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    for (let n; (n = w.nextNode());) { const t = fix(n.data); if (t !== n.data) n.data = t; }
    root.querySelectorAll?.("input").forEach((i) => { const t = fix(i.value); if (t !== i.value) i.value = t; });
    root.querySelectorAll?.(".avatar").forEach((a) => { if (avatars[a.textContent]) a.textContent = avatars[a.textContent]; });
  };
  new MutationObserver(() => document.body && walk(document.body)).observe(document, { childList: true, subtree: true, characterData: true });
})();
"""


def mask_script() -> str:
    """MASK filled in with this site's cardholders, full names replaced first."""
    db = DATA / "lintel.db"
    with sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True) as c:
        people = c.execute("SELECT first_name, last_name FROM cardholders ORDER BY id").fetchall()
    full, parts, avatars = [], [], {}
    for i, (first, last) in enumerate(people, 1):
        full.append([re.escape(f"{first} {last}"), f"Employee {i}"])
        parts += [[re.escape(first), "Employee"], [re.escape(last), str(i)]]
        avatars[(first[:1] + last[:1]).upper()] = f"E{i}"
    return MASK.replace("__NAMES__", json.dumps(full + parts)).replace("__AVATARS__", json.dumps(avatars))


def credentials() -> tuple[str, str]:
    """The administrator the server generated on first start."""
    fields = dict(line.split(": ", 1) for line in (DATA / "initial_admin.txt").read_text().splitlines() if ": " in line)
    return fields["username"].strip(), fields["password"].strip()


def login(page, base: str) -> None:
    user, password = credentials()
    page.goto(base)
    page.fill("[name=username]", user)
    page.fill("[name=password]", password)
    page.click("button[type=submit]")
    page.wait_for_selector("#app:not(.hidden)")


def args(description: str, target: str) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("out", type=Path, help=target)
    ap.add_argument("--url", default=DEFAULT_URL, help="console URL (default: %(default)s)")
    return ap.parse_args()


def main(out: Path, base: str) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        ctx = browser.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=2, ignore_https_errors=True)
        ctx.add_init_script(mask_script())
        page = ctx.new_page()
        login(page, base)

        def shot(name: str, settle: float = 1.2) -> None:
            page.add_style_tag(content=BLUR)
            time.sleep(settle)
            page.screenshot(path=str(out / f"{name}.png"))
            print("saved", name)

        page.goto(f"{base}/#monitor"); page.wait_for_selector("#stats .stat"); shot("console-monitor")
        page.goto(f"{base}/#activity"); page.wait_for_selector("#act-body"); shot("console-activity")
        page.goto(f"{base}/#doors"); page.wait_for_selector("tr.click")
        page.click("tr.click"); page.wait_for_selector(".tabs button")
        page.click(".tabs button:nth-child(3)"); page.wait_for_selector(".shots"); shot("console-door-diagnostics", 2)
        page.keyboard.press("Escape")
        page.goto(f"{base}/#cardholders"); page.wait_for_selector("#rows tr")
        page.click("#rows tr.click"); page.wait_for_selector(".tabs button")
        page.click(".tabs button:nth-child(2)"); page.wait_for_selector(".cred-row"); shot("console-cardholder-credentials", 2)
        page.keyboard.press("Escape")
        page.goto(f"{base}/#schedules"); page.wait_for_selector(".week"); shot("console-schedules")
        page.goto(f"{base}/#audit"); page.click("#run"); page.wait_for_selector(".verify b:has-text('Chain')"); shot("console-audit")
        page.evaluate("document.documentElement.dataset.theme='dark'")
        page.goto(f"{base}/#monitor"); page.wait_for_selector("#stats .stat"); shot("console-monitor-dark")
        page.evaluate("try{localStorage.setItem('lintel-theme','light')}catch(e){}")
        browser.close()


if __name__ == "__main__":
    a = args("Capture console screenshots for the README.", "output directory")
    main(a.out, a.url.rstrip("/"))
