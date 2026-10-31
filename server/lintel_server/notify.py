"""Alarm notifications to an operator-configured HTTPS webhook (Teams, Slack,
pager gateways). Sent from a worker thread so a slow endpoint never delays a
door decision."""

from __future__ import annotations

import json
import logging
import threading

import urllib.error
import urllib.request

log = logging.getLogger("lintel.notify")


def send(store, alarm: dict, force: bool = False) -> tuple[bool, str]:
    url = store.setting("alarm_webhook")
    if not url or not url.startswith("https://"):
        return False, "no https webhook configured"
    if not force and alarm.get("priority", 4) > int(store.setting("alarm_webhook_priority", "1")):
        return False, "below threshold"
    site = store.setting("site_name")
    text = f"[{site}] P{alarm.get('priority')} {alarm.get('title')}"
    body = json.dumps({"text": text, "site": site, "alarm": {k: alarm.get(k) for k in
                                                              ("id", "priority", "kind", "title", "door_id", "ts")}})
    req = urllib.request.Request(url, data=body.encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "Lintel/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return 200 <= r.status < 300, f"HTTP {r.status}"
    except (urllib.error.URLError, OSError) as e:
        log.warning("alarm webhook failed: %s", e)
        return False, str(e)


def send_async(store, alarm: dict) -> None:
    threading.Thread(target=send, args=(store, alarm), daemon=True).start()



