"""Alarm notifications to an operator-configured HTTPS webhook (Teams, Slack,
pager gateways). Sent from a worker thread so a slow endpoint never delays a
door decision.

The webhook is the one place the server makes outbound requests to an address
someone typed, so it is guarded against server-side request forgery: the host
must resolve only to public addresses (unless LINTEL_WEBHOOK_ALLOW_PRIVATE=1,
for a pager gateway on the site network), the connection goes to the exact
address that was checked so DNS cannot be switched in between, and redirects
are refused rather than followed.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import os
import socket
import ssl
import threading
from urllib.parse import urlsplit

log = logging.getLogger("lintel.notify")


class WebhookError(Exception):
    pass


def _allow_private() -> bool:
    return os.environ.get("LINTEL_WEBHOOK_ALLOW_PRIVATE") == "1"


def resolve_webhook(url: str) -> tuple[str, int, str, str]:
    """Checks a webhook URL and returns (host, port, path, address to connect to).
    Raises WebhookError for anything that is not HTTPS to a public address."""
    p = urlsplit(url)
    if p.scheme != "https" or not p.hostname:
        raise WebhookError("webhook must be an https:// URL")
    if p.username or p.password:
        raise WebhookError("webhook URL must not contain credentials")
    try:
        port = p.port or 443
    except ValueError:
        raise WebhookError("webhook port is not valid")
    try:
        infos = socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM)
    except OSError as e:
        raise WebhookError(f"webhook host does not resolve: {e}")
    addrs = [i[4][0] for i in infos]
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%")[0])
        if not ip.is_global and not _allow_private():
            raise WebhookError(f"webhook host resolves to a private or local address ({ip}); "
                               "set LINTEL_WEBHOOK_ALLOW_PRIVATE=1 for a gateway on the site network")
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")
    return p.hostname, port, path, addrs[0]


class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to a vetted address while verifying the certificate for the host name."""

    def __init__(self, host: str, address: str, port: int, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def send(store, alarm: dict, force: bool = False) -> tuple[bool, str]:
    url = store.setting("alarm_webhook")
    if not url:
        return False, "no webhook configured"
    if not force and alarm.get("priority", 4) > int(store.setting("alarm_webhook_priority", "1")):
        return False, "below threshold"
    site = store.setting("site_name")
    text = f"[{site}] P{alarm.get('priority')} {alarm.get('title')}"
    body = json.dumps({"text": text, "site": site, "alarm": {k: alarm.get(k) for k in
                                                              ("id", "priority", "kind", "title", "door_id", "ts")}})
    try:
        host, port, path, address = resolve_webhook(url)
        conn = _PinnedHTTPS(host, address, port, timeout=5)
        try:
            conn.request("POST", path, body=body.encode(),
                         headers={"Content-Type": "application/json", "User-Agent": "Lintel/0.1"})
            status = conn.getresponse().status
        finally:
            conn.close()
    except (WebhookError, OSError, http.client.HTTPException) as e:
        log.warning("alarm webhook failed: %s", e)
        return False, str(e)
    if 300 <= status < 400:
        return False, f"HTTP {status}: redirects are not followed"
    return 200 <= status < 300, f"HTTP {status}"


def send_async(store, alarm: dict) -> None:
    threading.Thread(target=send, args=(store, alarm), daemon=True).start()
