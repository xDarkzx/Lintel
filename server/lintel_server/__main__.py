"""Entry point: `python -m lintel_server serve`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from pathlib import Path

import uvicorn

from .access import AccessEngine
from .controller import Controller, run_controller
from .store import Store
from .web import Hub, create_app


async def serve(data: Path, host: str, http_port: int, udp_port: int) -> None:
    store = Store(data)
    hub = Hub()
    ctl = Controller(store, AccessEngine(store), hub.publish)
    ctl.load_doors()
    app = create_app(store, ctl, hub, udp_port)
    init = data / "initial_admin.txt"
    if init.exists():
        logging.getLogger("lintel").warning("first-run admin credentials are in %s", init)
    server = uvicorn.Server(uvicorn.Config(app, host=host, port=http_port, log_level="info"))
    await asyncio.gather(server.serve(), run_controller(ctl, host, udp_port))


def main() -> None:
    p = argparse.ArgumentParser(prog="lintel_server")
    p.add_argument("command", nargs="?", default="serve", choices=["serve"])
    p.add_argument("--data", default=os.environ.get("LINTEL_DATA", "data"))
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--http-port", type=int, default=int(os.environ.get("LINTEL_HTTP_PORT", "8080")))
    p.add_argument("--udp-port", type=int, default=int(os.environ.get("LINTEL_UDP_PORT", "47800")))
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(serve(Path(a.data), a.host, a.http_port, a.udp_port))


if __name__ == "__main__":
    main()
