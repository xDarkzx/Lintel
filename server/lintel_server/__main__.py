"""Entry point: `python -m lintel_server serve`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import time
from pathlib import Path

import uvicorn

from .access import AccessEngine
from .photos import stamp_photo
from .security import ensure_tls
from .controller import Controller, run_controller
from .store import Store
from .web import Hub, create_app


async def maintenance(store: Store, app) -> None:
    """Hourly: photo retention (privacy) and scheduled door key rotation."""
    log = logging.getLogger("lintel.maintenance")
    while True:
        try:
            days = int(store.setting("photo_retention_days", "90"))
            cutoff = time.time() - days * 86400
            old = store.q("SELECT seq, photo FROM events WHERE photo IS NOT NULL AND ts < ?", (cutoff,))
            for r in old:
                (store.data_dir / "photos" / r["photo"]).unlink(missing_ok=True)
                store.x("UPDATE events SET photo=NULL WHERE seq=?", (r["seq"],))
            if old:
                store.journal("privacy.photos_purged", operator="system",
                              detail=f"{len(old)} photos older than {days} days deleted (hashes remain in the journal)")
                log.info("purged %d photos older than %d days", len(old), days)
            rekey_s = int(store.setting("rekey_days", "30")) * 86400
            for d in store.q("SELECT d.id FROM doors d JOIN devices v ON v.door_id = d.id "
                             "WHERE d.key_created < ? AND v.pending_blob IS NULL", (time.time() - rekey_s,)):
                app.state.auto_rekey(d["id"])
                log.info("rotated key for door %d", d["id"])
        except Exception:
            log.exception("maintenance pass failed")
        await asyncio.sleep(3600)


async def serve(data: Path, host: str, http_port: int, udp_port: int) -> None:
    store = Store(data)
    hub = Hub()
    ctl = Controller(store, AccessEngine(store), hub.publish)
    ctl.load_doors()
    faces = None
    models = Path(os.environ.get("LINTEL_MODELS", Path(__file__).resolve().parent.parent / "models"))
    try:
        from .faces import FaceEngine
        faces = FaceEngine(models)
        logging.getLogger("lintel").info("face recognition ready (%s)", models)
    except (FileNotFoundError, ImportError) as e:
        logging.getLogger("lintel").warning("face recognition disabled: %s", e)

    def face_evidence(ev: dict, jpeg: bytes, door: str, who: str) -> None:
        rel = stamp_photo(store.data_dir / "photos", jpeg, ev["seq"], ev["ts"], door, who)
        store.x("UPDATE events SET photo=? WHERE seq=?", (rel, ev["seq"]))
        hub.publish({"type": "photo", "seq": ev["seq"]})

    ctl.on_face_evidence = face_evidence
    app = create_app(store, ctl, hub, udp_port, faces)
    init = data / "initial_admin.txt"
    if init.exists():
        logging.getLogger("lintel").warning("first-run admin credentials are in %s", init)
    cert, key, fp = ensure_tls(data / "tls")
    app.state.tls_fingerprint = fp
    # Everything a door controller needs to talk to this server, in one file.
    (data / "controller.env").write_text(f"LINTEL_TOKEN={store.secrets.controller_token}\n"
                                         f"LINTEL_PIN_SHA256={fp}\n")
    logging.getLogger("lintel").info("HTTPS certificate SHA-256 %s", fp)
    server = uvicorn.Server(uvicorn.Config(app, host=host, port=http_port, log_level="info", server_header=False,
                                           ssl_certfile=str(cert), ssl_keyfile=str(key)))
    await asyncio.gather(server.serve(), run_controller(ctl, host, udp_port), maintenance(store, app))


def restore(args) -> None:
    import getpass

    from .backup import BackupError, restore_backup
    from .store import Store
    passphrase = os.environ.get("LINTEL_BACKUP_PASSPHRASE") or getpass.getpass("Backup passphrase: ")
    try:
        files = restore_backup(Path(args.file).read_bytes(), passphrase, Path(args.data), force=args.force)
    except BackupError as e:
        raise SystemExit(f"restore failed: {e}")
    store = Store(Path(args.data))
    check = store.verify_journal()
    print(f"restored {len(files)} files into {args.data}")
    print(f"audit chain: {'intact' if check['ok'] else 'BROKEN at #' + str(check['broken_at'])}, "
          f"{check['checked']} records")
    if not check["ok"]:
        raise SystemExit(2)


def main() -> None:
    p = argparse.ArgumentParser(prog="lintel_server")
    p.add_argument("command", nargs="?", default="serve", choices=["serve", "restore"])
    p.add_argument("file", nargs="?", help="restore: the .lbk backup file")
    p.add_argument("--force", action="store_true", help="restore: replace an existing database")
    p.add_argument("--data", default=os.environ.get("LINTEL_DATA", "data"))
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--http-port", type=int, default=int(os.environ.get("LINTEL_HTTPS_PORT", "8443")))
    p.add_argument("--udp-port", type=int, default=int(os.environ.get("LINTEL_UDP_PORT", "47800")))
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if a.command == "restore":
        if not a.file:
            raise SystemExit("usage: python -m lintel_server restore <backup.lbk> [--data DIR] [--force]")
        restore(a)
        return
    asyncio.run(serve(Path(a.data), a.host, a.http_port, a.udp_port))


if __name__ == "__main__":
    main()
