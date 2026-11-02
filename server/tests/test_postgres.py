"""PostgreSQL connection policy and integration coverage."""

import os
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.conninfo import make_conninfo
from psycopg import sql

from lintel_server.access import AccessEngine
from lintel_server.controller import Controller
from lintel_server.db import PostgresDB
from lintel_server.store import Store
from lintel_server.web import Hub, create_app


@pytest.mark.parametrize(
    ("url", "sslmode"),
    [
        ("postgresql://lintel:secret@localhost/lintel", "require"),
        ("postgresql://lintel:secret@localhost/lintel?sslmode=verify-full", "verify-full"),
        ("postgresql://lintel:secret@localhost/lintel?sslmode=disable", "disable"),
    ],
)
def test_postgres_requires_tls_by_default_and_preserves_explicit_sslmode(url, sslmode):
    assert PostgresDB._connection_options(url)["sslmode"] == sslmode


@pytest.fixture
def postgres_store(tmp_path):
    url = os.environ.get("LINTEL_TEST_DATABASE_URL")
    if not url:
        pytest.skip("LINTEL_TEST_DATABASE_URL is not configured")

    schema = "lintel_test_" + uuid4().hex
    admin = psycopg.connect(url, autocommit=True)
    admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    scoped_url = make_conninfo(url, options=f"-csearch_path={schema}")
    store = Store(tmp_path, database_url=scoped_url)
    try:
        yield store
    finally:
        store.db.close()
        admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
        admin.close()


def test_postgres_migrates_schema_and_returns_inserted_ids(postgres_store):
    store = postgres_store

    assert store.q1("SELECT MAX(version) v FROM schema_migrations")["v"] == 2
    door_id = store.x("INSERT INTO doors(id, name, key) VALUES(?, ?, ?)", (7, "Side door", b"k" * 16))
    schedule_id = store.x("INSERT INTO schedules(name) VALUES(?)", ("Night shift",))

    assert door_id == 7
    assert store.q1("SELECT name FROM doors WHERE id=?", (door_id,))["name"] == "Side door"
    assert store.q1("SELECT name FROM schedules WHERE id=?", (schedule_id,))["name"] == "Night shift"


def test_postgres_supports_the_admin_access_control_api(postgres_store):
    store = postgres_store
    ctl = Controller(store, AccessEngine(store), lambda _: None)
    client = TestClient(create_app(store, ctl, Hub(), 47800))
    password = (store.data_dir / "initial_admin.txt").read_text().split("password: ")[1].strip()

    assert client.post("/api/login", json={"username": "admin", "password": password}).status_code == 200
    assert client.post("/api/doors", json={"id": 1, "name": "Main entrance"}).status_code == 200
    schedule = client.post("/api/schedules", json={"name": "Office", "windows": [
        {"days": 31, "start_min": 480, "end_min": 1020},
    ]})
    assert schedule.status_code == 200
    group = client.post("/api/groups", json={"name": "Staff", "schedule_id": schedule.json()["id"],
                                              "doors": [1]})
    assert group.status_code == 200
    person = client.post("/api/cardholders", json={"first_name": "Ada", "last_name": "Lovelace",
                                                    "pin": "2468", "groups": [group.json()["id"]]})
    assert person.status_code == 200
    duplicate = client.post("/api/cardholders", json={"first_name": "Grace", "pin": "2468"})
    assert duplicate.status_code == 409
    updated = client.patch(f"/api/cardholders/{person.json()['id']}", json={"pin": "8642"})
    assert updated.status_code == 200
    assert client.get("/api/cardholders?q=ada").json()[0]["first_name"] == "Ada"
    assert client.get("/api/journal/verify").json()["ok"]


def test_postgres_audit_triggers_block_rewrites_but_allow_photo_retention(postgres_store):
    store = postgres_store
    event = store.journal("test.event", detail="preserve this")

    with pytest.raises(psycopg.errors.RaiseException, match="audit records cannot be changed"):
        store.x("UPDATE events SET detail=? WHERE seq=?", ("rewritten", event["seq"]))
    with pytest.raises(psycopg.errors.RaiseException, match="audit records cannot be deleted"):
        store.x("DELETE FROM events WHERE seq=?", (event["seq"],))
    with pytest.raises(psycopg.errors.RaiseException, match="audit records cannot be deleted"):
        store.db.script("TRUNCATE events CASCADE")

    store.x("UPDATE events SET photo=NULL WHERE seq=?", (event["seq"],))
    assert store.verify_journal()["ok"]


def test_postgres_allows_one_server_per_database(postgres_store):
    url = os.environ["LINTEL_TEST_DATABASE_URL"]  # the lock is per database, whatever the schema
    first, second = PostgresDB(url), PostgresDB(url)
    try:
        assert first.claim_server()
        assert not second.claim_server(wait_s=0)  # a second server would reuse door message counters
        first.close()
        assert second.claim_server()  # released when the holder goes away
    finally:
        first.close()
        second.close()


def test_postgres_reports_rows_affected_for_a_missing_row(postgres_store):
    assert postgres_store.x("UPDATE doors SET name=? WHERE id=?", ("x", 999)) == 0


def test_postgres_reconnects_after_losing_its_connection_and_keeps_the_server_claim(postgres_store):
    db = postgres_store.db
    assert db.claim_server()
    url = os.environ["LINTEL_TEST_DATABASE_URL"]
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute("SELECT pg_terminate_backend(%s)", (db.conn.info.backend_pid,))
    with pytest.raises(psycopg.OperationalError):
        db.q("SELECT 1")  # the statement in flight fails, and is not silently retried
    assert db.q1("SELECT 1 AS one")["one"] == 1  # the next one reconnects
    other = PostgresDB(url)
    try:
        assert not other.claim_server(wait_s=0)  # the claim was taken back on reconnect
    finally:
        other.close()
