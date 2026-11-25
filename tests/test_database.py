"""Tests des opérations CRUD SQLite (base :memory:) et du mode WAL."""

from pathlib import Path

import pytest

from logsentinel.database import Database

TRAFFIC = {
    "timestamp": 1_000,
    "window_seconds": 5,
    "total_requests": 10,
    "rps": 2.0,
    "bytes_sent": 5_000,
    "count_2xx": 7,
    "count_3xx": 1,
    "count_4xx": 1,
    "count_5xx": 1,
    "latency_p50_ms": 50.0,
    "latency_p95_ms": 120.0,
    "latency_p99_ms": 300.0,
}


@pytest.fixture
def db():
    """Base SQLite en mémoire, schéma créé, fermée après le test."""
    with Database(":memory:") as database:
        yield database


def test_tables_created(db: Database) -> None:
    assert db.conn is not None
    names = {r[0] for r in db.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"traffic_metrics", "endpoint_stats", "client_stats", "security_events"} <= names


def test_insert_and_read_traffic(db: Database) -> None:
    db.insert_traffic(TRAFFIC)
    db.commit()
    assert db.conn is not None
    row = db.conn.execute(
        "SELECT total_requests, count_5xx, latency_p95_ms FROM traffic_metrics"
    ).fetchone()
    assert row == (10, 1, 120.0)


def test_insert_endpoints_clients_events(db: Database) -> None:
    db.insert_endpoints([(1_000, "GET", "/api/users/{id}", 3, 42.0, 1)])
    db.insert_clients([(1_000, "Browser", 8), (1_000, "Bot/Crawler", 2)])
    db.insert_events([(1_000, "bruteforce", "high", "10.0.0.1", "16 POST /login", 16)])
    db.commit()
    assert db.conn is not None
    assert db.conn.execute("SELECT normalized_route FROM endpoint_stats").fetchone() == (
        "/api/users/{id}",
    )
    assert db.conn.execute("SELECT SUM(hit_count) FROM client_stats").fetchone() == (10,)
    assert db.conn.execute("SELECT rule_name, source_ip FROM security_events").fetchone() == (
        "bruteforce",
        "10.0.0.1",
    )


def test_parameterized_query_is_safe(db: Database) -> None:
    evil = "x'); DROP TABLE security_events; --"
    db.insert_events([(1_000, "scan_404", "medium", evil, "test", 1)])
    db.commit()
    assert db.conn is not None
    assert db.conn.execute("SELECT source_ip FROM security_events").fetchone() == (evil,)


def test_purge_deletes_old_rows(db: Database) -> None:
    db.insert_events(
        [(0, "old", "low", "1.1.1.1", "x", 1), (1_000_000, "new", "low", "1.1.1.1", "x", 1)]
    )
    db.commit()
    assert db.purge(7, now=1_000_000) == 1
    assert db.conn is not None
    assert db.conn.execute("SELECT rule_name FROM security_events").fetchall() == [("new",)]


def test_not_connected_raises() -> None:
    with pytest.raises(RuntimeError):
        Database(":memory:").commit()


def test_wal_mode_on_file(tmp_path: Path) -> None:
    with Database(str(tmp_path / "t.db")) as database:
        assert database.conn is not None
        assert database.conn.execute("PRAGMA journal_mode;").fetchone()[0] == "wal"
