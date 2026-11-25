from pathlib import Path

from logsentinel.database import Database


def test_wal_and_purge(tmp_path: Path) -> None:
    with Database(str(tmp_path / "t.db")) as db:
        assert db.conn is not None
        mode = db.conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert mode == "wal"
        db.insert_events(
            [(0, "old", "low", "1.1.1.1", "x", 1), (1_000_000, "new", "low", "1.1.1.1", "x", 1)]
        )
        db.commit()
        assert db.purge(7, now=1_000_000) == 1
        rows = db.conn.execute("SELECT rule_name FROM security_events").fetchall()
        assert rows == [("new",)]
