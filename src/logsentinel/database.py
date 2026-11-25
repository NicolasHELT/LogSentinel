"""Persistance SQLite (mode WAL, index, requêtes paramétrées, purge)."""

from __future__ import annotations

import logging
import sqlite3
import time
from types import TracebackType
from typing import Any

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    window_seconds INTEGER NOT NULL,
    total_requests INTEGER NOT NULL,
    rps REAL NOT NULL,
    bytes_sent INTEGER NOT NULL,
    count_2xx INTEGER NOT NULL,
    count_3xx INTEGER NOT NULL,
    count_4xx INTEGER NOT NULL,
    count_5xx INTEGER NOT NULL,
    latency_p50_ms REAL NOT NULL,
    latency_p95_ms REAL NOT NULL,
    latency_p99_ms REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic_metrics(timestamp);

CREATE TABLE IF NOT EXISTS endpoint_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    method TEXT NOT NULL,
    normalized_route TEXT NOT NULL,
    hit_count INTEGER NOT NULL,
    avg_latency_ms REAL NOT NULL,
    error_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_endpoint_ts ON endpoint_stats(timestamp);
CREATE INDEX IF NOT EXISTS idx_endpoint_method ON endpoint_stats(method, timestamp);

CREATE TABLE IF NOT EXISTS client_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    ua_category TEXT NOT NULL,
    hit_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_client_ts ON client_stats(timestamp);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT,
    details TEXT,
    event_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_security_ts ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_sev ON security_events(severity, timestamp);
"""

TABLES = ("traffic_metrics", "endpoint_stats", "client_stats", "security_events")


class Database:
    """Accès SQLite, utilisable avec `with Database(path) as db:`."""

    def __init__(self, path: str) -> None:
        """Prépare l'accès à la base.

        Args:
            path: Chemin du fichier SQLite, ou ":memory:" pour une base en mémoire.
        """
        self.path = path
        self.conn: sqlite3.Connection | None = None

    def __enter__(self) -> Database:
        """Ouvre la connexion en entrant dans le bloc with."""
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Ferme la connexion en sortant du bloc with, même en cas d'erreur."""
        self.close()

    def connect(self) -> None:
        """Ouvre la connexion, active le mode WAL et crée les tables et index."""
        self.conn = sqlite3.connect(self.path, timeout=10)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        logger.info("Base SQLite prête : %s (WAL)", self.path)

    def close(self) -> None:
        """Ferme la connexion si elle est ouverte."""
        if self.conn is not None:
            self.conn.close()
            self.conn = None
            logger.info("Connexion SQLite fermée")

    def _db(self) -> sqlite3.Connection:
        """Retourne la connexion active.

        Raises:
            RuntimeError: Si la base n'est pas connectée.
        """
        if self.conn is None:
            raise RuntimeError("Base non connectée")
        return self.conn

    def insert_traffic(self, m: dict[str, Any]) -> None:
        """Insère les métriques d'une fenêtre dans traffic_metrics.

        Args:
            m: Dictionnaire "traffic" produit par Aggregator.flush().
        """
        self._db().execute(
            "INSERT INTO traffic_metrics (timestamp, window_seconds, total_requests, rps,"
            " bytes_sent, count_2xx, count_3xx, count_4xx, count_5xx,"
            " latency_p50_ms, latency_p95_ms, latency_p99_ms)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                m["timestamp"],
                m["window_seconds"],
                m["total_requests"],
                m["rps"],
                m["bytes_sent"],
                m["count_2xx"],
                m["count_3xx"],
                m["count_4xx"],
                m["count_5xx"],
                m["latency_p50_ms"],
                m["latency_p95_ms"],
                m["latency_p99_ms"],
            ),
        )

    def insert_endpoints(self, rows: list[tuple[int, str, str, int, float, int]]) -> None:
        """Insère les statistiques par endpoint.

        Args:
            rows: Tuples (timestamp, method, route, hits, latence moyenne, erreurs).
        """
        self._db().executemany(
            "INSERT INTO endpoint_stats (timestamp, method, normalized_route, hit_count,"
            " avg_latency_ms, error_count) VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )

    def insert_clients(self, rows: list[tuple[int, str, int]]) -> None:
        """Insère le comptage par type de client.

        Args:
            rows: Tuples (timestamp, catégorie User-Agent, hits).
        """
        self._db().executemany(
            "INSERT INTO client_stats (timestamp, ua_category, hit_count) VALUES (?, ?, ?)",
            rows,
        )

    def insert_events(self, rows: list[tuple[int, str, str, str, str, int]]) -> None:
        """Insère des alertes de sécurité.

        Args:
            rows: Tuples (timestamp, règle, sévérité, IP, détails, nombre).
        """
        self._db().executemany(
            "INSERT INTO security_events (timestamp, rule_name, severity, source_ip,"
            " details, event_count) VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )

    def commit(self) -> None:
        """Valide la transaction en cours."""
        self._db().commit()

    def purge(self, retention_days: int, now: float | None = None) -> int:
        """Supprime les données plus anciennes que la durée de rétention.

        Args:
            retention_days: Nombre de jours conservés.
            now: Horodatage de référence (par défaut l'heure actuelle).

        Returns:
            Nombre total de lignes supprimées.
        """
        limit = int((now or time.time()) - retention_days * 86400)
        deleted = 0
        db = self._db()
        for table in TABLES:  # noms fixes, pas d'entrée utilisateur
            cur = db.execute(f"DELETE FROM {table} WHERE timestamp < ?", (limit,))
            deleted += cur.rowcount
        db.commit()
        if deleted:
            logger.info("Purge : %d lignes supprimées", deleted)
        return deleted
