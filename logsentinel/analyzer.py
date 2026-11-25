"""Module C : agrégation par fenêtre et moteur de règles SIEM."""

from __future__ import annotations

import logging
import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import Any

from logsentinel.collector import LogEntry

logger = logging.getLogger(__name__)


def percentile(values: list[float], pct: float) -> float:
    """Percentile par la méthode du rang le plus proche."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return round(ordered[rank - 1], 2)


@dataclass
class SecurityEvent:
    timestamp: int
    rule_name: str
    severity: str
    source_ip: str
    details: str
    event_count: int

    def as_row(self) -> tuple[int, str, str, str, str, int]:
        return (
            self.timestamp,
            self.rule_name,
            self.severity,
            self.source_ip,
            self.details,
            self.event_count,
        )


class Aggregator:
    """Accumule les requêtes d'une fenêtre puis calcule les métriques."""

    def __init__(self, window_s: int) -> None:
        self.window_s = window_s
        self.reset()

    def reset(self) -> None:
        self.entries: list[LogEntry] = []

    def add(self, entry: LogEntry) -> None:
        self.entries.append(entry)

    def flush(self, now: float) -> dict[str, Any]:
        """Retourne les métriques de la fenêtre et vide le tampon."""
        ts = int(now)
        families: Counter[str] = Counter(f"{e.status // 100}xx" for e in self.entries)
        latencies = [e.latency_ms for e in self.entries]
        total = len(self.entries)
        traffic = {
            "timestamp": ts,
            "window_seconds": self.window_s,
            "total_requests": total,
            "rps": round(total / self.window_s, 2),
            "bytes_sent": sum(e.size for e in self.entries),
            "count_2xx": families["2xx"],
            "count_3xx": families["3xx"],
            "count_4xx": families["4xx"],
            "count_5xx": families["5xx"],
            "latency_p50_ms": percentile(latencies, 50),
            "latency_p95_ms": percentile(latencies, 95),
            "latency_p99_ms": percentile(latencies, 99),
        }
        groups: dict[tuple[str, str], list[LogEntry]] = defaultdict(list)
        for e in self.entries:
            groups[(e.method, e.route)].append(e)
        endpoints = [
            (
                ts,
                method,
                route,
                len(items),
                round(sum(i.latency_ms for i in items) / len(items), 2),
                sum(1 for i in items if i.status >= 400),
            )
            for (method, route), items in groups.items()
        ]
        clients = [(ts, cat, n) for cat, n in Counter(e.ua_category for e in self.entries).items()]
        self.reset()
        return {"traffic": traffic, "endpoints": endpoints, "clients": clients}


class RuleEngine:
    """Détection par fenêtres glissantes en mémoire (collections.deque)."""

    def __init__(self, rules: dict[str, Any]) -> None:
        self.bf = rules["bruteforce"]
        self.scan = rules["scan"]
        self.spike = rules["error_spike"]
        self._bf_hits: dict[str, deque[float]] = defaultdict(deque)
        self._404_hits: dict[str, deque[float]] = defaultdict(deque)
        self._status: deque[tuple[float, bool]] = deque()
        self._last_spike = 0.0
        self._sensitive_seen: dict[tuple[str, str], float] = {}

    @staticmethod
    def _slide(dq: deque[Any], now: float, window: float, key: Any = None) -> None:
        while dq and (dq[0] if key is None else dq[0][0]) < now - window:
            dq.popleft()

    def process(self, e: LogEntry) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        ts = e.timestamp

        # 1. Brute-force : trop de POST sur les routes d'authentification
        if e.method == "POST" and e.route in self.bf["paths"]:
            dq = self._bf_hits[e.ip]
            dq.append(ts)
            self._slide(dq, ts, self.bf["window_s"])
            if len(dq) > self.bf["threshold"]:
                events.append(
                    SecurityEvent(
                        int(ts),
                        "bruteforce",
                        self.bf["severity"],
                        e.ip,
                        f"{len(dq)} POST {e.route} en {self.bf['window_s']}s",
                        len(dq),
                    )
                )
                dq.clear()

        # 2a. Scan : trop de 404
        if e.status == 404:
            dq = self._404_hits[e.ip]
            dq.append(ts)
            self._slide(dq, ts, self.scan["window_s"])
            if len(dq) > self.scan["threshold"]:
                events.append(
                    SecurityEvent(
                        int(ts),
                        "scan_404",
                        self.scan["severity"],
                        e.ip,
                        f"{len(dq)} erreurs 404 en {self.scan['window_s']}s",
                        len(dq),
                    )
                )
                dq.clear()

        # 2b. Scan : accès à un chemin sensible
        key = (e.ip, e.route)
        recent = ts - self._sensitive_seen.get(key, -1e12) < self.scan["window_s"]
        if not recent and any(e.route.startswith(p) for p in self.scan["sensitive_paths"]):
            self._sensitive_seen[key] = ts
            events.append(
                SecurityEvent(
                    int(ts),
                    "sensitive_path",
                    self.scan["sensitive_severity"],
                    e.ip,
                    f"Accès à {e.uri}",
                    1,
                )
            )

        # 3. Pic d'erreurs 5xx sur la dernière minute
        self._status.append((ts, e.status >= 500))
        self._slide(self._status, ts, self.spike["window_s"], key=0)
        total = len(self._status)
        errors = sum(1 for _, is_err in self._status if is_err)
        if (
            total >= self.spike["min_requests"]
            and errors / total > self.spike["ratio"]
            and ts - self._last_spike >= self.spike["cooldown_s"]
        ):
            self._last_spike = ts
            events.append(
                SecurityEvent(
                    int(ts),
                    "error_spike",
                    self.spike["severity"],
                    "-",
                    f"{errors}/{total} réponses 5xx ({errors / total:.1%}) sur "
                    f"{self.spike['window_s']}s",
                    errors,
                )
            )

        for ev in events:
            logger.warning(
                "ALERTE %s [%s] %s : %s", ev.rule_name, ev.severity, ev.source_ip, ev.details
            )
        return events
