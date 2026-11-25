from logsentinel.analyzer import Aggregator, RuleEngine, percentile
from logsentinel.collector import LogEntry

RULES = {
    "bruteforce": {"paths": ["/login"], "threshold": 15, "window_s": 30, "severity": "high"},
    "scan": {
        "threshold": 20,
        "window_s": 60,
        "severity": "medium",
        "sensitive_paths": ["/.env"],
        "sensitive_severity": "high",
    },
    "error_spike": {
        "ratio": 0.05,
        "window_s": 60,
        "min_requests": 20,
        "cooldown_s": 60,
        "severity": "critical",
    },
}


def entry(
    ts: float,
    method: str = "GET",
    route: str = "/",
    status: int = 200,
    ip: str = "1.1.1.1",
    latency: float = 10.0,
) -> LogEntry:
    return LogEntry(ip, ts, method, route, route, "HTTP/1.1", status, 100, "ua", "Browser", latency)


def test_percentile() -> None:
    values = [float(v) for v in range(1, 101)]
    assert percentile(values, 50) == 50
    assert percentile(values, 99) == 99
    assert percentile([], 95) == 0.0


def test_aggregator() -> None:
    agg = Aggregator(5)
    for i in range(10):
        agg.add(entry(0, status=500 if i == 0 else 200))
    r = agg.flush(100)
    assert r["traffic"]["rps"] == 2.0
    assert r["traffic"]["count_5xx"] == 1
    assert r["endpoints"][0][3] == 10


def test_bruteforce() -> None:
    eng = RuleEngine(RULES)
    events = [ev for i in range(16) for ev in eng.process(entry(i, "POST", "/login", 401))]
    assert [e.rule_name for e in events] == ["bruteforce"]


def test_bruteforce_slow_is_ignored() -> None:
    eng = RuleEngine(RULES)
    events = [ev for i in range(16) for ev in eng.process(entry(i * 3, "POST", "/login", 401))]
    assert events == []


def test_scan_and_sensitive() -> None:
    eng = RuleEngine(RULES)
    events = [ev for i in range(21) for ev in eng.process(entry(i, route="/x", status=404))]
    assert any(e.rule_name == "scan_404" for e in events)
    assert (
        eng.process(entry(30, route="/.env", status=404, ip="2.2.2.2"))[0].rule_name
        == "sensitive_path"
    )


def test_error_spike() -> None:
    eng = RuleEngine(RULES)
    events = [
        ev for i in range(20) for ev in eng.process(entry(100 + i, status=500 if i < 2 else 200))
    ]
    assert [e.rule_name for e in events] == ["error_spike"]
