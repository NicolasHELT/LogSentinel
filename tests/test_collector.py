import os
from pathlib import Path

from logsentinel.collector import LogTailer, categorize_ua, normalize_route, parse_line

LINE = (
    '10.0.0.1 - - [25/Nov/2026:10:00:00 +0000] "GET /api/users/42?x=1 HTTP/1.1" '
    '200 512 "-" "Mozilla/5.0 (X11)" 0.123'
)


def test_parse_line() -> None:
    e = parse_line(LINE)
    assert e is not None
    assert e.ip == "10.0.0.1"
    assert e.method == "GET"
    assert e.status == 200
    assert e.size == 512
    assert e.route == "/api/users/{id}"
    assert e.ua_category == "Browser"
    assert abs(e.latency_ms - 123) < 0.01


def test_parse_invalid() -> None:
    assert parse_line("ligne invalide") is None


def test_normalize_route() -> None:
    assert normalize_route("/api/users/42/orders/7") == "/api/users/{id}/orders/{id}"
    assert normalize_route("/static/app.js") == "/static/app.js"


def test_categorize_ua() -> None:
    assert categorize_ua("Googlebot/2.1") == "Bot/Crawler"
    assert categorize_ua("curl/8.0") == "CLI/Script"
    assert categorize_ua("sqlmap/1.7") == "Suspicious"
    assert categorize_ua("-") == "Suspicious"


def test_tailer_rotation(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text("")
    tailer = LogTailer(str(log))
    assert list(tailer.poll()) == []
    with open(log, "a") as f:
        f.write("a\nb\n")
    assert list(tailer.poll()) == ["a", "b"]
    os.rename(log, tmp_path / "access.log.1")  # rotation
    log.write_text("c\n")
    lines = list(tailer.poll()) + list(tailer.poll())
    assert lines == ["c"]
    log.write_text("")  # troncature
    list(tailer.poll())
    with open(log, "a") as f:
        f.write("d\n")
    assert list(tailer.poll()) == ["d"]
    tailer.close()
