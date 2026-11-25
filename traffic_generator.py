"""Module A : générateur de trafic web et simulateur d'attaques.

Exemples :
    python traffic_generator.py                      # trafic normal
    python traffic_generator.py --attack bruteforce  # trafic normal + attaque
"""

from __future__ import annotations

import argparse
import logging
import math
import random
import signal
import time
from datetime import datetime, timezone
from types import FrameType
from typing import IO

logger = logging.getLogger("traffic_generator")

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile",
]
BOTS = ["Googlebot/2.1 (+http://www.google.com/bot.html)", "bingbot/2.0"]
CLIS = ["curl/8.4.0", "python-requests/2.31.0", "Wget/1.21"]
SCANNERS = ["sqlmap/1.7", "Nikto/2.5.0", "gobuster/3.6"]

# (méthode, uri, poids)
NORMAL_ROUTES = [
    ("GET", "/", 20),
    ("GET", "/products", 15),
    ("GET", "/products/{n}", 15),
    ("GET", "/static/css/main.css", 10),
    ("GET", "/static/js/app.js", 10),
    ("GET", "/api/users/{n}", 10),
    ("POST", "/api/orders", 5),
    ("GET", "/api/orders/{n}", 5),
    ("POST", "/login", 3),
    ("GET", "/about", 4),
    ("GET", "/missing-page", 2),
]
SCAN_PATHS = [
    "/.env",
    "/wp-admin",
    "/etc/passwd",
    "/.git/config",
    "/admin.php",
    "/phpmyadmin",
    "/backup.zip",
    "/config.php",
    "/test",
    "/old",
]

running = True


def stop(_signum: int, _frame: FrameType | None) -> None:
    global running
    running = False


def log_line(ip: str, method: str, uri: str, status: int, size: int, ua: str, rt: float) -> str:
    now = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{now}] "{method} {uri} HTTP/1.1" {status} {size} "-" "{ua}" {rt:.3f}\n'


def random_ip() -> str:
    return f"192.168.{random.randint(0, 5)}.{random.randint(1, 254)}"


def normal_line() -> str:
    method, uri, _ = random.choices(NORMAL_ROUTES, weights=[r[2] for r in NORMAL_ROUTES])[0]
    uri = uri.replace("{n}", str(random.randint(1, 500)))
    status = random.choices([200, 304, 301, 404, 500], weights=[85, 6, 2, 6, 1])[0]
    if uri == "/missing-page":
        status = 404
    ua = random.choices(
        [random.choice(BROWSERS), random.choice(BOTS), random.choice(CLIS)], weights=[80, 12, 8]
    )[0]
    rt = max(0.001, random.lognormvariate(-3.0, 0.7))  # ~50 ms médian
    return log_line(random_ip(), method, uri, status, random.randint(200, 50_000), ua, rt)


def attack_lines(kind: str, attacker: str) -> list[str]:
    ua = random.choice(BROWSERS)
    if kind == "bruteforce":
        return [log_line(attacker, "POST", "/login", 401, 120, ua, 0.08) for _ in range(3)]
    if kind == "scan":
        return [
            log_line(
                attacker, "GET", random.choice(SCAN_PATHS), 404, 150, random.choice(SCANNERS), 0.01
            )
            for _ in range(3)
        ]
    if kind == "error_spike":
        return [
            log_line(
                random_ip(),
                "GET",
                f"/api/orders/{random.randint(1, 99)}",
                500,
                300,
                ua,
                random.uniform(0.5, 2.0),
            )
            for _ in range(2)
        ]
    if kind == "flood":
        return [
            log_line(attacker, "GET", "/", 200, 5000, random.choice(CLIS), 0.3) for _ in range(30)
        ]
    return []


def write(f: IO[str], lines: list[str]) -> None:
    f.writelines(lines)
    f.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="Générateur de logs Combined + request_time")
    parser.add_argument("--file", default="access.log", help="fichier de sortie")
    parser.add_argument("--rate", type=float, default=20, help="requêtes/s moyennes")
    parser.add_argument("--attack", choices=["flood", "bruteforce", "scan", "error_spike"])
    parser.add_argument("--attack-duration", type=float, default=30, help="durée attaque (s)")
    parser.add_argument("--duration", type=float, default=0, help="0 = infini")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    attacker = f"10.66.{random.randint(0, 255)}.{random.randint(1, 254)}"
    start = time.time()
    logger.info("Écriture dans %s (attaque : %s, IP %s)", args.file, args.attack, attacker)

    while running:
        elapsed = time.time() - start
        if args.duration and elapsed > args.duration:
            break
        # heures creuses / pics simulés par une sinusoïde de 2 minutes
        rate = args.rate * (1 + 0.6 * math.sin(elapsed * 2 * math.pi / 120))
        lines = [normal_line() for _ in range(max(1, int(rate / 4)))]
        if args.attack and elapsed < args.attack_duration:
            lines += attack_lines(args.attack, attacker)
        with open(args.file, "a", encoding="utf-8") as f:  # ouverture à chaque lot : rotation OK
            write(f, lines)
        time.sleep(0.25)
    logger.info("Générateur arrêté")


if __name__ == "__main__":
    main()
