"""Module B : suivi du fichier de logs (tail -F) et parsing."""

from __future__ import annotations

import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import IO, Iterator

logger = logging.getLogger(__name__)

# Combined Log Format + $request_time (secondes) en fin de ligne
LOG_PATTERN = re.compile(
    r"(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<uri>\S+) (?P<version>HTTP/[\d.]+)" '
    r"(?P<status>\d{3}) (?P<size>\d+|-) "
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)" (?P<rt>[\d.]+)'
)
TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

ID_PATTERN = re.compile(
    r"/(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|[0-9a-fA-F]{16,})(?=/|$)"
)
SUSPICIOUS_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|hydra|nuclei", re.I
)
BOT_UA = re.compile(r"bot|crawler|spider|slurp", re.I)
CLI_UA = re.compile(r"curl|wget|python-requests|httpie|go-http-client|postman", re.I)


def open_shared(path: str) -> IO[str]:
    """Ouvre en lecture sans bloquer le renommage/suppression (rotation sous Windows)."""
    if sys.platform != "win32":
        return open(path, encoding="utf-8", errors="replace")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    create_file = ctypes.windll.kernel32.CreateFileW  # type: ignore[attr-defined]
    create_file.restype = wintypes.HANDLE
    generic_read, share_all, open_existing = 0x80000000, 0x7, 3
    handle = create_file(path, generic_read, share_all, None, open_existing, 0, None)
    if handle == wintypes.HANDLE(-1).value:
        raise FileNotFoundError(path)
    fd = msvcrt.open_osfhandle(handle, os.O_RDONLY)  # type: ignore[attr-defined]
    return open(fd, encoding="utf-8", errors="replace")


@dataclass
class LogEntry:
    ip: str
    timestamp: float
    method: str
    uri: str
    route: str
    version: str
    status: int
    size: int
    user_agent: str
    ua_category: str
    latency_ms: float


def normalize_route(uri: str) -> str:
    """/api/users/42?x=1 -> /api/users/{id}"""
    path = uri.split("?", 1)[0]
    return ID_PATTERN.sub("/{id}", path) or "/"


def categorize_ua(ua: str) -> str:
    """Retourne Browser, Bot/Crawler, CLI/Script ou Suspicious."""
    if not ua or ua == "-" or SUSPICIOUS_UA.search(ua):
        return "Suspicious"
    if BOT_UA.search(ua):
        return "Bot/Crawler"
    if CLI_UA.search(ua):
        return "CLI/Script"
    if ua.startswith("Mozilla/"):
        return "Browser"
    return "Suspicious"


def parse_line(line: str) -> LogEntry | None:
    """Parse une ligne. Retourne None si la ligne est invalide."""
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    try:
        ts = datetime.strptime(match["time"], TIME_FORMAT).timestamp()
        size = 0 if match["size"] == "-" else int(match["size"])
        return LogEntry(
            ip=match["ip"],
            timestamp=ts,
            method=match["method"],
            uri=match["uri"],
            route=normalize_route(match["uri"]),
            version=match["version"],
            status=int(match["status"]),
            size=size,
            user_agent=match["ua"],
            ua_category=categorize_ua(match["ua"]),
            latency_ms=float(match["rt"]) * 1000,
        )
    except ValueError:
        return None


class LogTailer:
    """Équivalent de tail -F : lecture non bloquante + gestion de la rotation."""

    def __init__(self, path: str, from_start: bool = False) -> None:
        self.path = path
        self.from_start = from_start
        self._file: IO[str] | None = None
        self._inode: int | None = None
        self._buffer = ""

    def _open(self, seek_end: bool) -> None:
        try:
            self._file = open_shared(self.path)
        except FileNotFoundError:
            self._file = None
            return
        self._inode = os.fstat(self._file.fileno()).st_ino
        if seek_end:
            self._file.seek(0, os.SEEK_END)
        logger.info("Fichier ouvert : %s (inode %s)", self.path, self._inode)

    def _rotated(self) -> bool:
        """Vrai si le fichier a changé d'inode ou a été tronqué."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return False  # fichier en cours de recréation : on attend
        if self._file is None:
            return True
        return st.st_ino != self._inode or st.st_size < self._file.tell()

    def poll(self) -> Iterator[str]:
        """Retourne les lignes complètes disponibles sans bloquer."""
        if self._file is None:
            self._open(seek_end=not self.from_start)
            if self._file is None:
                return
        for line in self._file:
            self._buffer += line
            if self._buffer.endswith("\n"):
                yield self._buffer.rstrip("\n")
                self._buffer = ""
        if self._rotated():
            logger.warning("Rotation détectée sur %s, réouverture", self.path)
            # on lit d'abord la fin de l'ancien fichier pour ne rien perdre
            for line in self._file:
                self._buffer += line
            if self._buffer:
                yield self._buffer.rstrip("\n")
                self._buffer = ""
            self.close()
            self._open(seek_end=False)

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
