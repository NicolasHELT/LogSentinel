"""Chargement de la configuration YAML et mise en place du logging."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    """Configuration absente ou invalide."""


def load_config(path: str | Path) -> dict[str, Any]:
    """Lit le fichier YAML et retourne un dictionnaire."""
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError as exc:
        raise ConfigError(f"Fichier de configuration introuvable : {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML invalide : {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("La configuration doit être un dictionnaire YAML")
    for key in ("log_file", "database", "aggregation", "rules", "logging"):
        if key not in data:
            raise ConfigError(f"Clé manquante dans la configuration : {key}")
    return data


def setup_logging(cfg: dict[str, Any]) -> None:
    """Logging vers la console et vers un fichier rotatif."""
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(cfg.get("level", "INFO"))
    root.handlers.clear()
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    file_handler = RotatingFileHandler(
        cfg.get("file", "app.log"),
        maxBytes=int(cfg.get("max_bytes", 1_048_576)),
        backupCount=int(cfg.get("backup_count", 3)),
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    root.addHandler(console)
    root.addHandler(file_handler)
