"""Point d'entrée : boucle principale et arrêt propre (SIGINT/SIGTERM)."""

from __future__ import annotations

import argparse
import logging
import signal
import time
from types import FrameType

from logsentinel.analyzer import Aggregator, RuleEngine
from logsentinel.collector import LogTailer, parse_line
from logsentinel.config import ConfigError, load_config, setup_logging
from logsentinel.database import Database

logger = logging.getLogger("logsentinel")


class App:
    """Application LogSentinel : relie collecteur, analyseur et base."""

    def __init__(self, config_path: str) -> None:
        """Charge la configuration.

        Args:
            config_path: Chemin de config.yaml.

        Raises:
            ConfigError: Si la configuration est invalide.
        """
        self.cfg = load_config(config_path)
        self.running = True

    def stop(self, signum: int, _frame: FrameType | None) -> None:
        """Gestionnaire SIGINT/SIGTERM : demande l'arrêt de la boucle principale.

        Args:
            signum: Numéro du signal reçu.
            _frame: Frame courante (non utilisée).
        """
        logger.info("Signal %s reçu, arrêt en cours...", signal.Signals(signum).name)
        self.running = False

    def run(self) -> None:
        """Boucle principale : lecture, analyse, agrégation, stockage et purge."""
        cfg = self.cfg
        window = int(cfg["aggregation"]["window_s"])
        tailer = LogTailer(cfg["log_file"], bool(cfg.get("read_from_start", False)))
        aggregator = Aggregator(window)
        rules = RuleEngine(cfg["rules"])
        poll = float(cfg.get("poll_interval_s", 0.5))
        db_cfg = cfg["database"]
        next_flush = time.time() + window
        next_purge = 0.0
        invalid = 0

        with Database(db_cfg["path"]) as db:
            try:
                while self.running:
                    got_line = False
                    for line in tailer.poll():
                        got_line = True
                        entry = parse_line(line)
                        if entry is None:
                            invalid += 1
                            logger.debug("Ligne ignorée : %s", line[:120])
                            continue
                        aggregator.add(entry)
                        events = rules.process(entry)
                        if events:
                            db.insert_events([ev.as_row() for ev in events])
                    now = time.time()
                    if now >= next_flush:
                        self._flush(db, aggregator, now)
                        next_flush = now + window
                    if now >= next_purge:
                        db.purge(int(db_cfg["retention_days"]), now)
                        next_purge = now + float(db_cfg["purge_interval_s"])
                    if not got_line:
                        time.sleep(poll)
            except Exception:
                logger.exception("Erreur inattendue dans la boucle principale")
                raise
            finally:
                self._flush(db, aggregator, time.time())
                tailer.close()
                logger.info("Arrêt propre terminé (%d lignes invalides)", invalid)

    @staticmethod
    def _flush(db: Database, aggregator: Aggregator, now: float) -> None:
        """Enregistre les métriques de la fenêtre écoulée.

        Args:
            db: Base ouverte.
            aggregator: Agrégateur de la fenêtre.
            now: Horodatage de fin de fenêtre.
        """
        result = aggregator.flush(now)
        db.insert_traffic(result["traffic"])
        db.insert_endpoints(result["endpoints"])
        db.insert_clients(result["clients"])
        db.commit()
        t = result["traffic"]
        logger.info(
            "Fenêtre : %d req, %.1f rps, p95=%.0f ms, 5xx=%d",
            t["total_requests"],
            t["rps"],
            t["latency_p95_ms"],
            t["count_5xx"],
        )


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée en ligne de commande.

    Args:
        argv: Arguments (par défaut ceux de la ligne de commande).

    Returns:
        Code de sortie : 0 si tout va bien, 1 si la configuration est invalide.
    """
    parser = argparse.ArgumentParser(description="LogSentinel - SIEM léger")
    parser.add_argument("-c", "--config", default="config.yaml")
    args = parser.parse_args(argv)
    try:
        app = App(args.config)
    except ConfigError as exc:
        logging.basicConfig()
        logging.error("%s", exc)
        return 1
    setup_logging(app.cfg["logging"])
    signal.signal(signal.SIGINT, app.stop)
    signal.signal(signal.SIGTERM, app.stop)
    logger.info("LogSentinel démarré, surveillance de %s", app.cfg["log_file"])
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
