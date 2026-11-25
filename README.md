# LogSentinel

SIEM léger : lit un fichier `access.log` en temps réel, calcule des métriques de trafic,
détecte des attaques, stocke tout dans SQLite et l'affiche dans Grafana.

## Architecture

```
src/
  traffic_generator.py    Module A : génère des logs (normal + attaques)
  logsentinel/
    config.py             Lecture de config.yaml + logging (console + app.log rotatif)
    collector.py          Module B : tail -F (rotation inode/troncature), regex, User-Agent, routes
    analyzer.py           Module C : agrégation 5 s (RPS, octets, 2xx..5xx, p50/p95/p99) + règles SIEM
    database.py           SQLite : WAL, index, requêtes paramétrées, purge > 7 jours
    main.py               Boucle principale, arrêt propre SIGINT/SIGTERM
config.yaml               Toute la configuration (seuils, chemins, logging)
tests/                    Tests unitaires pytest (parsing, métriques, règles, CRUD SQLite :memory:)
grafana/dashboard.json    Dashboard Grafana à importer
docs/screenshots/         Captures du dashboard en charge
```

### Schéma des flux

```
traffic_generator.py ──écrit──▶ access.log
                                    │  tail -F (détection rotation)
                                    ▼
                           collector.py  (regex compilée, User-Agent, route normalisée)
                                    │  LogEntry
                     ┌──────────────┴──────────────┐
                     ▼                             ▼
          analyzer.Aggregator              analyzer.RuleEngine
          (fenêtre 5 s, percentiles)       (fenêtres glissantes deque)
                     │                             │ SecurityEvent
                     └──────────────┬──────────────┘
                                    ▼
                       database.py ──▶ logsentinel.db (SQLite WAL)
                                    │  lecture simultanée
                                    ▼
                    Grafana (plugin frser-sqlite-datasource)
```

### Modèle relationnel SQLite

Tables indépendantes (pas de clé étrangère) : chaque ligne est une mesure horodatée.

```
traffic_metrics            endpoint_stats             client_stats          security_events
---------------            --------------             ------------          ---------------
id            PK           id               PK        id          PK        id           PK
timestamp     INDEX        timestamp        INDEX     timestamp   INDEX     timestamp    INDEX
window_seconds             method           INDEX     ua_category           rule_name
total_requests             normalized_route           hit_count             severity     INDEX
rps                        hit_count                                        source_ip
bytes_sent                 avg_latency_ms                                   details
count_2xx..count_5xx       error_count                                      event_count
latency_p50/p95/p99_ms
```

## Règles de détection

| Règle | Condition | Sévérité |
|---|---|---|
| `bruteforce` | > 15 POST sur `/login` ou `/api/auth` depuis une IP en 30 s | high |
| `scan_404` | > 20 réponses 404 depuis une IP en 60 s | medium |
| `sensitive_path` | accès à `/.env`, `/wp-admin`, `/etc/passwd`, `/.git` | high |
| `error_spike` | > 5 % de réponses 5xx sur la dernière minute | critical |

Les fenêtres glissantes utilisent `collections.deque`. Les seuils se modifient dans `config.yaml`.

## Base SQLite

- `traffic_metrics` : métriques par fenêtre de 5 s (`window_seconds` ajouté pour calculer le RPS par code)
- `endpoint_stats` : hits, latence moyenne, erreurs par méthode + route normalisée
- `client_stats` : nombre de requêtes par type de client (pour le donut)
- `security_events` : alertes horodatées

Mode WAL activé, index sur `timestamp` (+ `method`, `severity`), purge automatique toutes les heures.

## Installation

Prérequis : Python 3.10+, Grafana.

```bash
python -m venv venv
venv\Scripts\activate            # Linux : source venv/bin/activate
pip install -r requirements.txt
pip install -e .                  # rend le package src/logsentinel lançable
```

## Lancement (2 terminaux)

Terminal 1, le collecteur :
```bash
python -m logsentinel             # ou : python -m logsentinel -c config.yaml
```

Terminal 2, le générateur :
```bash
python src/traffic_generator.py                         # trafic normal
python src/traffic_generator.py --attack bruteforce     # + brute-force pendant 30 s
python src/traffic_generator.py --attack scan
python src/traffic_generator.py --attack error_spike
python src/traffic_generator.py --attack flood
```
Options : `--rate 20` (req/s), `--attack-duration 30`, `--duration 0` (0 = infini), `--file access.log`.

Arrêt : `Ctrl+C` (le collecteur enregistre la dernière fenêtre et ferme SQLite proprement).

Tester la rotation pendant que tout tourne :
```bash
mv access.log access.log.1        # Windows : ren access.log access.log.1
```
Le log `app.log` affiche `Rotation détectée`.

## Grafana

1. Installer le plugin (PowerShell administrateur), puis redémarrer Grafana :
   ```powershell
   & "C:\Program Files\GrafanaLabs\grafana\bin\grafana.exe" cli plugins install frser-sqlite-datasource
   Restart-Service Grafana
   ```
   Depuis Grafana 10, `grafana-cli.exe` n'existe plus. Si le réseau bloque, télécharger le zip du plugin
   et le décompresser dans `C:\Program Files\GrafanaLabs\grafana\data\plugins\`.
2. Ouvrir http://localhost:3000 (admin / admin).
3. *Connections > Data sources > Add* : **SQLite**. Path = chemin **absolu** de `logsentinel.db`. *Save & test*.
4. *Dashboards > New > Import* : charger `grafana/dashboard.json`, choisir la source SQLite.

Contenu du dashboard (rafraîchissement 5 s, variables `$method` et `$severity` de type *Custom*) :
1. RPS empilé par code HTTP (2xx vert, 3xx bleu, 4xx orange, 5xx rouge)
2. Latence p50 / p95 / p99 (seuil visuel à 1000 ms)
3. Top 10 endpoints les plus sollicités / les plus lents (filtre `$method`)
4. Donut des types de clients
5. Journal des événements de sécurité + compteur d'alertes coloré (filtre `$severity`)

Après modification dans Grafana : *Share > Export > Save to file* pour mettre à jour `dashboard.json`.

## Captures d'écran

Voir `docs/screenshots/` : dashboard en charge pendant les attaques bruteforce, scan et error_spike.

## Choix techniques

| Choix | Justification |
|---|---|
| `sqlite3` natif + requêtes `?` | Aucune dépendance, protection contre l'injection SQL |
| Mode WAL | Python écrit pendant que Grafana lit, sans `database is locked` |
| Index sur `timestamp` | Toutes les requêtes Grafana filtrent sur la période affichée |
| `collections.deque` | Fenêtre glissante en O(1) : ajout à droite, expiration à gauche |
| Détection de rotation par inode + taille | Couvre `mv` (nouvel inode) et `truncate` (taille réduite) |
| Ouverture Windows avec `FILE_SHARE_DELETE` | Permet de renommer `access.log` pendant la lecture |
| Agrégation par fenêtre de 5 s | Volume de données limité, précision suffisante pour Grafana |
| Percentile par rang le plus proche | Simple, exact sur les valeurs observées |
| Configuration YAML | Seuils et chemins modifiables sans toucher au code |

## Limites identifiées

- Un seul fichier de logs suivi à la fois.
- Fenêtres de détection en mémoire : perdues au redémarrage.
- Les alertes `scan_404` et `bruteforce` se répètent tant que l'attaque dure (pas de regroupement).
- Percentiles calculés par fenêtre de 5 s : pas de percentile exact sur une longue période.
- Variables Grafana `$method` / `$severity` en valeurs fixes (*Custom*).
- Pas d'authentification ni de chiffrement : outil prévu pour un usage local.

## Qualité

```bash
ruff check .        # PEP 8
pytest -q           # tests unitaires
```

## Notes techniques Grafana

- Filtre temporel : `${__from:date:seconds}` / `${__to:date:seconds}` (les macros `$__unixEpochFrom()` ne sont pas reconnues par toutes les versions du plugin).
- Variables `$method` et `$severity` en valeurs fixes (*Custom*) : les variables de type *Query* restaient vides avec le plugin SQLite.
