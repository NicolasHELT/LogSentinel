# LogSentinel

SIEM léger : lit un fichier `access.log` en temps réel, calcule des métriques de trafic,
détecte des attaques, stocke tout dans SQLite et l'affiche dans Grafana.

## Architecture

```
traffic_generator.py      Module A : génère des logs (normal + attaques)
config.yaml               Toute la configuration (seuils, chemins, logging)
logsentinel/
  config.py               Lecture de config.yaml + logging (console + app.log rotatif)
  collector.py            Module B : tail -F (rotation inode/troncature), regex, User-Agent, routes
  analyzer.py             Module C : agrégation 5 s (RPS, octets, 2xx..5xx, p50/p95/p99) + règles SIEM
  database.py             SQLite : WAL, index, requêtes paramétrées, purge > 7 jours
  main.py                 Boucle principale, arrêt propre SIGINT/SIGTERM
tests/                    Tests unitaires pytest
grafana/dashboard.json    Dashboard Grafana à importer
```

Flux : `access.log` → `collector` → `analyzer` → `database (SQLite WAL)` → Grafana.

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
source venv/bin/activate          # Windows : venv\Scripts\activate
pip install -r requirements.txt
```

## Lancement (2 terminaux)

Terminal 1, le collecteur :
```bash
python -m logsentinel             # ou : python -m logsentinel -c config.yaml
```

Terminal 2, le générateur :
```bash
python traffic_generator.py                         # trafic normal
python traffic_generator.py --attack bruteforce     # + brute-force pendant 30 s
python traffic_generator.py --attack scan
python traffic_generator.py --attack error_spike
python traffic_generator.py --attack flood
```
Options : `--rate 20` (req/s), `--attack-duration 30`, `--duration 0` (0 = infini), `--file access.log`.

Arrêt : `Ctrl+C` (le collecteur enregistre la dernière fenêtre et ferme SQLite proprement).

Tester la rotation pendant que tout tourne :
```bash
mv access.log access.log.1        # Windows : ren access.log access.log.1
```
Le log `app.log` affiche `Rotation détectée`.

## Grafana

1. Installer le plugin : `grafana.exe cli plugins install frser-sqlite-datasource` (PowerShell admin, dans `C:\Program Files\GrafanaLabs\grafana\bin` ; `grafana-cli.exe` n'existe plus depuis Grafana 10), puis redémarrer Grafana.
2. Ouvrir http://localhost:3000 (admin / admin).
3. *Connections > Data sources > Add* : **SQLite**. Path = chemin **absolu** de `logsentinel.db`. *Save & test*.
4. *Dashboards > New > Import* : charger `grafana/dashboard.json`, choisir la source SQLite.

Contenu du dashboard (rafraîchissement 5 s, variables `$method` et `$severity`) :
1. RPS empilé par code HTTP (2xx vert, 3xx bleu, 4xx orange, 5xx rouge)
2. Latence p50 / p95 / p99 (seuil visuel à 1000 ms)
3. Top 10 endpoints les plus sollicités / les plus lents (filtre `$method`)
4. Donut des types de clients
5. Journal des événements de sécurité + compteur d'alertes coloré (filtre `$severity`)

Après modification dans Grafana : *Share > Export > Save to file* pour mettre à jour `dashboard.json`.

## Qualité

```bash
ruff check .        # PEP 8
pytest -q           # tests unitaires
```

## Notes techniques Grafana

- Filtre temporel : `${__from:date:seconds}` / `${__to:date:seconds}` (macros `$__unixEpochFrom()` non reconnues par le plugin).
- Variables `$method` et `$severity` de type *Custom* : les variables *Query* restaient vides avec le plugin SQLite.
