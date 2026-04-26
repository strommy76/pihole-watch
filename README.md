# pihole-watch

Read-only AI/ML threat-detection sidecar for Pi-hole. Pulls the Pi-hole
query log via the HTTP API, runs four lightweight analyses, and writes
findings to its own SQLite database. Runs every 5 minutes via systemd.

The point is to demonstrate value with proven, simple techniques rather
than chase state-of-the-art ML. There are no model files to maintain.

## Architecture

- Read-only consumer of Pi-hole. Never modifies Pi-hole itself.
- Sidecar pattern matching the other services on this Pi (`stocks/`,
  `enviroplus/`).
- Fail-loud: missing config, API errors, and DB errors all surface, never
  silently swallowed.
- Own state lives in `findings.db` (separate from Pi-hole's storage).

## Modules

| Module | Purpose |
| --- | --- |
| `pihole_watch.config` | Loads `.env` via `shared.config_service`. Frozen `WatchConfig`. |
| `pihole_watch.api` | HTTP client. `authenticate()`, `fetch_queries(...)`, `get_summary()`. |
| `pihole_watch.dga` | Heuristic DGA score from entropy / length / vowel-ratio / consonant-runs / digits. |
| `pihole_watch.anomaly` | NXDOMAIN-rate per client; QPS anomaly vs EWMA baseline; baseline updates. |
| `pihole_watch.beacon` | Periodic-query / C2 beacon detection via inter-arrival CV. |
| `pihole_watch.findings` | SQLite store: `findings`, `baselines`, `run_log`. |
| `pihole_watch.main` | systemd-oneshot entry point; orchestrates the four analyses. |

## Finding types

- `dga` — domain looks algorithmically generated (random-looking label).
  `score` = the 0-1 DGA score; default flag threshold 0.65.
- `nxdomain_spike` — a client is hitting NXDOMAIN at an elevated rate
  (default 30%+ over a 6-min window with at least 20 queries). Classic
  malware C2 / DGA signature.
- `volume_anomaly` — a client's QPS is far from its rolling EWMA baseline.
  `score` = pseudo-sigma deviation `(observed - baseline) / sqrt(baseline+1)`.
- `beacon` — same `(client, domain)` queried regularly enough that the
  inter-arrival times have very low coefficient of variation. Default:
  >= 6 occurrences over 60 minutes with CV < 0.15.

## Severity

- `info` — informational, below action threshold (e.g., NX rate over a
  small sample).
- `low` / `medium` / `high` — escalating concern. Severity rules live in
  `main.py` and use score and sample-count cutoffs.

## Install

```bash
cd /home/pistrommy/projects/pihole-watch
cp .env.example .env
# edit .env: set PIHOLE_PASSWORD
```

Required venv: `/home/pistrommy/.virtualenvs/pimoroni/bin/python` with
`requests` and `python-dotenv`.

Manual run:

```bash
PYTHONPATH=/home/pistrommy/projects \
  /home/pistrommy/.virtualenvs/pimoroni/bin/python -m pihole_watch.main
```

Deploy as a systemd timer (not auto-installed):

```bash
sudo cp pihole-watch.service /etc/systemd/system/
sudo cp pihole-watch.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pihole-watch.timer
```

## Tests

```bash
cd /home/pistrommy/projects/pihole-watch
PYTHONPATH=/home/pistrommy/projects \
  /home/pistrommy/.virtualenvs/pimoroni/bin/python -m pytest tests/ -q
```

## Reading findings.db

```bash
sqlite3 findings.db 'SELECT detected_at, finding_type, severity, client_ip,
  domain, score FROM findings ORDER BY detected_at DESC LIMIT 50;'

sqlite3 findings.db 'SELECT * FROM run_log ORDER BY run_at DESC LIMIT 10;'

sqlite3 findings.db 'SELECT * FROM baselines ORDER BY qps_ewma DESC;'
```

Useful one-liners:

```bash
# Findings in the last hour, by type
sqlite3 findings.db "SELECT finding_type, COUNT(*) FROM findings
  WHERE detected_at > datetime('now', '-1 hour')
  GROUP BY finding_type;"

# High/medium severity only
sqlite3 findings.db "SELECT detected_at, finding_type, client_ip, domain,
  score FROM findings WHERE severity IN ('high','medium')
  ORDER BY detected_at DESC LIMIT 20;"
```

## Config keys

See `.env.example`. All key names start with `WATCH_` except for
`PIHOLE_URL`, `PIHOLE_PASSWORD`, `LOG_PATH`.

## Telemetry & Reports

In addition to anomaly findings, each run also captures a Pi-hole
**snapshot** — a row in the `pihole_snapshots` table with overall stats
(total / blocked / cached / forwarded queries, block rate, cache hit
rate, active clients, gravity domain count, top blocked domain, top
querying client). This builds a 5-minute-granular timeline of Pi-hole's
own metrics that's much easier to reason about than scraping the Pi-hole
UI charts.

Findings now have a **triage lifecycle**. Each row gets `triage_outcome`
(default `pending`) plus optional `triaged_at` and `triage_note`. Valid
outcomes:

- `confirmed` — real threat
- `false_positive` — not a threat (informs precision)
- `ignored` — known-noisy / known-benign, suppress without judging
- `pending` — not yet reviewed

The `weekly-report` CLI command emits a markdown summary covering
Pi-hole metrics drift, finding totals, triage status, per-detector
precision, and noisy clients — useful for dropping into a weekly
journal.

## CLI

```bash
PYTHONPATH=/home/pistrommy/projects \
  /home/pistrommy/.virtualenvs/pimoroni/bin/python -m pihole_watch.cli <command>
```

Commands:

| Command | Purpose |
| --- | --- |
| `list [--limit N] [--outcome O] [--type T]` | Print the latest findings, optionally filtered by triage outcome or finding type. |
| `triage FINDING_ID --outcome O [--note "..."]` | Stamp a finding with `confirmed`/`false_positive`/`ignored`/`pending`. |
| `summary [--since YYYY-MM-DD]` | Per-detector triage rollup with precision %. Also prints latest Pi-hole snapshot. |
| `weekly-report` | Markdown summary of the last 7 days. |

Examples:

```bash
# Last 20 pending DGA findings
... -m pihole_watch.cli list --type dga --outcome pending --limit 20

# Mark a finding as a false positive with a note
... -m pihole_watch.cli triage 42 --outcome false_positive --note "CDN edge name"

# Weekly markdown report
... -m pihole_watch.cli weekly-report > /tmp/pihole-watch-week.md
```

## Grafana setup

The `grafana/pihole-watch.json` dashboard visualizes everything: snapshot
timeline, findings, triage status, detector run health.

It uses `frser-sqlite-datasource` and assumes a datasource UID of
`pihole-watch-sqlite-ds` pointing at this repo's `findings.db`. To wire
it up:

1. **Datasource provisioning.** Add a new entry under your Grafana
   container's `datasources/` provisioning directory (e.g.,
   `~/grafana-data/datasources/pihole-watch.yml`):

   ```yaml
   apiVersion: 1
   datasources:
     - name: pihole-watch SQLite
       type: frser-sqlite-datasource
       uid: pihole-watch-sqlite-ds
       jsonData:
         path: /var/lib/pihole-watch/findings.db
   ```

   The path inside the container must match wherever you mount
   `findings.db`.

2. **Volume mount.** The Grafana container needs read access to
   `findings.db`. Add a mount in your `docker-compose.yml` (read-only
   is fine — Grafana never writes here):

   ```yaml
   services:
     grafana:
       volumes:
         - /home/pistrommy/projects/pihole-watch:/var/lib/pihole-watch:ro
   ```

   SQLite WAL mode also writes `findings.db-wal` / `findings.db-shm`
   alongside; mounting the whole directory is the simplest approach.

3. **Dashboard provisioning.** Drop `grafana/pihole-watch.json` into
   your dashboards provisioning directory (e.g.,
   `~/grafana-data/dashboards/pihole-watch.json`).

4. **Reload.** `docker compose restart grafana` (or just hit the Grafana
   reload-provisioning endpoint).

The dashboard refreshes every 5 minutes — same cadence as the watcher.
