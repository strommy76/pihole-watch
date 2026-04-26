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
