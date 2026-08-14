# PROJECT-CONFIG.md — pihole-watch

Project-specific authority for the pihole-watch repository. Portable agent doctrine is loaded from the
global `AGENTS.md`; this file contains only pihole-watch facts, boundaries, and verification.

## Responsibility and Boundaries

pihole-watch is a read-only consumer of the Pi-hole API. Detection writes its own SQLite findings store
and observational JSONL log; when local-LLM triage is due, that same invocation also updates only
`_meta.last_triage_at` through the tuning document's atomic writer. Calibration owns threshold changes and
`_meta.last_calibrated_at`. Neither path may alter Pi-hole state or enter the DNS serving path. Grafana is
a read-only consumer of the sidecar's store, and the dashboard definition remains owned here.

The two runtime invocations are `python -m pihole_watch.main` for detection and
`python -m pihole_watch.cli calibrate` for calibration. The committed systemd unit and timer files are
deployment templates, not proof of the live installed unit bytes or current service state.

## Configuration and Persistence

`.env` is uncommitted host residue for secrets and infrastructure paths. The uncommitted
`dynamic_config.json` is the active tuning surface and `dynamic_config.example.json` is the committed
bootstrap shape. The current loader admits the example when the active file is absent; that existing
behavior is not permission to treat the example as evidence of the live configuration or to add another
fallback. `findings.db` is the sidecar's canonical observation store. `watch.log*` is observational and
never evidence of canonical state. These host-residue and runtime files remain uncommitted.

## Verification

The repository-local environment is derived from the committed requirement files. If `.venv` is absent,
restore it before treating the validation lane as green:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
PYTHONPATH="$(realpath ..)" .venv/bin/python -m pytest tests -q
```

Do not substitute another project's interpreter as completion evidence; that can establish source
compatibility while this project's own reproducible lane remains red.

A service-affecting change additionally runs one real invocation through the installed interface, then
verifies the systemd result, structured logs, and newly persisted rows without mutating Pi-hole.

<!-- PROJECT-CONFIG-END v1 -->
