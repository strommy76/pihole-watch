"""
--------------------------------------------------------------------------------
FILE:        findings.py
PATH:        ~/projects/pihole-watch/pihole_watch/findings.py
DESCRIPTION: SQLite findings store. Schema init, DAO functions for findings,
             baselines, run_log, pihole_snapshots, and finding triage.

CHANGELOG:
2026-04-25            Claude      [Feature] Initial implementation.
2026-04-25            Claude      [Feature] Add pihole_snapshots timeline
                                      table, triage columns on findings, and
                                      additive _apply_migrations(). Idempotent
                                      and safe on existing DBs.
2026-04-26            Claude      [Feature] Add calibration + calibration_history
                                      tables and DAO helpers for autonomous
                                      threshold calibration.
2026-04-26            Claude      [Refactor] Drop `calibration` table -- current
                                      tuning values now live in dynamic_config.json
                                      (the SSOT). calibration_history remains
                                      as the audit trail of evolution.
--------------------------------------------------------------------------------
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)


_VALID_TRIAGE_OUTCOMES: frozenset[str] = frozenset(
    {"confirmed", "false_positive", "ignored", "pending"}
)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at TEXT NOT NULL,
    finding_type TEXT NOT NULL CHECK(finding_type IN ('dga','nxdomain_spike','volume_anomaly','beacon')),
    severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high')),
    client_ip TEXT NOT NULL,
    domain TEXT,
    score REAL,
    details TEXT,
    sample_queries TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_detected ON findings(detected_at);
CREATE INDEX IF NOT EXISTS idx_findings_type_client ON findings(finding_type, client_ip);

CREATE TABLE IF NOT EXISTS baselines (
    client_ip TEXT PRIMARY KEY,
    qps_ewma REAL NOT NULL,
    nxdomain_rate_ewma REAL NOT NULL,
    last_updated TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS run_log (
    run_at TEXT PRIMARY KEY,
    queries_seen INTEGER NOT NULL,
    findings_emitted INTEGER NOT NULL,
    elapsed_ms INTEGER NOT NULL,
    error TEXT
);

CREATE TABLE IF NOT EXISTS pihole_snapshots (
    snapshot_at TEXT PRIMARY KEY,
    total_queries INTEGER NOT NULL,
    blocked_queries INTEGER NOT NULL,
    cached_queries INTEGER NOT NULL,
    forwarded_queries INTEGER NOT NULL,
    block_rate_pct REAL NOT NULL,
    cache_hit_rate_pct REAL NOT NULL,
    active_clients INTEGER NOT NULL,
    unique_domains INTEGER NOT NULL,
    gravity_domains INTEGER NOT NULL,
    top_blocked_domain TEXT,
    top_querying_client TEXT
);
CREATE INDEX IF NOT EXISTS idx_snapshots_at ON pihole_snapshots(snapshot_at);

CREATE TABLE IF NOT EXISTS calibration_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    calibrated_at TEXT NOT NULL,
    parameter TEXT NOT NULL,
    old_value REAL,
    new_value REAL NOT NULL,
    method TEXT NOT NULL,
    metrics_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_calibration_history_param
    ON calibration_history(parameter, calibrated_at);
"""


def connect(db_path: str) -> sqlite3.Connection:
    """Open a WAL-mode connection with row factory and schema applied."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    init_schema(conn)
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Apply the schema (idempotent) plus additive migrations."""
    conn.executescript(_SCHEMA)
    _apply_migrations(conn)
    conn.commit()


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r["name"] for r in rows}


def _apply_migrations(conn: sqlite3.Connection) -> None:
    """Additive-only migrations. Existing rows are preserved.

    Each migration checks whether its target column/table already exists
    before applying. SQLite ALTER cannot easily add CHECK constraints, so
    enforcement of `triage_outcome` values lives in DAO functions, not the
    DB layer.
    """
    # Migration: add triage columns to `findings`.
    findings_cols = _table_columns(conn, "findings")
    if "triaged_at" not in findings_cols:
        conn.execute("ALTER TABLE findings ADD COLUMN triaged_at TEXT")
    if "triage_outcome" not in findings_cols:
        conn.execute(
            "ALTER TABLE findings ADD COLUMN triage_outcome TEXT DEFAULT 'pending'"
        )
        # Backfill any pre-existing rows that the DEFAULT didn't touch
        # (SQLite applies DEFAULT only to columns added via ALTER for
        # subsequent inserts; existing rows get NULL unless we update).
        conn.execute(
            "UPDATE findings SET triage_outcome='pending' WHERE triage_outcome IS NULL"
        )
    if "triage_note" not in findings_cols:
        conn.execute("ALTER TABLE findings ADD COLUMN triage_note TEXT")

    # Migration: drop legacy `calibration` table. Its rows were the
    # current-values store; that role moved to dynamic_config.json.
    # calibration_history is unchanged.
    has_calibration = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='calibration'"
    ).fetchone()
    if has_calibration is not None:
        conn.execute("DROP TABLE calibration")


# -- findings ----------------------------------------------------------------


def record_finding(
    conn: sqlite3.Connection,
    *,
    finding_type: str,
    severity: str,
    client_ip: str,
    domain: str | None = None,
    score: float | None = None,
    details: dict[str, Any] | None = None,
    sample_queries: list[int] | None = None,
    detected_at: str | None = None,
) -> int:
    """Insert a finding. Returns its row id. Default triage_outcome='pending'."""
    if detected_at is None:
        detected_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cur = conn.execute(
        """INSERT INTO findings
           (detected_at, finding_type, severity, client_ip, domain, score,
            details, sample_queries, triage_outcome)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')""",
        (
            detected_at,
            finding_type,
            severity,
            client_ip,
            domain,
            score,
            json.dumps(details) if details is not None else None,
            json.dumps(sample_queries) if sample_queries is not None else None,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def list_findings_since(
    conn: sqlite3.Connection, since_iso: str
) -> list[sqlite3.Row]:
    """Return findings with detected_at >= since_iso, newest first."""
    return list(
        conn.execute(
            "SELECT * FROM findings WHERE detected_at >= ? "
            "ORDER BY detected_at DESC, id DESC",
            (since_iso,),
        )
    )


# -- triage ------------------------------------------------------------------


def triage_finding(
    conn: sqlite3.Connection,
    finding_id: int,
    outcome: str,
    note: str | None = None,
) -> dict[str, Any]:
    """Mark a finding with a triage outcome. Returns the updated row as dict.

    Raises:
        ValueError: outcome not in the valid set or finding_id not found.
    """
    if outcome not in _VALID_TRIAGE_OUTCOMES:
        raise ValueError(
            f"triage outcome {outcome!r} not in {sorted(_VALID_TRIAGE_OUTCOMES)}"
        )
    triaged_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cur = conn.execute(
        """UPDATE findings
           SET triaged_at = ?, triage_outcome = ?, triage_note = ?
           WHERE id = ?""",
        (triaged_at, outcome, note, int(finding_id)),
    )
    if cur.rowcount == 0:
        raise ValueError(f"finding id {finding_id} not found")
    conn.commit()
    row = conn.execute(
        "SELECT * FROM findings WHERE id = ?", (int(finding_id),)
    ).fetchone()
    return dict(row) if row is not None else {}


def findings_by_outcome(
    conn: sqlite3.Connection,
    outcome: str | None = None,
    since_iso: str | None = None,
) -> list[dict[str, Any]]:
    """Filter findings by triage outcome and optional since cutoff."""
    where: list[str] = []
    params: list[Any] = []
    if outcome is not None:
        if outcome not in _VALID_TRIAGE_OUTCOMES:
            raise ValueError(
                f"outcome {outcome!r} not in {sorted(_VALID_TRIAGE_OUTCOMES)}"
            )
        where.append("triage_outcome = ?")
        params.append(outcome)
    if since_iso is not None:
        where.append("detected_at >= ?")
        params.append(since_iso)
    sql = "SELECT * FROM findings"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY detected_at DESC, id DESC"
    return [dict(r) for r in conn.execute(sql, params)]


def triage_summary(
    conn: sqlite3.Connection, since_iso: str | None = None
) -> dict[str, dict[str, int]]:
    """Per-detector counts grouped by triage outcome.

    Returns a dict like
        {'dga': {'confirmed': 6, 'false_positive': 24, 'ignored': 5,
                 'pending': 7}, ...}

    Detectors with zero findings are omitted.
    """
    sql = (
        "SELECT finding_type, COALESCE(triage_outcome, 'pending') AS outcome, "
        "COUNT(*) AS n FROM findings"
    )
    params: list[Any] = []
    if since_iso is not None:
        sql += " WHERE detected_at >= ?"
        params.append(since_iso)
    sql += " GROUP BY finding_type, outcome"
    out: dict[str, dict[str, int]] = {}
    for row in conn.execute(sql, params):
        ftype = row["finding_type"]
        outcome = row["outcome"]
        bucket = out.setdefault(
            ftype,
            {"confirmed": 0, "false_positive": 0, "ignored": 0, "pending": 0},
        )
        if outcome in bucket:
            bucket[outcome] = int(row["n"])
        else:
            # Unknown outcome (e.g., manual DB mutation) — keep as pending.
            bucket["pending"] += int(row["n"])
    return out


# -- baselines ---------------------------------------------------------------


def get_baseline(
    conn: sqlite3.Connection, client_ip: str
) -> dict[str, Any] | None:
    """Fetch the EWMA baseline row for ``client_ip`` or None."""
    row = conn.execute(
        "SELECT client_ip, qps_ewma, nxdomain_rate_ewma, last_updated, sample_count "
        "FROM baselines WHERE client_ip = ?",
        (client_ip,),
    ).fetchone()
    if row is None:
        return None
    return {
        "client_ip": row["client_ip"],
        "qps_ewma": float(row["qps_ewma"]),
        "nxdomain_rate_ewma": float(row["nxdomain_rate_ewma"]),
        "last_updated": row["last_updated"],
        "sample_count": int(row["sample_count"]),
    }


def all_baseline_qps(conn: sqlite3.Connection) -> dict[str, float]:
    """Return {client_ip: qps_ewma} for all baselines."""
    return {
        row["client_ip"]: float(row["qps_ewma"])
        for row in conn.execute(
            "SELECT client_ip, qps_ewma FROM baselines"
        )
    }


def set_baseline(
    conn: sqlite3.Connection,
    *,
    client_ip: str,
    qps_ewma: float,
    nxdomain_rate_ewma: float,
    last_updated: str,
    sample_count: int,
) -> None:
    """Upsert a baseline row."""
    conn.execute(
        """INSERT INTO baselines
           (client_ip, qps_ewma, nxdomain_rate_ewma, last_updated, sample_count)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(client_ip) DO UPDATE SET
             qps_ewma = excluded.qps_ewma,
             nxdomain_rate_ewma = excluded.nxdomain_rate_ewma,
             last_updated = excluded.last_updated,
             sample_count = excluded.sample_count""",
        (
            client_ip, float(qps_ewma), float(nxdomain_rate_ewma),
            last_updated, int(sample_count),
        ),
    )
    conn.commit()


# -- run_log -----------------------------------------------------------------


def record_run(
    conn: sqlite3.Connection,
    *,
    run_at: str,
    queries_seen: int,
    findings_emitted: int,
    elapsed_ms: int,
    error: str | None = None,
) -> None:
    """Insert a row into run_log. Idempotent on duplicate run_at via OR REPLACE."""
    conn.execute(
        """INSERT OR REPLACE INTO run_log
           (run_at, queries_seen, findings_emitted, elapsed_ms, error)
           VALUES (?, ?, ?, ?, ?)""",
        (run_at, int(queries_seen), int(findings_emitted), int(elapsed_ms), error),
    )
    conn.commit()


def last_successful_run(conn: sqlite3.Connection) -> str | None:
    """Return the most recent run_at where error IS NULL, or None."""
    row = conn.execute(
        "SELECT run_at FROM run_log WHERE error IS NULL "
        "ORDER BY run_at DESC LIMIT 1"
    ).fetchone()
    return row["run_at"] if row else None


# -- pihole_snapshots --------------------------------------------------------


_SNAPSHOT_COLS: tuple[str, ...] = (
    "snapshot_at",
    "total_queries",
    "blocked_queries",
    "cached_queries",
    "forwarded_queries",
    "block_rate_pct",
    "cache_hit_rate_pct",
    "active_clients",
    "unique_domains",
    "gravity_domains",
    "top_blocked_domain",
    "top_querying_client",
)


def record_snapshot(
    conn: sqlite3.Connection, snapshot: dict[str, Any]
) -> None:
    """Insert a Pi-hole timeline snapshot. Idempotent on duplicate
    snapshot_at via OR REPLACE.

    Caller supplies ``snapshot`` matching the ``pihole_snapshots`` schema.
    Missing keys raise KeyError so we fail loud on malformed input.
    """
    values = tuple(snapshot[c] for c in _SNAPSHOT_COLS)
    placeholders = ",".join("?" for _ in _SNAPSHOT_COLS)
    cols_csv = ",".join(_SNAPSHOT_COLS)
    conn.execute(
        f"INSERT OR REPLACE INTO pihole_snapshots ({cols_csv}) "
        f"VALUES ({placeholders})",
        values,
    )
    conn.commit()


def latest_snapshot(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """Return most recent snapshot row as dict or None."""
    row = conn.execute(
        "SELECT * FROM pihole_snapshots ORDER BY snapshot_at DESC LIMIT 1"
    ).fetchone()
    return dict(row) if row is not None else None


def snapshots_since(
    conn: sqlite3.Connection, since_iso: str
) -> list[dict[str, Any]]:
    """Return all snapshots with snapshot_at >= since_iso, oldest first."""
    return [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM pihole_snapshots WHERE snapshot_at >= ? "
            "ORDER BY snapshot_at ASC",
            (since_iso,),
        )
    ]


# -- calibration history -----------------------------------------------------


def record_calibration_event(
    conn: sqlite3.Connection,
    parameter: str,
    new_value: float,
    method: str,
    *,
    old_value: float | None = None,
    metrics: dict[str, Any] | None = None,
    calibrated_at: str | None = None,
) -> int:
    """Append a single calibration audit row.

    Current-values store is dynamic_config.json (out-of-band of this DB);
    this table records what changed and when so we can graph evolution.
    Returns the inserted row id.
    """
    if calibrated_at is None:
        calibrated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    metrics_json = json.dumps(metrics) if metrics is not None else None
    cur = conn.execute(
        """INSERT INTO calibration_history
           (calibrated_at, parameter, old_value, new_value, method, metrics_json)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            calibrated_at, parameter,
            float(old_value) if old_value is not None else None,
            float(new_value), method, metrics_json,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def calibration_history(
    conn: sqlite3.Connection,
    parameter: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Return calibration_history rows newest first.

    Args:
        parameter: optional filter to one parameter.
        limit: max rows to return.
    """
    sql = "SELECT * FROM calibration_history"
    params: list[Any] = []
    if parameter is not None:
        sql += " WHERE parameter = ?"
        params.append(parameter)
    sql += " ORDER BY calibrated_at DESC, id DESC LIMIT ?"
    params.append(int(limit))
    out: list[dict[str, Any]] = []
    for row in conn.execute(sql, params):
        metrics = (
            json.loads(row["metrics_json"])
            if row["metrics_json"] is not None
            else None
        )
        out.append({
            "id": int(row["id"]),
            "calibrated_at": row["calibrated_at"],
            "parameter": row["parameter"],
            "old_value": (
                float(row["old_value"]) if row["old_value"] is not None else None
            ),
            "new_value": float(row["new_value"]),
            "method": row["method"],
            "metrics": metrics,
        })
    return out


__all__ = [
    "connect",
    "init_schema",
    "record_finding",
    "list_findings_since",
    "triage_finding",
    "findings_by_outcome",
    "triage_summary",
    "get_baseline",
    "all_baseline_qps",
    "set_baseline",
    "record_run",
    "last_successful_run",
    "record_snapshot",
    "latest_snapshot",
    "snapshots_since",
    "record_calibration_event",
    "calibration_history",
]
