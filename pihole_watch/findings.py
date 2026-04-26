"""
--------------------------------------------------------------------------------
FILE:        findings.py
PATH:        ~/projects/pihole-watch/pihole_watch/findings.py
DESCRIPTION: SQLite findings store. Schema init, DAO functions for findings,
             baselines, and run_log.

CHANGELOG:
2026-04-25            Claude      [Feature] Initial implementation.
--------------------------------------------------------------------------------
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)


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
    """Apply the schema (idempotent)."""
    conn.executescript(_SCHEMA)
    conn.commit()


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
    """Insert a finding. Returns its row id."""
    if detected_at is None:
        detected_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cur = conn.execute(
        """INSERT INTO findings
           (detected_at, finding_type, severity, client_ip, domain, score,
            details, sample_queries)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
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


__all__ = [
    "connect",
    "init_schema",
    "record_finding",
    "list_findings_since",
    "get_baseline",
    "all_baseline_qps",
    "set_baseline",
    "record_run",
    "last_successful_run",
]
