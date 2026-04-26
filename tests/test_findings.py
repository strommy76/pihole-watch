"""Findings DB lifecycle tests -- init, write, read, baselines, run_log,
snapshots, triage, and migration safety."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile

import pytest

from pihole_watch import findings as findings_db


@pytest.fixture
def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    conn = findings_db.connect(path)
    try:
        yield conn
    finally:
        conn.close()
        for ext in ("", "-wal", "-shm"):
            p = path + ext
            if os.path.exists(p):
                os.unlink(p)


# --- schema ----------------------------------------------------------------


def test_schema_creates_expected_tables(db) -> None:
    rows = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    names = [r["name"] for r in rows]
    assert names == [
        "baselines",
        "calibration",
        "calibration_history",
        "findings",
        "pihole_snapshots",
        "run_log",
    ]


def test_init_schema_idempotent(db) -> None:
    findings_db.init_schema(db)
    findings_db.init_schema(db)  # should not raise


# --- findings --------------------------------------------------------------


def test_record_finding_dga(db) -> None:
    fid = findings_db.record_finding(
        db,
        finding_type="dga",
        severity="medium",
        client_ip="10.0.0.1",
        domain="xnvbq3mlpoq.evil.com",
        score=0.85,
        details={"score": 0.85, "occurrences": 3},
        sample_queries=[1, 2, 3],
    )
    assert fid > 0
    row = db.execute("SELECT * FROM findings WHERE id = ?", (fid,)).fetchone()
    assert row["finding_type"] == "dga"
    assert row["severity"] == "medium"
    assert row["client_ip"] == "10.0.0.1"
    assert row["score"] == 0.85
    details = json.loads(row["details"])
    assert details["score"] == 0.85
    samples = json.loads(row["sample_queries"])
    assert samples == [1, 2, 3]


def test_record_finding_invalid_type_rejected(db) -> None:
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        findings_db.record_finding(
            db,
            finding_type="not_a_real_type",
            severity="low",
            client_ip="10.0.0.1",
        )


def test_record_finding_invalid_severity_rejected(db) -> None:
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        findings_db.record_finding(
            db,
            finding_type="dga",
            severity="catastrophic",
            client_ip="10.0.0.1",
        )


def test_list_findings_since(db) -> None:
    findings_db.record_finding(
        db, finding_type="dga", severity="low", client_ip="10.0.0.1",
        detected_at="2026-04-25T10:00:00+00:00",
    )
    findings_db.record_finding(
        db, finding_type="beacon", severity="high", client_ip="10.0.0.2",
        detected_at="2026-04-25T11:00:00+00:00",
    )
    after = findings_db.list_findings_since(db, "2026-04-25T10:30:00+00:00")
    assert len(after) == 1
    assert after[0]["finding_type"] == "beacon"


# --- baselines -------------------------------------------------------------


def test_set_and_get_baseline(db) -> None:
    findings_db.set_baseline(
        db, client_ip="10.0.0.5", qps_ewma=0.5,
        nxdomain_rate_ewma=0.05, last_updated="2026-04-25T10:00:00+00:00",
        sample_count=1,
    )
    b = findings_db.get_baseline(db, "10.0.0.5")
    assert b is not None
    assert b["qps_ewma"] == 0.5
    assert b["nxdomain_rate_ewma"] == 0.05
    assert b["sample_count"] == 1


def test_get_baseline_missing_returns_none(db) -> None:
    assert findings_db.get_baseline(db, "10.99.99.99") is None


def test_set_baseline_upsert(db) -> None:
    findings_db.set_baseline(
        db, client_ip="10.0.0.6", qps_ewma=0.5, nxdomain_rate_ewma=0.0,
        last_updated="2026-04-25T10:00:00+00:00", sample_count=1,
    )
    findings_db.set_baseline(
        db, client_ip="10.0.0.6", qps_ewma=1.5, nxdomain_rate_ewma=0.1,
        last_updated="2026-04-25T10:05:00+00:00", sample_count=2,
    )
    b = findings_db.get_baseline(db, "10.0.0.6")
    assert b["qps_ewma"] == 1.5
    assert b["sample_count"] == 2


def test_all_baseline_qps(db) -> None:
    findings_db.set_baseline(
        db, client_ip="10.0.0.7", qps_ewma=0.3, nxdomain_rate_ewma=0.0,
        last_updated="2026-04-25T10:00:00+00:00", sample_count=1,
    )
    findings_db.set_baseline(
        db, client_ip="10.0.0.8", qps_ewma=1.2, nxdomain_rate_ewma=0.0,
        last_updated="2026-04-25T10:00:00+00:00", sample_count=1,
    )
    out = findings_db.all_baseline_qps(db)
    assert out == {"10.0.0.7": 0.3, "10.0.0.8": 1.2}


# --- run_log ---------------------------------------------------------------


def test_record_run_success(db) -> None:
    findings_db.record_run(
        db, run_at="2026-04-25T10:00:00+00:00",
        queries_seen=100, findings_emitted=2, elapsed_ms=350,
    )
    last = findings_db.last_successful_run(db)
    assert last == "2026-04-25T10:00:00+00:00"


def test_record_run_with_error_not_last_success(db) -> None:
    findings_db.record_run(
        db, run_at="2026-04-25T10:00:00+00:00",
        queries_seen=100, findings_emitted=2, elapsed_ms=350,
    )
    findings_db.record_run(
        db, run_at="2026-04-25T10:05:00+00:00",
        queries_seen=0, findings_emitted=0, elapsed_ms=80,
        error="PiHoleAPIError: connection refused",
    )
    # Last successful is still the older one
    last = findings_db.last_successful_run(db)
    assert last == "2026-04-25T10:00:00+00:00"


def test_last_successful_run_none_when_empty(db) -> None:
    assert findings_db.last_successful_run(db) is None


# --- pihole_snapshots ------------------------------------------------------


def _sample_snapshot(at: str, **overrides) -> dict:
    base = {
        "snapshot_at": at,
        "total_queries": 10000,
        "blocked_queries": 1500,
        "cached_queries": 4000,
        "forwarded_queries": 4500,
        "block_rate_pct": 15.0,
        "cache_hit_rate_pct": 40.0,
        "active_clients": 8,
        "unique_domains": 320,
        "gravity_domains": 750000,
        "top_blocked_domain": "doubleclick.net",
        "top_querying_client": "BSFlow (192.168.1.225)",
    }
    base.update(overrides)
    return base


def test_record_and_latest_snapshot(db) -> None:
    findings_db.record_snapshot(db, _sample_snapshot("2026-04-25T10:00:00+00:00"))
    findings_db.record_snapshot(
        db,
        _sample_snapshot(
            "2026-04-25T10:05:00+00:00", block_rate_pct=18.5, total_queries=10500
        ),
    )
    latest = findings_db.latest_snapshot(db)
    assert latest is not None
    assert latest["snapshot_at"] == "2026-04-25T10:05:00+00:00"
    assert latest["block_rate_pct"] == 18.5
    assert latest["total_queries"] == 10500


def test_latest_snapshot_none_when_empty(db) -> None:
    assert findings_db.latest_snapshot(db) is None


def test_snapshots_since(db) -> None:
    findings_db.record_snapshot(db, _sample_snapshot("2026-04-25T10:00:00+00:00"))
    findings_db.record_snapshot(db, _sample_snapshot("2026-04-25T10:30:00+00:00"))
    findings_db.record_snapshot(db, _sample_snapshot("2026-04-25T11:00:00+00:00"))
    rows = findings_db.snapshots_since(db, "2026-04-25T10:30:00+00:00")
    assert [r["snapshot_at"] for r in rows] == [
        "2026-04-25T10:30:00+00:00",
        "2026-04-25T11:00:00+00:00",
    ]


def test_record_snapshot_idempotent_on_same_at(db) -> None:
    findings_db.record_snapshot(
        db, _sample_snapshot("2026-04-25T10:00:00+00:00", block_rate_pct=10.0)
    )
    findings_db.record_snapshot(
        db, _sample_snapshot("2026-04-25T10:00:00+00:00", block_rate_pct=12.5)
    )
    n = db.execute("SELECT COUNT(*) AS n FROM pihole_snapshots").fetchone()["n"]
    assert n == 1
    latest = findings_db.latest_snapshot(db)
    assert latest["block_rate_pct"] == 12.5


# --- triage ----------------------------------------------------------------


def test_record_finding_default_outcome_is_pending(db) -> None:
    fid = findings_db.record_finding(
        db, finding_type="dga", severity="medium", client_ip="10.0.0.1",
        domain="x.evil.com", score=0.8,
    )
    row = db.execute("SELECT * FROM findings WHERE id = ?", (fid,)).fetchone()
    assert row["triage_outcome"] == "pending"
    assert row["triaged_at"] is None
    assert row["triage_note"] is None


def test_triage_finding_updates_row(db) -> None:
    fid = findings_db.record_finding(
        db, finding_type="dga", severity="medium", client_ip="10.0.0.1",
        domain="x.evil.com", score=0.8,
    )
    out = findings_db.triage_finding(
        db, fid, "false_positive", note="CDN edge name"
    )
    assert out["triage_outcome"] == "false_positive"
    assert out["triage_note"] == "CDN edge name"
    assert out["triaged_at"] is not None


def test_triage_finding_invalid_outcome(db) -> None:
    fid = findings_db.record_finding(
        db, finding_type="dga", severity="low", client_ip="10.0.0.1",
    )
    with pytest.raises(ValueError):
        findings_db.triage_finding(db, fid, "totally_not_a_thing")


def test_triage_finding_unknown_id(db) -> None:
    with pytest.raises(ValueError):
        findings_db.triage_finding(db, 99999, "confirmed")


def test_findings_by_outcome_filters(db) -> None:
    f1 = findings_db.record_finding(
        db, finding_type="dga", severity="low", client_ip="10.0.0.1"
    )
    findings_db.record_finding(
        db, finding_type="beacon", severity="high", client_ip="10.0.0.2"
    )
    findings_db.triage_finding(db, f1, "confirmed")
    confirmed = findings_db.findings_by_outcome(db, outcome="confirmed")
    pending = findings_db.findings_by_outcome(db, outcome="pending")
    assert len(confirmed) == 1
    assert confirmed[0]["id"] == f1
    assert len(pending) == 1
    assert pending[0]["finding_type"] == "beacon"


def test_triage_summary_per_detector(db) -> None:
    # Seed: 3 dga (1 confirmed, 1 fp, 1 pending), 2 beacon (1 ignored, 1 pending)
    ids = [
        findings_db.record_finding(
            db, finding_type="dga", severity="low", client_ip="10.0.0.1",
        )
        for _ in range(3)
    ]
    findings_db.triage_finding(db, ids[0], "confirmed")
    findings_db.triage_finding(db, ids[1], "false_positive")
    bid = findings_db.record_finding(
        db, finding_type="beacon", severity="medium", client_ip="10.0.0.5"
    )
    findings_db.record_finding(
        db, finding_type="beacon", severity="medium", client_ip="10.0.0.5"
    )
    findings_db.triage_finding(db, bid, "ignored")

    summary = findings_db.triage_summary(db)
    assert summary["dga"] == {
        "confirmed": 1, "false_positive": 1, "ignored": 0, "pending": 1
    }
    assert summary["beacon"] == {
        "confirmed": 0, "false_positive": 0, "ignored": 1, "pending": 1
    }


# --- migration safety ------------------------------------------------------


def test_migration_preserves_existing_rows(tmp_path) -> None:
    """Pre-create a v1-shaped DB (no triage cols, no snapshots table) and
    confirm that connect() applies migrations without losing data."""
    path = str(tmp_path / "old.db")
    raw = sqlite3.connect(path)
    raw.executescript(
        """
        CREATE TABLE findings (
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
        CREATE TABLE baselines (
            client_ip TEXT PRIMARY KEY,
            qps_ewma REAL NOT NULL,
            nxdomain_rate_ewma REAL NOT NULL,
            last_updated TEXT NOT NULL,
            sample_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE run_log (
            run_at TEXT PRIMARY KEY,
            queries_seen INTEGER NOT NULL,
            findings_emitted INTEGER NOT NULL,
            elapsed_ms INTEGER NOT NULL,
            error TEXT
        );
        """
    )
    raw.execute(
        "INSERT INTO findings (detected_at, finding_type, severity, client_ip) "
        "VALUES (?, ?, ?, ?)",
        ("2026-04-20T10:00:00+00:00", "dga", "medium", "10.0.0.99"),
    )
    raw.commit()
    raw.close()

    # Now open via the new code — migrations should run, row preserved.
    conn = findings_db.connect(path)
    try:
        rows = list(conn.execute("SELECT * FROM findings"))
        assert len(rows) == 1
        assert rows[0]["client_ip"] == "10.0.0.99"
        assert rows[0]["triage_outcome"] == "pending"
        # Snapshot table now exists.
        n = conn.execute(
            "SELECT COUNT(*) AS n FROM pihole_snapshots"
        ).fetchone()["n"]
        assert n == 0
        # Re-running init_schema is a no-op (idempotent).
        findings_db.init_schema(conn)
        cols = {
            r["name"]
            for r in conn.execute("PRAGMA table_info(findings)")
        }
        assert {"triaged_at", "triage_outcome", "triage_note"}.issubset(cols)
    finally:
        conn.close()
