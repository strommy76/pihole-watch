"""Findings DB lifecycle tests -- init, write, read, baselines, run_log."""

from __future__ import annotations

import json
import os
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


def test_schema_creates_three_tables(db) -> None:
    rows = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    names = [r["name"] for r in rows]
    assert names == ["baselines", "findings", "run_log"]


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
