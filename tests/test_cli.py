"""CLI tests for pihole_watch.cli — list, triage, summary, weekly-report."""

from __future__ import annotations

import os
import tempfile

import pytest

from pihole_watch import cli, findings as findings_db


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    yield path
    for ext in ("", "-wal", "-shm"):
        p = path + ext
        if os.path.exists(p):
            os.unlink(p)


def _seed(path: str) -> dict:
    """Seed a small DB with a deterministic triage shape. Returns id map."""
    conn = findings_db.connect(path)
    try:
        ids: dict[str, list[int]] = {"dga": [], "beacon": []}
        for _ in range(4):
            ids["dga"].append(
                findings_db.record_finding(
                    conn, finding_type="dga", severity="medium",
                    client_ip="10.0.0.1", domain="x.evil.com", score=0.8,
                )
            )
        for _ in range(2):
            ids["beacon"].append(
                findings_db.record_finding(
                    conn, finding_type="beacon", severity="high",
                    client_ip="10.0.0.2", domain="c2.example.com", score=0.05,
                )
            )
        # Triage 2 dga: 1 confirmed, 1 false_positive
        findings_db.triage_finding(conn, ids["dga"][0], "confirmed")
        findings_db.triage_finding(conn, ids["dga"][1], "false_positive")
        # Beacon: 1 confirmed, 1 ignored
        findings_db.triage_finding(conn, ids["beacon"][0], "confirmed")
        findings_db.triage_finding(conn, ids["beacon"][1], "ignored")
        # Add a snapshot too
        findings_db.record_snapshot(
            conn,
            {
                "snapshot_at": "2026-04-25T10:00:00+00:00",
                "total_queries": 12000,
                "blocked_queries": 1800,
                "cached_queries": 4000,
                "forwarded_queries": 6200,
                "block_rate_pct": 15.0,
                "cache_hit_rate_pct": 33.3,
                "active_clients": 7,
                "unique_domains": 250,
                "gravity_domains": 700000,
                "top_blocked_domain": "doubleclick.net",
                "top_querying_client": "BSFlow",
            },
        )
        return ids
    finally:
        conn.close()


# -- list -------------------------------------------------------------------


def test_cli_list_default(db_path, capsys) -> None:
    _seed(db_path)
    rc = cli.main(["--db", db_path, "list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ID" in out and "DETECTED" in out
    # 6 findings seeded — all should appear given default limit 20
    assert out.count("dga") + out.count("beacon") >= 6


def test_cli_list_filter_by_outcome(db_path, capsys) -> None:
    _seed(db_path)
    rc = cli.main(["--db", db_path, "list", "--outcome", "confirmed"])
    out = capsys.readouterr().out
    assert rc == 0
    # 2 confirmed in seed (1 dga + 1 beacon)
    assert "confirmed" in out
    # No false_positive lines should appear in this filter
    body_lines = [l for l in out.splitlines() if l.startswith("#")]
    assert len(body_lines) == 2
    for line in body_lines:
        assert "false_positive" not in line


def test_cli_list_filter_by_type(db_path, capsys) -> None:
    _seed(db_path)
    rc = cli.main(["--db", db_path, "list", "--type", "beacon"])
    out = capsys.readouterr().out
    assert rc == 0
    body_lines = [l for l in out.splitlines() if l.startswith("#")]
    assert len(body_lines) == 2
    for line in body_lines:
        assert "beacon" in line


# -- triage -----------------------------------------------------------------


def test_cli_triage_updates_row(db_path, capsys) -> None:
    ids = _seed(db_path)
    target = ids["dga"][2]  # currently pending
    rc = cli.main(
        [
            "--db", db_path, "triage", str(target),
            "--outcome", "ignored", "--note", "edge cdn",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert f"#{target}" in out and "ignored" in out
    # Verify on disk
    conn = findings_db.connect(db_path)
    try:
        row = conn.execute(
            "SELECT triage_outcome, triage_note FROM findings WHERE id=?",
            (target,),
        ).fetchone()
        assert row["triage_outcome"] == "ignored"
        assert row["triage_note"] == "edge cdn"
    finally:
        conn.close()


def test_cli_triage_invalid_id_returns_error(db_path, capsys) -> None:
    _seed(db_path)
    rc = cli.main(
        ["--db", db_path, "triage", "999999", "--outcome", "confirmed"]
    )
    err = capsys.readouterr().err
    assert rc == 2
    assert "not found" in err


# -- summary ----------------------------------------------------------------


def test_cli_summary_computes_precision(db_path, capsys) -> None:
    _seed(db_path)
    rc = cli.main(["--db", db_path, "summary"])
    out = capsys.readouterr().out
    assert rc == 0
    # dga: 1 confirmed / 2 (confirmed+fp) = 50.0%
    assert "dga" in out and "50.0%" in out
    # beacon: 1 confirmed / 1 (confirmed only — no fp) = 100.0%
    assert "beacon" in out and "100.0%" in out
    # Snapshot block too
    assert "Pi-hole latest snapshot" in out


def test_cli_summary_empty_db(db_path, capsys) -> None:
    # Just init
    conn = findings_db.connect(db_path)
    conn.close()
    rc = cli.main(["--db", db_path, "summary"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "total findings: 0" in out


# -- weekly-report ----------------------------------------------------------


def test_cli_weekly_report_renders(db_path, capsys) -> None:
    _seed(db_path)
    rc = cli.main(["--db", db_path, "weekly-report"])
    out = capsys.readouterr().out
    assert rc == 0
    # Markdown anchors we expect
    assert out.startswith("# pihole-watch weekly report")
    assert "## Findings emitted" in out
    assert "## Triage" in out
    assert "## Per-detector precision" in out
    assert "## Top noisy clients" in out
