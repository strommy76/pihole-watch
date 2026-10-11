"""Real findings-owner lifecycle against a filesystem-read-only consumer."""

import sqlite3

from pihole_watch import findings


def test_closed_store_is_readable_without_writable_directory(tmp_path):
    storage = tmp_path / "store"
    storage.mkdir()
    path = storage / "findings.db"

    # Initial publication and a later producer run both leave committed data
    # readable after the owner closes; expected counts come from supplied input.
    for index, queries_seen in enumerate((19, 23)):
        writer = findings.connect(str(path))
        findings.record_run(
            writer, run_at=f"2026-10-11T12:0{index}:00+00:00",
            queries_seen=queries_seen, findings_emitted=0, elapsed_ms=1,
        )
        writer.close()
        path.chmod(0o444)
        storage.chmod(0o555)
        try:
            reader = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
            try:
                assert reader.execute(
                    "SELECT queries_seen FROM run_log ORDER BY run_at DESC LIMIT 1"
                ).fetchone() == (queries_seen,)
            finally:
                reader.close()
        finally:
            storage.chmod(0o755)
            path.chmod(0o644)


def test_existing_wal_store_keeps_records_when_owner_changes_mode(tmp_path):
    path = tmp_path / "findings.db"
    writer = findings.connect(str(path))
    # Native SQLite constructs the deployed predecessor, not a mocked pragma.
    assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    findings.record_run(
        writer, run_at="2026-10-11T12:00:00+00:00", queries_seen=17,
        findings_emitted=0, elapsed_ms=1,
    )
    writer.close()

    owner = findings.connect(str(path))
    try:
        assert owner.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert owner.execute("SELECT queries_seen FROM run_log").fetchone()[0] == 17
    finally:
        owner.close()
