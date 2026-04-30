"""Per-client anomaly detection tests -- NXDOMAIN rate, volume sigma, EWMA baselines."""

from __future__ import annotations

import os
import tempfile

from pihole_watch import findings as findings_db
from pihole_watch.anomaly import (
    filter_infrastructure_clients,
    nxdomain_rate_per_client,
    query_volume_anomalies,
    update_baselines,
)


def _q(qid: int, ip: str, domain: str = "example.com",
       reply_type: str = "IP", status: str = "FORWARDED",
       t: float = 1700000000.0) -> dict:
    return {
        "id": qid,
        "time": t,
        "type": "A",
        "status": status,
        "domain": domain,
        "client": {"ip": ip, "name": None},
        "reply": {"type": reply_type, "time": 0.0001},
    }


# --- NXDOMAIN rate -------------------------------------------------------


def test_nx_rate_basic() -> None:
    qs = [
        _q(1, "10.0.0.1", reply_type="IP"),
        _q(2, "10.0.0.1", reply_type="NXDOMAIN"),
        _q(3, "10.0.0.1", reply_type="NXDOMAIN"),
        _q(4, "10.0.0.1", reply_type="IP"),
    ]
    out = nxdomain_rate_per_client(qs)
    assert out["10.0.0.1"]["total"] == 4
    assert out["10.0.0.1"]["nxdomain"] == 2
    assert abs(out["10.0.0.1"]["rate"] - 0.5) < 1e-9


def test_nx_rate_empty() -> None:
    assert nxdomain_rate_per_client([]) == {}


def test_nx_rate_skips_clients_without_ip() -> None:
    qs = [
        _q(1, "10.0.0.1"),
        {"id": 2, "client": {"ip": None}, "reply": {"type": "IP"},
         "status": "FORWARDED"},
    ]
    out = nxdomain_rate_per_client(qs)
    assert "10.0.0.1" in out
    assert len(out) == 1


def test_nx_rate_status_signal() -> None:
    qs = [
        _q(1, "10.0.0.2", status="NXDOMAIN", reply_type="UNKNOWN"),
        _q(2, "10.0.0.2", status="FORWARDED", reply_type="IP"),
    ]
    out = nxdomain_rate_per_client(qs)
    assert out["10.0.0.2"]["nxdomain"] == 1


# --- volume anomaly ------------------------------------------------------


def test_volume_anomaly_returns_empty_without_baseline() -> None:
    qs = [_q(i, "10.0.0.1", t=1700000000.0 + i) for i in range(50)]
    assert query_volume_anomalies(qs, baseline_qps=None) == []
    assert query_volume_anomalies(qs, baseline_qps={}) == []


def test_volume_anomaly_flags_spike() -> None:
    # Tight window: 100 queries in 60s -> ~1.67 qps; baseline is 0.05 qps.
    qs = [
        _q(i, "10.0.0.5", t=1700000000.0 + i * 0.6) for i in range(100)
    ]
    out = query_volume_anomalies(
        qs, {"10.0.0.5": 0.05}, window_seconds=60.0, sigma_threshold=3.0
    )
    assert len(out) == 1
    assert out[0]["client_ip"] == "10.0.0.5"
    assert out[0]["deviation_sigma"] > 3.0


def test_volume_anomaly_below_threshold_no_flag() -> None:
    qs = [_q(i, "10.0.0.6", t=1700000000.0 + i * 1.0) for i in range(60)]
    out = query_volume_anomalies(
        qs, {"10.0.0.6": 0.95}, window_seconds=60.0, sigma_threshold=3.0
    )
    assert out == []


# --- EWMA baselines ------------------------------------------------------


def _new_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    return path


def test_baseline_first_observation() -> None:
    path = _new_db()
    try:
        conn = findings_db.connect(path)
        qs = [_q(i, "10.0.0.10", t=1700000000.0 + i) for i in range(60)]
        update_baselines(conn, qs)
        b = findings_db.get_baseline(conn, "10.0.0.10")
        assert b is not None
        assert b["sample_count"] == 1
        # 60 queries over 59s -> ~1.017 qps
        assert 0.9 < b["qps_ewma"] < 1.1
        conn.close()
    finally:
        os.unlink(path)


def test_baseline_ewma_smooths_subsequent() -> None:
    path = _new_db()
    try:
        conn = findings_db.connect(path)
        # First window: ~1 qps
        qs1 = [_q(i, "10.0.0.11", t=1700000000.0 + i) for i in range(60)]
        update_baselines(conn, qs1)
        first = findings_db.get_baseline(conn, "10.0.0.11")
        assert first is not None
        # Second window: ~10 qps
        qs2 = [_q(1000 + i, "10.0.0.11", t=1700000100.0 + i * 0.1)
               for i in range(60)]
        update_baselines(conn, qs2)
        second = findings_db.get_baseline(conn, "10.0.0.11")
        assert second is not None
        assert second["sample_count"] == 2
        # EWMA with alpha=0.3 should pull toward the new (~10) but not all
        # the way: 0.3*10 + 0.7*1 = 3.7 (approx)
        assert second["qps_ewma"] > first["qps_ewma"]
        assert 2.0 < second["qps_ewma"] < 6.0
        conn.close()
    finally:
        os.unlink(path)


def test_volume_anomaly_severity_levels() -> None:
    qs = [_q(i, "10.0.0.7", t=1700000000.0 + i * 0.1) for i in range(600)]
    out = query_volume_anomalies(
        qs, {"10.0.0.7": 0.05}, window_seconds=60.0, sigma_threshold=3.0
    )
    assert out and out[0]["severity"] == "high"


# --- filter_infrastructure_clients (Docker bridge gateway exclusion) -----


def test_filter_infrastructure_clients_drops_matching_ips() -> None:
    """Queries from configured infrastructure IPs are stripped; everything
    else passes through unchanged."""
    queries = [
        _q(1, "172.19.0.1"),    # Docker bridge gateway — drop
        _q(2, "10.0.0.5"),      # real endpoint — keep
        _q(3, "172.17.0.1"),    # Docker bridge gateway — drop
        _q(4, "192.168.1.42"),  # real endpoint — keep
    ]
    out = filter_infrastructure_clients(
        queries, frozenset({"172.17.0.1", "172.19.0.1"}),
    )
    assert len(out) == 2
    assert {q["client"]["ip"] for q in out} == {"10.0.0.5", "192.168.1.42"}


def test_filter_infrastructure_clients_empty_set_is_noop() -> None:
    """Empty infrastructure set → returns the input list unchanged."""
    queries = [_q(1, "172.19.0.1"), _q(2, "10.0.0.5")]
    out = filter_infrastructure_clients(queries, frozenset())
    assert out is queries  # identity, not just equality — no-op


def test_filter_infrastructure_clients_handles_missing_client_field() -> None:
    """Records without a client.ip don't crash the filter — they pass
    through (downstream per-client analyses already skip them)."""
    queries = [
        _q(1, "172.19.0.1"),
        {"id": 2, "time": 1700000000.0, "type": "A", "status": "FORWARDED",
         "domain": "anon.example", "reply": {"type": "IP", "time": 0.0}},
    ]
    out = filter_infrastructure_clients(queries, frozenset({"172.19.0.1"}))
    assert len(out) == 1
    assert out[0]["id"] == 2


def test_volume_anomaly_with_filter_skips_gateway() -> None:
    """End-to-end: a gateway IP that would otherwise produce a high-sigma
    volume anomaly is silently filtered out."""
    qs = [_q(i, "172.19.0.1", t=1700000000.0 + i * 0.1) for i in range(600)]
    qs += [_q(700, "10.0.0.5", t=1700000000.5)]  # one real endpoint query
    filtered = filter_infrastructure_clients(qs, frozenset({"172.19.0.1"}))
    out = query_volume_anomalies(
        filtered, {"172.19.0.1": 0.05, "10.0.0.5": 1.0},
        window_seconds=60.0, sigma_threshold=3.0,
    )
    # 172.19.0.1 should not appear in findings — it was filtered upstream.
    assert all(f["client_ip"] != "172.19.0.1" for f in out)
