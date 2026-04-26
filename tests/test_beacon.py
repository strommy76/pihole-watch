"""Beacon detection tests -- synthetic regular and irregular series."""

from __future__ import annotations

from pihole_watch.beacon import detect_beacons


def _q(qid: int, ip: str, domain: str, t: float) -> dict:
    return {
        "id": qid, "time": t, "domain": domain,
        "client": {"ip": ip, "name": None},
        "reply": {"type": "IP"}, "status": "FORWARDED", "type": "A",
    }


def test_regular_interval_flagged() -> None:
    base = 1700000000.0
    # 12 queries every 60.0s exactly -- CV should be 0.
    qs = [_q(i, "10.0.0.1", "c2.evil.com", base + i * 60.0) for i in range(12)]
    out = detect_beacons(qs, min_occurrences=6, max_cv=0.15, lookback_minutes=60)
    assert len(out) == 1
    f = out[0]
    assert f["client_ip"] == "10.0.0.1"
    assert f["domain"] == "c2.evil.com"
    assert f["occurrences"] == 12
    assert abs(f["mean_interval_sec"] - 60.0) < 1e-6
    assert f["cv"] < 1e-6


def test_jittered_interval_flagged() -> None:
    base = 1700000000.0
    # 60s +/- ~1s = CV ~ 1/60 = 0.017 -> still well below 0.15
    offsets = [0, 60.0, 121.0, 179.5, 240.5, 299.0, 361.0, 419.5]
    qs = [_q(i, "10.0.0.2", "c2.evil.com", base + off) for i, off in enumerate(offsets)]
    out = detect_beacons(qs, min_occurrences=6, max_cv=0.15, lookback_minutes=60)
    assert len(out) == 1


def test_irregular_intervals_not_flagged() -> None:
    base = 1700000000.0
    # Random-ish gaps from human browsing
    offsets = [0, 5.0, 73.0, 81.0, 120.0, 240.0, 600.0, 612.0, 999.0]
    qs = [_q(i, "10.0.0.3", "youtube.com", base + off) for i, off in enumerate(offsets)]
    out = detect_beacons(qs, min_occurrences=6, max_cv=0.15, lookback_minutes=60)
    assert out == []


def test_below_min_occurrences_not_flagged() -> None:
    base = 1700000000.0
    qs = [_q(i, "10.0.0.4", "c2.evil.com", base + i * 60.0) for i in range(4)]
    out = detect_beacons(qs, min_occurrences=6, max_cv=0.15, lookback_minutes=60)
    assert out == []


def test_lookback_window_excludes_old_samples() -> None:
    # Only the most recent lookback_minutes' worth of queries should count.
    # 5 fresh + 5 stale -> total 10 but only 5 in window -> below min=6.
    base = 1700000000.0
    fresh = [_q(i, "10.0.0.5", "c2.evil.com", base + i * 60.0) for i in range(5)]
    stale = [_q(i + 100, "10.0.0.5", "c2.evil.com", base - 7200.0 - i * 60.0)
             for i in range(5)]
    out = detect_beacons(
        fresh + stale, min_occurrences=6, max_cv=0.15, lookback_minutes=60
    )
    assert out == []


def test_multiple_groups_separated() -> None:
    base = 1700000000.0
    qs = (
        [_q(i, "10.0.0.6", "c2.evil.com", base + i * 30.0) for i in range(8)]
        + [_q(i + 100, "10.0.0.7", "other.com", base + i * 31.5) for i in range(8)]
    )
    out = detect_beacons(qs, min_occurrences=6, max_cv=0.15, lookback_minutes=60)
    assert len(out) == 2
    ips = {f["client_ip"] for f in out}
    assert ips == {"10.0.0.6", "10.0.0.7"}


def test_empty_input() -> None:
    assert detect_beacons([]) == []
