"""
--------------------------------------------------------------------------------
FILE:        beacon.py
PATH:        ~/projects/pihole-watch/pihole_watch/beacon.py
DESCRIPTION: Periodic-query (C2 beacon) detection. For each (client, domain)
             group with enough occurrences in the lookback window, compute
             coefficient of variation on inter-arrival times. CV < threshold
             -> the queries are suspiciously regular -> flag.

CHANGELOG:
2026-04-25            Claude      [Feature] Initial implementation.
--------------------------------------------------------------------------------
"""

from __future__ import annotations

import logging
import statistics
from datetime import datetime, timezone

log = logging.getLogger(__name__)


def _client_ip(q: dict) -> str | None:
    client = q.get("client") or {}
    ip = client.get("ip")
    return ip if isinstance(ip, str) and ip else None


def _coef_of_variation(values: list[float]) -> float | None:
    """Sample stdev / mean. Returns None if mean is 0 or sample too small."""
    if len(values) < 2:
        return None
    mean = statistics.fmean(values)
    if mean <= 0:
        return None
    stdev = statistics.stdev(values)
    return stdev / mean


def detect_beacons(
    queries: list[dict],
    min_occurrences: int = 6,
    max_cv: float = 0.15,
    lookback_minutes: int = 60,
) -> list[dict]:
    """Group queries by (client_ip, domain). Flag groups with enough samples
    and a low coefficient of variation on inter-arrival times.

    Args:
        queries: query dicts (must contain ``time``, ``domain``, ``client.ip``).
        min_occurrences: minimum query count per (client, domain) group.
        max_cv: maximum CV to flag as a beacon (lower = more regular).
        lookback_minutes: only consider queries whose ``time`` falls within
            the most recent ``lookback_minutes`` of the data.

    Returns:
        list of finding dicts: client_ip, domain, occurrences, mean_interval_sec,
        cv, first_seen, last_seen.
    """
    if not queries:
        return []

    valid: list[tuple[str, str, float]] = []
    max_time = 0.0
    for q in queries:
        t = q.get("time")
        d = q.get("domain")
        ip = _client_ip(q)
        if not isinstance(t, (int, float)) or not isinstance(d, str) or ip is None:
            continue
        valid.append((ip, d, float(t)))
        if t > max_time:
            max_time = float(t)

    if not valid:
        return []

    cutoff = max_time - (lookback_minutes * 60.0)
    groups: dict[tuple[str, str], list[float]] = {}
    for ip, d, t in valid:
        if t < cutoff:
            continue
        groups.setdefault((ip, d), []).append(t)

    findings: list[dict] = []
    for (ip, domain), times in groups.items():
        if len(times) < min_occurrences:
            continue
        times.sort()
        intervals = [b - a for a, b in zip(times, times[1:])]
        if not intervals or any(i <= 0 for i in intervals):
            continue
        cv = _coef_of_variation(intervals)
        if cv is None or cv >= max_cv:
            continue
        mean_interval = statistics.fmean(intervals)
        findings.append({
            "client_ip": ip,
            "domain": domain,
            "occurrences": len(times),
            "mean_interval_sec": float(mean_interval),
            "cv": float(cv),
            "first_seen": datetime.fromtimestamp(
                times[0], tz=timezone.utc
            ).isoformat(timespec="seconds"),
            "last_seen": datetime.fromtimestamp(
                times[-1], tz=timezone.utc
            ).isoformat(timespec="seconds"),
        })
    return findings


__all__ = ["detect_beacons"]
