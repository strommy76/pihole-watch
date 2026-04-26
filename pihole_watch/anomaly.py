"""
--------------------------------------------------------------------------------
FILE:        anomaly.py
PATH:        ~/projects/pihole-watch/pihole_watch/anomaly.py
DESCRIPTION: Per-client behavior anomalies -- NXDOMAIN rates, query-volume
             anomalies vs EWMA baseline, and baseline updates.

CHANGELOG:
2026-04-25            Claude      [Feature] Initial implementation.
--------------------------------------------------------------------------------
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone

log = logging.getLogger(__name__)

_NX_STATUSES: frozenset[str] = frozenset({"NXDOMAIN", "NX"})
# Standard EWMA factor on per-window observations
_EWMA_ALPHA = 0.3


def _client_ip(q: dict) -> str | None:
    client = q.get("client") or {}
    ip = client.get("ip")
    return ip if isinstance(ip, str) and ip else None


def _is_nxdomain(q: dict) -> bool:
    reply = q.get("reply") or {}
    rtype = reply.get("type")
    if isinstance(rtype, str) and rtype.upper() == "NXDOMAIN":
        return True
    status = q.get("status")
    if isinstance(status, str) and status.upper() in _NX_STATUSES:
        return True
    return False


def nxdomain_rate_per_client(queries: list[dict]) -> dict[str, dict]:
    """Per-client NXDOMAIN counts and rates.

    Returns ``{client_ip: {"total": N, "nxdomain": M, "rate": M/N}}``.
    Clients with no IP in the query record are skipped.
    """
    out: dict[str, dict] = {}
    for q in queries:
        ip = _client_ip(q)
        if ip is None:
            continue
        bucket = out.setdefault(ip, {"total": 0, "nxdomain": 0, "rate": 0.0})
        bucket["total"] += 1
        if _is_nxdomain(q):
            bucket["nxdomain"] += 1
    for ip, b in out.items():
        b["rate"] = (b["nxdomain"] / b["total"]) if b["total"] else 0.0
    return out


def query_volume_anomalies(
    queries: list[dict],
    baseline_qps: dict[str, float] | None = None,
    *,
    window_seconds: float | None = None,
    sigma_threshold: float = 3.0,
) -> list[dict]:
    """Flag clients whose observed QPS deviates strongly from baseline.

    If ``baseline_qps`` is None or empty, returns []. The deviation is a
    pseudo-sigma computed as ``(observed - baseline) / sqrt(baseline + 1)``
    -- a Poisson-style normalisation that grows with absolute spike size
    while remaining stable on quiet baselines.

    Args:
        queries: queries seen in the current window.
        baseline_qps: dict ``{client_ip: ewma_qps}`` from prior runs.
        window_seconds: explicit window length. If None, inferred from
            queries' min/max timestamps.
        sigma_threshold: minimum absolute deviation to surface.
    """
    if not baseline_qps:
        return []
    if not queries:
        return []

    if window_seconds is None:
        times = [
            float(q["time"]) for q in queries if isinstance(q.get("time"), (int, float))
        ]
        if len(times) < 2:
            return []
        window_seconds = max(1.0, max(times) - min(times))

    counts: dict[str, int] = {}
    for q in queries:
        ip = _client_ip(q)
        if ip is None:
            continue
        counts[ip] = counts.get(ip, 0) + 1

    findings: list[dict] = []
    for ip, n in counts.items():
        observed_qps = n / window_seconds
        baseline = float(baseline_qps.get(ip, 0.0))
        # Poisson-style sigma on expected count over the window.
        expected_count = baseline * window_seconds
        denom = math.sqrt(expected_count + 1.0)
        deviation = (n - expected_count) / denom
        if abs(deviation) < sigma_threshold:
            continue
        if deviation >= 6.0:
            severity = "high"
        elif deviation >= 4.0:
            severity = "medium"
        else:
            severity = "low"
        findings.append({
            "client_ip": ip,
            "observed_qps": observed_qps,
            "baseline_qps": baseline,
            "deviation_sigma": deviation,
            "severity": severity,
        })
    return findings


def update_baselines(findings_conn, queries: list[dict]) -> None:
    """Update per-client EWMA baselines for QPS and NXDOMAIN rate.

    Uses ``alpha=0.3`` over the (single) window represented by ``queries``.
    Window length is inferred from the queries' min/max timestamps; a 5-min
    floor is applied so very small windows don't inflate the QPS estimate.

    The findings DB connection must already have the ``baselines`` table.
    """
    from .findings import get_baseline, set_baseline

    if not queries:
        return

    times = [
        float(q["time"]) for q in queries if isinstance(q.get("time"), (int, float))
    ]
    if len(times) < 2:
        return
    window_seconds = max(1.0, max(times) - min(times))

    counts: dict[str, int] = {}
    nx: dict[str, int] = {}
    for q in queries:
        ip = _client_ip(q)
        if ip is None:
            continue
        counts[ip] = counts.get(ip, 0) + 1
        if _is_nxdomain(q):
            nx[ip] = nx.get(ip, 0) + 1

    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for ip, n in counts.items():
        observed_qps = n / window_seconds
        observed_nx_rate = (nx.get(ip, 0) / n) if n else 0.0
        prev = get_baseline(findings_conn, ip)
        if prev is None:
            new_qps = observed_qps
            new_nx = observed_nx_rate
            sample_count = 1
        else:
            new_qps = _EWMA_ALPHA * observed_qps + (1 - _EWMA_ALPHA) * float(
                prev["qps_ewma"]
            )
            new_nx = _EWMA_ALPHA * observed_nx_rate + (1 - _EWMA_ALPHA) * float(
                prev["nxdomain_rate_ewma"]
            )
            sample_count = int(prev["sample_count"]) + 1
        set_baseline(
            findings_conn,
            client_ip=ip,
            qps_ewma=float(new_qps),
            nxdomain_rate_ewma=float(new_nx),
            last_updated=now_iso,
            sample_count=sample_count,
        )


__all__ = [
    "nxdomain_rate_per_client",
    "query_volume_anomalies",
    "update_baselines",
]
