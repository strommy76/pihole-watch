"""
--------------------------------------------------------------------------------
FILE:        calibrate.py
PATH:        ~/projects/pihole-watch/pihole_watch/calibrate.py
DESCRIPTION: Autonomous threshold calibration for pihole-watch detectors.
             Uses the user's own Pi-hole traffic as a negative corpus and
             generates synthetic DGA-style domains as the positive corpus,
             then performs ROC analysis to pick the threshold that meets a
             target false-positive rate while maximising true-positive rate.
             Also calibrates the NXDOMAIN-rate, beacon CV, and volume-sigma
             thresholds via per-parameter percentile heuristics.

CHANGELOG:
2026-04-26            Claude      [Feature] Initial implementation.
--------------------------------------------------------------------------------
"""

from __future__ import annotations

import logging
import random
import sqlite3
import statistics
import string
import time
from typing import Any, Callable, Iterable

from pihole_watch import findings as findings_db
from pihole_watch.beacon import _coef_of_variation
from pihole_watch.dga import dga_score

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Defaults (also documented in config.py / .env.example)
# ---------------------------------------------------------------------------

DEFAULT_DGA_THRESHOLD: float = 0.65
DEFAULT_NXDOMAIN_RATE_THRESHOLD: float = 0.30
DEFAULT_BEACON_CV_THRESHOLD: float = 0.15
DEFAULT_VOLUME_SIGMA_THRESHOLD: float = 3.0

_BLOCKED_STATUSES: frozenset[str] = frozenset({
    "GRAVITY", "DENYLIST", "REGEX", "BLACKLIST",
    "BLACKLIST_CNAME", "GRAVITY_CNAME", "DENYLIST_CNAME",
})


# ---------------------------------------------------------------------------
# Synthetic DGA generator
# ---------------------------------------------------------------------------


_VOWELS = "aeiou"
_CONSONANTS = "bcdfghjklmnpqrstvwxyz"
_LETTERS = string.ascii_lowercase
_ALNUM = string.ascii_lowercase + string.digits
_DGA_TLDS: tuple[str, ...] = (
    "com", "net", "org", "info", "biz", "ru", "cc", "xyz", "top", "online",
)


def _conficker_style(rng: random.Random) -> str:
    n = rng.randint(8, 11)
    label = "".join(rng.choices(_LETTERS, k=n))
    tld = rng.choice(("com", "net", "org"))
    return f"{label}.{tld}"


def _cryptolocker_style(rng: random.Random) -> str:
    n = rng.randint(12, 25)
    label = "".join(rng.choices(_LETTERS, k=n))
    return f"{label}.com"


def _banjori_style(rng: random.Random) -> str:
    """Vowel-poor consonant runs. Real Banjori is slightly different but the
    character-statistics fingerprint matches: very low vowel ratio, long
    consonant runs."""
    n = rng.randint(10, 18)
    chars: list[str] = []
    for _ in range(n):
        # 85% consonant, 15% vowel
        if rng.random() < 0.85:
            chars.append(rng.choice(_CONSONANTS))
        else:
            chars.append(rng.choice(_VOWELS))
    return "".join(chars) + ".com"


def _necurs_style(rng: random.Random) -> str:
    n = rng.randint(6, 25)
    body = "".join(rng.choices(_ALNUM, k=n))
    # ~30% chance of a digit-rich suffix
    if rng.random() < 0.3:
        suffix = "".join(rng.choices(string.digits, k=rng.randint(2, 5)))
        body = body + suffix
    tld = rng.choice(_DGA_TLDS)
    return f"{body}.{tld}"


def _pseudoword_style(rng: random.Random) -> str:
    """Concatenate random pseudo-syllables. Some DGAs (e.g. Suppobox) use
    English-word lookalikes, but the character stats still trip the scorer
    when pieces are jammed together with no separators."""
    syllable_count = rng.randint(2, 4)
    parts: list[str] = []
    for _ in range(syllable_count):
        slen = rng.randint(3, 6)
        piece = "".join(rng.choices(_LETTERS, k=slen))
        parts.append(piece)
    label = "".join(parts)
    # Sometimes inject a digit run for extra DGA-ness
    if rng.random() < 0.25:
        label = label + "".join(rng.choices(string.digits, k=rng.randint(1, 3)))
    tld = rng.choice(("com", "net", "info", "xyz"))
    return f"{label}.{tld}"


_GENERATORS: tuple[Callable[[random.Random], str], ...] = (
    _conficker_style,
    _cryptolocker_style,
    _banjori_style,
    _necurs_style,
    _pseudoword_style,
)


def generate_synthetic_dga(n: int = 2000, seed: int = 42) -> list[str]:
    """Generate a deterministic list of ``n`` synthetic DGA-style domains.

    The mix is roughly uniform across five style families (Conficker,
    Cryptolocker, Banjori, Necurs, pseudoword). Output is deduped so the
    final length may be slightly below ``n``.
    """
    if n <= 0:
        return []
    rng = random.Random(seed)
    out: set[str] = set()
    # 4x oversample to absorb dedupe loss while keeping it bounded
    attempts = 0
    max_attempts = n * 8
    while len(out) < n and attempts < max_attempts:
        gen = rng.choice(_GENERATORS)
        out.add(gen(rng))
        attempts += 1
    return sorted(out)


# ---------------------------------------------------------------------------
# Negative corpus from real Pi-hole traffic
# ---------------------------------------------------------------------------


def _is_blocked(q: dict) -> bool:
    s = q.get("status")
    return isinstance(s, str) and s.upper() in _BLOCKED_STATUSES


def collect_negative_corpus(
    pihole_client: Any,
    *,
    lookback_days: int,
    page_length: int = 10000,
    max_pages: int = 200,
) -> list[str]:
    """Pull distinct non-blocked domains from the past ``lookback_days``.

    Pi-hole's API is paginated; we walk pages forward until exhausted.
    Domains that are blocked, gravity-matched, or regex-matched are
    excluded -- those are already known threats and would skew the corpus.

    Raises:
        Whatever the API client raises on connection / auth failure.
            We deliberately do NOT swallow these -- a failing API means we
            have no negative corpus and calibration cannot proceed.
    """
    if lookback_days <= 0:
        raise ValueError(f"lookback_days must be > 0 (got {lookback_days})")
    until = time.time()
    since = until - (lookback_days * 86400.0)
    queries = pihole_client.fetch_queries(
        since, until_unix=until, page_length=page_length, max_pages=max_pages
    )
    seen: set[str] = set()
    for q in queries:
        if _is_blocked(q):
            continue
        d = q.get("domain")
        if isinstance(d, str) and d:
            seen.add(d.lower())
    return sorted(seen)


# ---------------------------------------------------------------------------
# ROC computation
# ---------------------------------------------------------------------------


def _roc_curve(
    negative_scores: list[float],
    positive_scores: list[float],
    *,
    step: float = 0.01,
    lo: float = 0.30,
    hi: float = 0.95,
) -> list[tuple[float, float, float, float]]:
    """Compute (threshold, fpr, tpr, f1) at thresholds in [lo, hi].

    A domain is flagged if its score >= threshold. Scores are evaluated
    in 0.01 steps by default. Both negative and positive lists may be
    non-empty; a divide-by-zero on either yields a 0.0 rate.
    """
    n_neg = len(negative_scores)
    n_pos = len(positive_scores)
    out: list[tuple[float, float, float, float]] = []
    # Build threshold grid (inclusive of `hi`).
    t = lo
    grid: list[float] = []
    while t <= hi + 1e-9:
        grid.append(round(t, 4))
        t += step
    for thr in grid:
        fp = sum(1 for s in negative_scores if s >= thr)
        tp = sum(1 for s in positive_scores if s >= thr)
        fn = n_pos - tp
        fpr = (fp / n_neg) if n_neg else 0.0
        tpr = (tp / n_pos) if n_pos else 0.0
        # F1 = 2*precision*recall / (precision+recall); precision = TP/(TP+FP)
        if tp + fp == 0:
            precision = 0.0
        else:
            precision = tp / (tp + fp)
        recall = tpr
        if precision + recall == 0:
            f1 = 0.0
        else:
            f1 = 2.0 * precision * recall / (precision + recall)
        out.append((thr, fpr, tpr, f1))
    return out


def _auroc(negative_scores: list[float], positive_scores: list[float]) -> float:
    """AUROC via the Mann-Whitney U statistic.

    U = (sum of ranks of positives) - n_pos*(n_pos+1)/2
    AUC = U / (n_pos * n_neg)

    Tied scores between groups contribute 0.5 each (standard convention).
    Returns 0.5 when either group is empty.
    """
    n_pos = len(positive_scores)
    n_neg = len(negative_scores)
    if n_pos == 0 or n_neg == 0:
        return 0.5
    # Pair-counting via merge -- O(n log n) on n = n_pos + n_neg.
    combined = (
        [(s, 1) for s in positive_scores] + [(s, 0) for s in negative_scores]
    )
    combined.sort(key=lambda x: x[0])
    # Assign average ranks to ties
    n = len(combined)
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0  # 1-based
        for k in range(i, j + 1):
            ranks[k] = avg_rank
        i = j + 1
    rank_sum_pos = sum(r for r, (_, lab) in zip(ranks, combined) if lab == 1)
    u = rank_sum_pos - n_pos * (n_pos + 1) / 2.0
    return float(u / (n_pos * n_neg))


def _select_optimal_threshold(
    curve: list[tuple[float, float, float, float]],
    *,
    target_fpr: float,
) -> tuple[float, dict[str, float]]:
    """Pick the threshold meeting the FPR target while maximising TPR.

    1. Filter to thresholds with fpr <= target_fpr. Among those, pick the
       one with the highest TPR; tie-break on higher threshold (more
       conservative).
    2. If no threshold achieves the target, return the one whose
       (TPR >= 0.5) has the lowest FPR. Tie-break on higher threshold.
    3. If still no candidate, return the threshold with min FPR.
    """
    if not curve:
        raise ValueError("empty ROC curve")
    # Phase 1: meets target
    feasible = [c for c in curve if c[1] <= target_fpr]
    if feasible:
        # Sort: highest TPR first, then highest threshold (more conservative)
        feasible.sort(key=lambda c: (c[2], c[0]), reverse=True)
        thr, fpr, tpr, f1 = feasible[0]
        return thr, {"tpr": tpr, "fpr": fpr, "f1": f1}
    # Phase 2: TPR >= 0.5
    catch_half = [c for c in curve if c[2] >= 0.5]
    if catch_half:
        catch_half.sort(key=lambda c: (c[1], -c[0]))  # min FPR, then higher thr
        thr, fpr, tpr, f1 = catch_half[0]
        return thr, {"tpr": tpr, "fpr": fpr, "f1": f1}
    # Phase 3: min FPR
    by_fpr = sorted(curve, key=lambda c: (c[1], -c[0]))
    thr, fpr, tpr, f1 = by_fpr[0]
    return thr, {"tpr": tpr, "fpr": fpr, "f1": f1}


# ---------------------------------------------------------------------------
# DGA threshold calibration
# ---------------------------------------------------------------------------


def calibrate_dga_threshold(
    pihole_client: Any,
    findings_conn: sqlite3.Connection | None = None,
    *,
    lookback_days: int = 7,
    n_synthetic_dga: int = 2000,
    target_fpr: float = 0.02,
    seed: int = 42,
    negative_corpus_override: list[str] | None = None,
) -> dict[str, Any]:
    """Determine the optimal DGA threshold via ROC analysis.

    See module docstring for the algorithm. ``negative_corpus_override`` is
    provided for testing; in production it's None and the corpus is fetched
    from the live Pi-hole client.

    Returns the structured result dict described in the assignment.
    """
    if negative_corpus_override is not None:
        negative_domains = list(negative_corpus_override)
    else:
        negative_domains = collect_negative_corpus(
            pihole_client, lookback_days=lookback_days
        )
    positive_domains = generate_synthetic_dga(n=n_synthetic_dga, seed=seed)

    if not negative_domains:
        raise RuntimeError(
            "negative corpus is empty -- cannot calibrate DGA threshold"
        )
    if not positive_domains:
        raise RuntimeError(
            "positive (synthetic) corpus is empty -- cannot calibrate"
        )

    neg_scored = [(d, dga_score(d)) for d in negative_domains]
    pos_scored = [(d, dga_score(d)) for d in positive_domains]
    neg_scores = [s for _, s in neg_scored]
    pos_scores = [s for _, s in pos_scored]

    curve = _roc_curve(neg_scores, pos_scores)
    auroc = _auroc(neg_scores, pos_scores)
    optimal, sel_metrics = _select_optimal_threshold(curve, target_fpr=target_fpr)

    # Diagnostics: hardest legitimate cases (highest scoring negatives) and
    # easiest DGA cases (highest scoring positives).
    neg_scored_sorted = sorted(neg_scored, key=lambda x: x[1], reverse=True)
    pos_scored_sorted = sorted(pos_scored, key=lambda x: x[1], reverse=True)
    top_fp = [d for d, _ in neg_scored_sorted[:10]]
    top_tp = [d for d, _ in pos_scored_sorted[:10]]

    return {
        "parameter": "dga_threshold",
        "optimal_value": float(optimal),
        "method": "roc_optimal",
        "metrics": {
            "tpr_at_optimal": float(sel_metrics["tpr"]),
            "fpr_at_optimal": float(sel_metrics["fpr"]),
            "f1_at_optimal": float(sel_metrics["f1"]),
            "auroc": float(auroc),
        },
        "details": {
            "negative_corpus_size": len(negative_domains),
            "positive_corpus_size": len(positive_domains),
            "lookback_days": int(lookback_days),
            "target_fpr": float(target_fpr),
            "fpr_curve": [
                (float(t), float(fpr), float(tpr), float(f1))
                for (t, fpr, tpr, f1) in curve
            ],
            "top_legitimate_false_positives": top_fp,
            "top_dga_true_positives": top_tp,
        },
    }


# ---------------------------------------------------------------------------
# NXDOMAIN-rate threshold calibration
# ---------------------------------------------------------------------------


def calibrate_nxdomain_rate_threshold(
    findings_conn: sqlite3.Connection,
    *,
    lookback_days: int = 7,
    floor: float = 0.20,
    ceiling: float = 0.50,
) -> dict[str, Any]:
    """Set the NXDOMAIN-rate threshold to the 95th percentile of observed
    per-client NXDOMAIN rates from the baselines table, clamped to
    [floor, ceiling].

    ``lookback_days`` is informational here -- baselines are EWMAs without
    a date column. The output records the value for traceability.
    """
    rows = list(
        findings_conn.execute(
            "SELECT client_ip, nxdomain_rate_ewma, sample_count FROM baselines"
        )
    )
    rates = [
        float(r["nxdomain_rate_ewma"])
        for r in rows
        if int(r["sample_count"] or 0) >= 1
    ]

    if not rates:
        # No baseline data yet -- fall back to default and surface that.
        return {
            "parameter": "nxdomain_rate_threshold",
            "optimal_value": float(DEFAULT_NXDOMAIN_RATE_THRESHOLD),
            "method": "default",
            "metrics": {
                "sample_size": 0,
                "p95": None,
                "floor": floor,
                "ceiling": ceiling,
            },
            "details": {
                "lookback_days": int(lookback_days),
                "reason": "no baseline rows available",
            },
        }

    p95 = _percentile(rates, 95.0)
    clamped = max(floor, min(ceiling, p95))
    return {
        "parameter": "nxdomain_rate_threshold",
        "optimal_value": float(clamped),
        "method": "percentile",
        "metrics": {
            "sample_size": len(rates),
            "p50": _percentile(rates, 50.0),
            "p95": p95,
            "p99": _percentile(rates, 99.0),
            "floor": floor,
            "ceiling": ceiling,
        },
        "details": {
            "lookback_days": int(lookback_days),
            "rate_min": min(rates),
            "rate_max": max(rates),
            "rate_mean": statistics.fmean(rates),
        },
    }


# ---------------------------------------------------------------------------
# Beacon CV threshold calibration
# ---------------------------------------------------------------------------


def _client_ip_of(q: dict) -> str | None:
    client = q.get("client") or {}
    ip = client.get("ip")
    return ip if isinstance(ip, str) and ip else None


def calibrate_beacon_cv_threshold(
    pihole_client: Any,
    *,
    lookback_hours: int = 24,
    min_pairs: int = 6,
    floor: float = 0.10,
    ceiling: float = 0.20,
    queries_override: list[dict] | None = None,
) -> dict[str, Any]:
    """Set the beacon CV threshold to the 5th percentile of observed CVs of
    naturally-occurring (client, domain) groups, clamped to [floor, ceiling].

    Groups with fewer than ``min_pairs`` query pairs to a single domain are
    skipped (they don't yield a stable CV). ``min_pairs=6`` matches the
    runtime detector default.
    """
    if queries_override is not None:
        queries = list(queries_override)
    else:
        until = time.time()
        since = until - lookback_hours * 3600.0
        queries = pihole_client.fetch_queries(since, until_unix=until)

    groups: dict[tuple[str, str], list[float]] = {}
    for q in queries:
        ip = _client_ip_of(q)
        d = q.get("domain")
        t = q.get("time")
        if (
            ip is None
            or not isinstance(d, str)
            or not isinstance(t, (int, float))
        ):
            continue
        groups.setdefault((ip, d), []).append(float(t))

    cvs: list[float] = []
    for times in groups.values():
        if len(times) < min_pairs:
            continue
        times.sort()
        intervals = [b - a for a, b in zip(times, times[1:])]
        if not intervals or any(i <= 0 for i in intervals):
            continue
        cv = _coef_of_variation(intervals)
        if cv is None:
            continue
        cvs.append(float(cv))

    if not cvs:
        return {
            "parameter": "beacon_cv_threshold",
            "optimal_value": float(DEFAULT_BEACON_CV_THRESHOLD),
            "method": "default",
            "metrics": {
                "sample_size": 0,
                "p5": None,
                "floor": floor,
                "ceiling": ceiling,
            },
            "details": {
                "lookback_hours": int(lookback_hours),
                "min_pairs": int(min_pairs),
                "reason": (
                    "no (client, domain) groups with enough samples"
                ),
            },
        }

    p5 = _percentile(cvs, 5.0)
    clamped = max(floor, min(ceiling, p5))
    return {
        "parameter": "beacon_cv_threshold",
        "optimal_value": float(clamped),
        "method": "percentile",
        "metrics": {
            "sample_size": len(cvs),
            "p5": p5,
            "p25": _percentile(cvs, 25.0),
            "p50": _percentile(cvs, 50.0),
            "floor": floor,
            "ceiling": ceiling,
        },
        "details": {
            "lookback_hours": int(lookback_hours),
            "min_pairs": int(min_pairs),
            "cv_min": min(cvs),
            "cv_max": max(cvs),
            "cv_mean": statistics.fmean(cvs),
        },
    }


# ---------------------------------------------------------------------------
# Volume-sigma threshold calibration
# ---------------------------------------------------------------------------


def calibrate_volume_sigma_threshold(
    findings_conn: sqlite3.Connection,
    *,
    lookback_days: int = 7,
    floor: float = 3.0,
    ceiling: float = 10.0,
) -> dict[str, Any]:
    """Set the volume-sigma threshold to the 99th percentile of historical
    volume_anomaly deviations, clamped to [floor, ceiling].

    The score column on volume_anomaly findings stores the pseudo-sigma
    deviation that triggered the alert.
    """
    rows = list(
        findings_conn.execute(
            "SELECT score FROM findings "
            "WHERE finding_type = 'volume_anomaly' "
            "AND detected_at >= datetime('now', ?)",
            (f"-{int(lookback_days)} days",),
        )
    )
    sigmas = [
        abs(float(r["score"]))
        for r in rows
        if r["score"] is not None
    ]

    if not sigmas:
        return {
            "parameter": "volume_sigma_threshold",
            "optimal_value": float(DEFAULT_VOLUME_SIGMA_THRESHOLD),
            "method": "default",
            "metrics": {
                "sample_size": 0,
                "p99": None,
                "floor": floor,
                "ceiling": ceiling,
            },
            "details": {
                "lookback_days": int(lookback_days),
                "reason": "no historical volume_anomaly findings",
            },
        }

    p99 = _percentile(sigmas, 99.0)
    clamped = max(floor, min(ceiling, p99))
    return {
        "parameter": "volume_sigma_threshold",
        "optimal_value": float(clamped),
        "method": "percentile",
        "metrics": {
            "sample_size": len(sigmas),
            "p50": _percentile(sigmas, 50.0),
            "p95": _percentile(sigmas, 95.0),
            "p99": p99,
            "floor": floor,
            "ceiling": ceiling,
        },
        "details": {
            "lookback_days": int(lookback_days),
            "sigma_min": min(sigmas),
            "sigma_max": max(sigmas),
            "sigma_mean": statistics.fmean(sigmas),
        },
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _percentile(values: Iterable[float], pct: float) -> float:
    """Linear-interpolated percentile in [0, 100]. Empty input -> 0.0."""
    arr = sorted(float(v) for v in values)
    if not arr:
        return 0.0
    if pct <= 0:
        return arr[0]
    if pct >= 100:
        return arr[-1]
    k = (pct / 100.0) * (len(arr) - 1)
    lo = int(k)
    hi = min(lo + 1, len(arr) - 1)
    frac = k - lo
    return arr[lo] * (1 - frac) + arr[hi] * frac


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def calibrate_all(
    pihole_client: Any,
    findings_conn: sqlite3.Connection,
    *,
    lookback_days: int = 7,
    n_synthetic_dga: int = 2000,
    target_fpr: float = 0.02,
    beacon_lookback_hours: int = 24,
) -> dict[str, dict[str, Any]]:
    """Run every calibration and persist results to the calibration table.

    Returns ``{parameter: result_dict}``. Each result is also written to
    the ``calibration`` table (with history) before being returned.
    """
    results: dict[str, dict[str, Any]] = {}

    log.info("calibrating dga_threshold (lookback=%d days)", lookback_days)
    dga_res = calibrate_dga_threshold(
        pihole_client,
        findings_conn,
        lookback_days=lookback_days,
        n_synthetic_dga=n_synthetic_dga,
        target_fpr=target_fpr,
    )
    findings_db.set_calibration(
        findings_conn,
        parameter=dga_res["parameter"],
        value=dga_res["optimal_value"],
        method=dga_res["method"],
        metrics=dga_res["metrics"],
        details=_strip_curve_for_storage(dga_res["details"]),
    )
    results[dga_res["parameter"]] = dga_res

    log.info("calibrating nxdomain_rate_threshold")
    nx_res = calibrate_nxdomain_rate_threshold(
        findings_conn, lookback_days=lookback_days
    )
    findings_db.set_calibration(
        findings_conn,
        parameter=nx_res["parameter"],
        value=nx_res["optimal_value"],
        method=nx_res["method"],
        metrics=nx_res["metrics"],
        details=nx_res["details"],
    )
    results[nx_res["parameter"]] = nx_res

    log.info("calibrating beacon_cv_threshold")
    beacon_res = calibrate_beacon_cv_threshold(
        pihole_client, lookback_hours=beacon_lookback_hours
    )
    findings_db.set_calibration(
        findings_conn,
        parameter=beacon_res["parameter"],
        value=beacon_res["optimal_value"],
        method=beacon_res["method"],
        metrics=beacon_res["metrics"],
        details=beacon_res["details"],
    )
    results[beacon_res["parameter"]] = beacon_res

    log.info("calibrating volume_sigma_threshold")
    vol_res = calibrate_volume_sigma_threshold(
        findings_conn, lookback_days=lookback_days
    )
    findings_db.set_calibration(
        findings_conn,
        parameter=vol_res["parameter"],
        value=vol_res["optimal_value"],
        method=vol_res["method"],
        metrics=vol_res["metrics"],
        details=vol_res["details"],
    )
    results[vol_res["parameter"]] = vol_res

    return results


def _strip_curve_for_storage(details: dict[str, Any]) -> dict[str, Any]:
    """Trim the full ROC curve before storing it in calibration.details_json.

    Storing all 66 ROC points per calibration adds up. Keep a sparse
    sub-sample plus the head/tail so we still see curve shape in disk-side
    diagnostics. Top FP / top TP lists are preserved as-is.
    """
    out = dict(details)
    curve = out.get("fpr_curve")
    if isinstance(curve, list) and len(curve) > 16:
        # Keep every 5th point plus the endpoints
        keep_idx = set(range(0, len(curve), 5))
        keep_idx.add(0)
        keep_idx.add(len(curve) - 1)
        out["fpr_curve_sparse"] = [curve[i] for i in sorted(keep_idx)]
        del out["fpr_curve"]
    return out


__all__ = [
    "DEFAULT_DGA_THRESHOLD",
    "DEFAULT_NXDOMAIN_RATE_THRESHOLD",
    "DEFAULT_BEACON_CV_THRESHOLD",
    "DEFAULT_VOLUME_SIGMA_THRESHOLD",
    "generate_synthetic_dga",
    "collect_negative_corpus",
    "calibrate_dga_threshold",
    "calibrate_nxdomain_rate_threshold",
    "calibrate_beacon_cv_threshold",
    "calibrate_volume_sigma_threshold",
    "calibrate_all",
]
