"""Calibration tests -- DGA ROC, percentile heuristics, persistence, history."""

from __future__ import annotations

import os
import random
import statistics
import tempfile

import pytest

from pihole_watch import calibrate as cal_mod
from pihole_watch import findings as findings_db
from pihole_watch.dga import dga_score


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


class FakePiHoleClient:
    """Minimal stub satisfying the bits calibrate.py exercises."""

    def __init__(self, queries: list[dict]) -> None:
        self.queries = queries

    def fetch_queries(
        self,
        since_unix: float,
        until_unix: float | None = None,
        *,
        page_length: int = 10000,
        max_pages: int = 200,
    ) -> list[dict]:
        return list(self.queries)


def _make_query(domain: str, ip: str = "10.0.0.1", *, t: float = 1.0,
                blocked: bool = False, qid: int = 0) -> dict:
    status = "GRAVITY" if blocked else "FORWARDED"
    return {
        "id": qid,
        "time": float(t),
        "domain": domain,
        "client": {"ip": ip, "name": None},
        "status": status,
        "type": "A",
        "reply": {"type": "IP"},
    }


# ---------------------------------------------------------------------------
# Synthetic DGA generator
# ---------------------------------------------------------------------------


def test_generate_synthetic_dga_count_and_unique() -> None:
    out = cal_mod.generate_synthetic_dga(n=200, seed=1234)
    assert len(out) >= 180  # dedupe loss is minor
    assert len(set(out)) == len(out)
    # Every entry has a TLD
    for d in out:
        assert "." in d
        assert all(ch.isalnum() or ch in ".-" for ch in d)


def test_generate_synthetic_dga_seeded_repeatable() -> None:
    a = cal_mod.generate_synthetic_dga(n=100, seed=42)
    b = cal_mod.generate_synthetic_dga(n=100, seed=42)
    assert a == b


def test_generate_synthetic_dga_high_entropy_majority() -> None:
    """Most synthetic DGAs should score above the heuristic threshold of 0.65."""
    samples = cal_mod.generate_synthetic_dga(n=500, seed=42)
    high = sum(1 for d in samples if dga_score(d) > 0.5)
    # Pseudoword style is intentionally English-like; allow some leakage but
    # the bulk should be well above 0.5.
    assert high / len(samples) >= 0.55, (high, len(samples))


def test_synthetic_distinct_from_legit_domains() -> None:
    """Legitimate domains should rarely score where DGAs cluster."""
    legit = [
        "google.com", "github.com", "stripe.com", "wikipedia.org",
        "amazon.com", "youtube.com", "cloudflare.com", "duckduckgo.com",
        "claude.ai", "openai.com", "apple.com", "microsoft.com",
        "anthropic.com", "stackoverflow.com",
    ]
    legit_high = sum(1 for d in legit if dga_score(d) > 0.5)
    assert legit_high == 0, (
        [(d, dga_score(d)) for d in legit if dga_score(d) > 0.5]
    )


# ---------------------------------------------------------------------------
# ROC curve correctness
# ---------------------------------------------------------------------------


def test_roc_curve_perfect_separation() -> None:
    # Negatives all at 0.1, positives all at 0.9 -> perfect split at any
    # threshold in (0.1, 0.9].
    neg = [0.1] * 100
    pos = [0.9] * 100
    curve = cal_mod._roc_curve(neg, pos, lo=0.30, hi=0.95, step=0.05)
    assert len(curve) > 0
    for thr, fpr, tpr, f1 in curve:
        if 0.10 < thr <= 0.90:
            assert fpr == 0.0
            assert tpr == 1.0
            assert f1 == pytest.approx(1.0, abs=1e-6)


def test_roc_select_optimal_meets_target() -> None:
    # Build a curve where threshold 0.50 has fpr=0.01, tpr=0.95 (best
    # feasible at fpr <= 0.02). Make 0.40 fpr=0.05 (infeasible), 0.60
    # fpr=0.005 tpr=0.80.
    curve = [
        (0.40, 0.05, 0.99, 0.7),
        (0.50, 0.01, 0.95, 0.92),
        (0.60, 0.005, 0.80, 0.85),
    ]
    thr, metrics = cal_mod._select_optimal_threshold(curve, target_fpr=0.02)
    assert thr == 0.50
    assert metrics["tpr"] == 0.95
    assert metrics["fpr"] == 0.01


def test_roc_select_optimal_fallback_when_target_unmet() -> None:
    # All thresholds exceed target_fpr; phase-2 should pick the lowest FPR
    # whose TPR >= 0.5.
    curve = [
        (0.30, 0.30, 0.99, 0.5),
        (0.50, 0.10, 0.80, 0.7),
        (0.70, 0.08, 0.55, 0.65),
        (0.90, 0.05, 0.10, 0.15),
    ]
    thr, metrics = cal_mod._select_optimal_threshold(curve, target_fpr=0.02)
    assert thr == 0.70  # lowest FPR among TPR>=0.5
    assert metrics["fpr"] == 0.08
    assert metrics["tpr"] == 0.55


def test_roc_tie_break_prefers_higher_threshold() -> None:
    """When TPR is identical at multiple feasible thresholds, prefer the
    higher (more conservative) one."""
    curve = [
        (0.40, 0.01, 0.90, 0.85),
        (0.50, 0.01, 0.90, 0.86),
        (0.60, 0.01, 0.90, 0.87),
    ]
    thr, _ = cal_mod._select_optimal_threshold(curve, target_fpr=0.02)
    assert thr == 0.60


def test_auroc_perfect_separation() -> None:
    auc = cal_mod._auroc(negative_scores=[0.0] * 100, positive_scores=[1.0] * 100)
    assert auc == 1.0


def test_auroc_random_is_around_half() -> None:
    rng = random.Random(7)
    neg = [rng.random() for _ in range(500)]
    pos = [rng.random() for _ in range(500)]
    auc = cal_mod._auroc(neg, pos)
    assert 0.40 < auc < 0.60


# ---------------------------------------------------------------------------
# DGA threshold calibration
# ---------------------------------------------------------------------------


def test_calibrate_dga_threshold_runs_and_returns_shape(db) -> None:
    legit = [
        "google.com", "github.com", "youtube.com", "wikipedia.org",
        "stackoverflow.com", "duckduckgo.com", "anthropic.com",
        "claude.ai", "stripe.com", "openai.com", "amazon.com",
        "apple.com", "cloudflare.com", "microsoft.com",
    ] * 5  # 70 entries
    # Use override path so we don't need a real client
    res = cal_mod.calibrate_dga_threshold(
        pihole_client=None,
        findings_conn=db,
        lookback_days=7,
        n_synthetic_dga=300,
        target_fpr=0.02,
        negative_corpus_override=legit,
    )
    assert res["parameter"] == "dga_threshold"
    assert 0.30 <= res["optimal_value"] <= 0.95
    assert res["method"] == "roc_optimal"
    m = res["metrics"]
    assert {"tpr_at_optimal", "fpr_at_optimal", "f1_at_optimal", "auroc"} <= set(m)
    d = res["details"]
    assert d["negative_corpus_size"] == len(legit)
    assert d["positive_corpus_size"] >= 250
    assert isinstance(d["fpr_curve"], list) and len(d["fpr_curve"]) > 30
    assert isinstance(d["top_legitimate_false_positives"], list)
    assert isinstance(d["top_dga_true_positives"], list)


def test_calibrate_dga_threshold_empty_negative_raises(db) -> None:
    with pytest.raises(RuntimeError, match="negative corpus is empty"):
        cal_mod.calibrate_dga_threshold(
            pihole_client=None,
            findings_conn=db,
            n_synthetic_dga=50,
            negative_corpus_override=[],
        )


# ---------------------------------------------------------------------------
# Negative corpus filtering
# ---------------------------------------------------------------------------


def test_collect_negative_corpus_excludes_blocked() -> None:
    queries = [
        _make_query("good.com", t=1.0, blocked=False, qid=1),
        _make_query("good.com", t=2.0, blocked=False, qid=2),
        _make_query("doubleclick.net", t=3.0, blocked=True, qid=3),
        _make_query("ads.example.com", t=4.0, blocked=True, qid=4),
        _make_query("github.com", t=5.0, blocked=False, qid=5),
    ]
    client = FakePiHoleClient(queries)
    out = cal_mod.collect_negative_corpus(client, lookback_days=1)
    assert "good.com" in out
    assert "github.com" in out
    assert "doubleclick.net" not in out
    assert "ads.example.com" not in out


# ---------------------------------------------------------------------------
# NXDOMAIN-rate calibration
# ---------------------------------------------------------------------------


def test_calibrate_nxdomain_rate_with_known_distribution(db) -> None:
    # Seed 100 baselines with known NX rates.
    rates = [i / 100.0 for i in range(100)]  # 0.00..0.99
    for i, r in enumerate(rates):
        findings_db.set_baseline(
            db,
            client_ip=f"10.0.0.{i}",
            qps_ewma=1.0,
            nxdomain_rate_ewma=r,
            last_updated="2026-04-25T00:00:00+00:00",
            sample_count=10,
        )
    res = cal_mod.calibrate_nxdomain_rate_threshold(db, lookback_days=7)
    # p95 of 0..0.99 step 0.01 is ~0.94 -> clamped to ceiling 0.50
    assert res["method"] == "percentile"
    assert res["optimal_value"] == 0.50
    assert res["metrics"]["sample_size"] == 100


def test_calibrate_nxdomain_rate_floor_when_traffic_clean(db) -> None:
    # All baselines clean (rate 0.0) -> p95 = 0.0 -> floor 0.20
    for i in range(20):
        findings_db.set_baseline(
            db,
            client_ip=f"10.0.0.{i}",
            qps_ewma=1.0,
            nxdomain_rate_ewma=0.0,
            last_updated="2026-04-25T00:00:00+00:00",
            sample_count=5,
        )
    res = cal_mod.calibrate_nxdomain_rate_threshold(db, lookback_days=7)
    assert res["optimal_value"] == 0.20


def test_calibrate_nxdomain_rate_no_baselines_returns_default(db) -> None:
    res = cal_mod.calibrate_nxdomain_rate_threshold(db, lookback_days=7)
    assert res["method"] == "default"
    assert res["optimal_value"] == cal_mod.DEFAULT_NXDOMAIN_RATE_THRESHOLD


# ---------------------------------------------------------------------------
# Beacon CV calibration
# ---------------------------------------------------------------------------


def test_calibrate_beacon_cv_with_synthetic_groups() -> None:
    # 10 (client, domain) groups, each with 10 queries; varying jitter.
    # Use deterministic timing to land specific CVs.
    rng = random.Random(11)
    queries: list[dict] = []
    qid = 0
    base = 1700000000.0
    for g in range(10):
        ip = f"10.0.0.{g}"
        domain = f"site{g}.com"
        # Group g: jitter scale = (g + 1) * 0.5 seconds around 60-second period
        for k in range(10):
            jitter = rng.gauss(0.0, (g + 1) * 0.5)
            t = base + k * 60.0 + jitter
            queries.append(
                _make_query(domain, ip=ip, t=t, qid=qid)
            )
            qid += 1
    client = FakePiHoleClient(queries)
    res = cal_mod.calibrate_beacon_cv_threshold(
        client,
        lookback_hours=24,
        min_pairs=6,
        queries_override=queries,
    )
    assert res["method"] == "percentile"
    assert res["metrics"]["sample_size"] >= 5
    # The 5th percentile of CVs should be very small (the cleanest group),
    # then clamped to floor 0.10.
    assert res["optimal_value"] >= 0.10
    assert res["optimal_value"] <= 0.20


def test_calibrate_beacon_cv_skips_short_groups() -> None:
    # A single (client, domain) group with only 3 queries -- below min_pairs.
    queries = [
        _make_query("c2.example.com", ip="10.0.0.1", t=1.0, qid=1),
        _make_query("c2.example.com", ip="10.0.0.1", t=61.0, qid=2),
        _make_query("c2.example.com", ip="10.0.0.1", t=122.0, qid=3),
    ]
    client = FakePiHoleClient(queries)
    res = cal_mod.calibrate_beacon_cv_threshold(
        client,
        lookback_hours=24,
        min_pairs=6,
        queries_override=queries,
    )
    assert res["method"] == "default"
    assert res["metrics"]["sample_size"] == 0


# ---------------------------------------------------------------------------
# Volume-sigma calibration
# ---------------------------------------------------------------------------


def test_calibrate_volume_sigma_with_history(db) -> None:
    from datetime import datetime, timezone

    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    sigmas = [3.1, 3.5, 4.0, 4.5, 5.0, 6.0, 8.0, 12.0, 15.0, 20.0]
    for i, s in enumerate(sigmas):
        findings_db.record_finding(
            db,
            finding_type="volume_anomaly",
            severity="medium",
            client_ip="10.0.0.1",
            score=float(s),
            detected_at=now_iso,
        )
    res = cal_mod.calibrate_volume_sigma_threshold(db, lookback_days=7)
    assert res["method"] == "percentile"
    # p99 of [3.1..20.0] => clamped to ceiling=10.0
    assert 3.0 <= res["optimal_value"] <= 10.0
    assert res["metrics"]["sample_size"] == len(sigmas)


def test_calibrate_volume_sigma_no_history(db) -> None:
    res = cal_mod.calibrate_volume_sigma_threshold(db, lookback_days=7)
    assert res["method"] == "default"
    assert res["optimal_value"] == cal_mod.DEFAULT_VOLUME_SIGMA_THRESHOLD


# ---------------------------------------------------------------------------
# Calibration history (audit table)
# ---------------------------------------------------------------------------


def test_record_calibration_event_appends_history(db) -> None:
    rid1 = findings_db.record_calibration_event(
        db,
        parameter="dga_threshold",
        new_value=0.72,
        method="roc_optimal",
        old_value=None,
        metrics={"auroc": 0.95},
    )
    rid2 = findings_db.record_calibration_event(
        db,
        parameter="dga_threshold",
        new_value=0.68,
        method="roc_optimal",
        old_value=0.72,
        metrics={"auroc": 0.96},
    )
    assert rid2 > rid1
    history = findings_db.calibration_history(db, parameter="dga_threshold")
    assert len(history) == 2
    # newest first
    assert history[0]["new_value"] == 0.68
    assert history[0]["old_value"] == 0.72
    assert history[0]["metrics"] == {"auroc": 0.96}
    assert history[1]["new_value"] == 0.72
    assert history[1]["old_value"] is None


# ---------------------------------------------------------------------------
# Orchestrator (writes JSON + history)
# ---------------------------------------------------------------------------


def _seed_dynamic_config(path: str) -> None:
    """Drop a minimal dynamic_config.json into ``path`` for the orchestrator."""
    import json as _json
    with open(path, "w", encoding="utf-8") as fh:
        _json.dump({
            "_meta": {"schema_version": 1},
            "lookback_minutes": 6,
            "beacon_lookback_minutes": 60,
            "beacon_min_occurrences": 6,
            "dga_threshold": 0.65,
            "nxdomain_rate_threshold": 0.30,
            "beacon_max_interval_cv": 0.15,
            "volume_sigma_threshold": 3.0,
            "infrastructure_clients_extra": [],
        }, fh)


def test_calibrate_all_writes_json_and_history(db, tmp_path) -> None:
    legit = [
        "google.com", "github.com", "stackoverflow.com", "youtube.com",
        "wikipedia.org", "anthropic.com", "claude.ai", "stripe.com",
        "openai.com", "amazon.com", "apple.com", "cloudflare.com",
    ]
    queries = [
        _make_query(d, t=float(i + 1), qid=i + 1) for i, d in enumerate(legit)
    ]
    # Add a beacon-eligible group with 8 evenly-spaced queries
    base_t = 1000.0
    for k in range(8):
        queries.append(
            _make_query("beacon.example.com", ip="10.0.0.99",
                        t=base_t + k * 60.0, qid=1000 + k)
        )
    client = FakePiHoleClient(queries)
    cfg_path = str(tmp_path / "dynamic_config.json")
    _seed_dynamic_config(cfg_path)

    results = cal_mod.calibrate_all(
        client, db,
        lookback_days=7, n_synthetic_dga=200, target_fpr=0.05,
        beacon_lookback_hours=24,
        dynamic_config_path=cfg_path,
    )
    assert {
        "dga_threshold",
        "nxdomain_rate_threshold",
        "beacon_cv_threshold",
        "volume_sigma_threshold",
    } == set(results)

    # JSON now reflects calibrated values.
    import json as _json
    with open(cfg_path, "r", encoding="utf-8") as fh:
        new_cfg = _json.load(fh)
    assert new_cfg["dga_threshold"] == results["dga_threshold"]["optimal_value"]
    assert new_cfg["nxdomain_rate_threshold"] == results["nxdomain_rate_threshold"]["optimal_value"]
    # beacon_cv_threshold result -> beacon_max_interval_cv config key
    assert new_cfg["beacon_max_interval_cv"] == results["beacon_cv_threshold"]["optimal_value"]
    assert new_cfg["volume_sigma_threshold"] == results["volume_sigma_threshold"]["optimal_value"]
    assert new_cfg["_meta"]["last_calibrated_at"] is not None

    # History has one row per parameter.
    history = findings_db.calibration_history(db, limit=100)
    params_in_history = {h["parameter"] for h in history}
    assert {
        "dga_threshold",
        "nxdomain_rate_threshold",
        "beacon_cv_threshold",
        "volume_sigma_threshold",
    } == params_in_history
    # The seeded prior values become old_value entries.
    dga_h = [h for h in history if h["parameter"] == "dga_threshold"]
    assert dga_h and dga_h[0]["old_value"] == 0.65


# ---------------------------------------------------------------------------
# Percentile helper
# ---------------------------------------------------------------------------


def test_percentile_basic() -> None:
    arr = list(range(1, 101))  # 1..100
    assert cal_mod._percentile(arr, 50.0) == pytest.approx(50.5, rel=1e-6)
    assert cal_mod._percentile(arr, 95.0) == pytest.approx(95.05, rel=1e-6)
    assert cal_mod._percentile(arr, 0.0) == 1
    assert cal_mod._percentile(arr, 100.0) == 100
    assert cal_mod._percentile([], 50.0) == 0.0
