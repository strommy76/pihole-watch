"""
--------------------------------------------------------------------------------
FILE:        main.py
PATH:        ~/projects/pihole-watch/pihole_watch/main.py
DESCRIPTION: pihole-watch entry point. Run as a systemd oneshot every 5 min:
             pull recent Pi-hole queries, run DGA/NXDOMAIN/volume/beacon
             analyses, persist findings, update EWMA baselines, exit 0 on
             success.

CHANGELOG:
2026-04-25            Claude      [Feature] Initial implementation.
2026-04-25            Claude      [Feature] Capture pihole_snapshots row on
                                      every run (best-effort, doesn't fail
                                      the run on snapshot error).
2026-04-26            Claude      [Feature] Read autonomous-calibration values
                                      from findings.db at startup. Env
                                      overrides win, then calibration table,
                                      then built-in defaults.
2026-04-26            Claude      [Refactor] Tuning now comes from
                                      dynamic_config.json (read fresh every
                                      cycle = effective hot-reload). Drop
                                      the calibration-table merge layer.
2026-04-26            Claude      [Feature] Best-effort LLM triage step
                                      after detection. Borderline DGA
                                      findings (score in band) get
                                      auto-classified by qwen3:4b via
                                      Ollama on loopback. Gated by
                                      cfg.triage.enabled; failures are
                                      logged and never crash the cycle.
2026-04-26            Claude      [Refactor] Move triage off the 5-min
                                      hot path. It runs as its own daily
                                      systemd timer now (cli triage-run).
                                      Detection cycle returns to ~350ms.
--------------------------------------------------------------------------------
"""

from __future__ import annotations

import logging
import os
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, "/home/pistrommy/projects")

from shared.logging_service import setup_logger  # noqa: E402

from pihole_watch.anomaly import (  # noqa: E402
    filter_infrastructure_clients,
    nxdomain_rate_per_client,
    query_volume_anomalies,
    update_baselines,
)
from pihole_watch.discovery import resolve_infrastructure_clients  # noqa: E402
from pihole_watch.api import PiHoleAPIError, PiHoleClient  # noqa: E402
from pihole_watch.beacon import detect_beacons  # noqa: E402
from pihole_watch.config import (  # noqa: E402
    load_config, load_dynamic_config, write_dynamic_config,
)
from pihole_watch.dga import dga_score  # noqa: E402
from pihole_watch import findings as findings_db  # noqa: E402
from pihole_watch import triage as triage_mod  # noqa: E402


_BLOCKED_STATUSES: frozenset[str] = frozenset({
    "GRAVITY", "DENYLIST", "REGEX", "BLACKLIST",
    "BLACKLIST_CNAME", "GRAVITY_CNAME", "DENYLIST_CNAME",
})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _triage_due(interval_hours: float, last_triage_at: str | None) -> bool:
    """True if it's time to run triage given the configured interval.

    interval_hours <= 0 means "every cycle" (testing aid). A missing or
    unparseable last_triage_at counts as never-run, so triage is due.
    """
    if interval_hours <= 0:
        return True
    if not last_triage_at:
        return True
    try:
        last = datetime.fromisoformat(last_triage_at)
    except ValueError:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    elapsed = datetime.now(timezone.utc) - last
    return elapsed.total_seconds() >= interval_hours * 3600.0


def _is_blocked(q: dict) -> bool:
    s = q.get("status")
    return isinstance(s, str) and s.upper() in _BLOCKED_STATUSES


def _severity_from_dga(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.75:
        return "medium"
    return "low"


def _severity_from_nx_rate(rate: float, total: int) -> str:
    if total < 20:
        return "info"
    if rate >= 0.70:
        return "high"
    if rate >= 0.50:
        return "medium"
    return "low"


def _severity_from_beacon(cv: float, occurrences: int) -> str:
    if cv <= 0.05 and occurrences >= 20:
        return "high"
    if cv <= 0.10:
        return "medium"
    return "low"


def main() -> int:
    cfg = load_config()
    logger = setup_logger("pihole_watch", cfg.log_path, console=True)
    logger.info(
        "pihole-watch run start (lookback=%dm beacon_lookback=%dm dga_thresh=%.2f)",
        cfg.lookback_minutes, cfg.beacon_lookback_minutes, cfg.dga_threshold,
    )

    started = time.monotonic()
    run_at = _now_iso()
    queries_seen = 0
    findings_emitted = 0
    err_msg: str | None = None
    conn = None

    try:
        conn = findings_db.connect(cfg.db_path)

        logger.info(
            "tuning loaded from dynamic_config.json: dga=%.3f nx=%.3f "
            "beacon_cv=%.3f vol_sigma=%.2f",
            cfg.dga_threshold, cfg.nxdomain_rate_threshold,
            cfg.beacon_max_interval_cv, cfg.volume_sigma_threshold,
        )

        # 1. Pull queries for the short-window analyses (DGA/NXDOMAIN/volume)
        now = time.time()
        short_since = now - cfg.lookback_minutes * 60.0
        beacon_since = now - cfg.beacon_lookback_minutes * 60.0

        client = PiHoleClient(cfg.pihole_url, cfg.pihole_password)
        client.authenticate()

        # Capture a snapshot of Pi-hole's overall metrics (best-effort —
        # any failure is logged but does not fail the run).
        try:
            snapshot = client.fetch_snapshot()
            findings_db.record_snapshot(conn, snapshot)
            logger.info(
                "snapshot recorded: total=%d blocked=%d block_rate=%.2f%%",
                snapshot["total_queries"], snapshot["blocked_queries"],
                snapshot["block_rate_pct"],
            )
        except Exception as exc:  # noqa: BLE001 -- snapshot is best-effort
            logger.warning("failed to record pihole snapshot: %s", exc)

        # Fetch the longer beacon window once and slice short window from it,
        # avoiding two round-trips against the same dataset.
        beacon_queries = client.fetch_queries(beacon_since, until_unix=now)
        short_queries = [
            q for q in beacon_queries
            if isinstance(q.get("time"), (int, float))
            and float(q["time"]) >= short_since
        ]
        queries_seen = len(short_queries)
        logger.info(
            "fetched queries: short_window=%d beacon_window=%d",
            queries_seen, len(beacon_queries),
        )

        # 2. DGA on unique non-blocked domains in short window
        unique_by_domain: dict[str, list[dict]] = {}
        for q in short_queries:
            if _is_blocked(q):
                continue
            d = q.get("domain")
            if isinstance(d, str) and d:
                unique_by_domain.setdefault(d, []).append(q)

        dga_findings = 0
        for domain, samples in unique_by_domain.items():
            score = dga_score(domain)
            if score < cfg.dga_threshold:
                continue
            # Group sample query IDs by client to surface per-client findings
            by_client: dict[str, list[int]] = {}
            for q in samples:
                ip = (q.get("client") or {}).get("ip")
                qid = q.get("id")
                if isinstance(ip, str) and isinstance(qid, int):
                    by_client.setdefault(ip, []).append(qid)
            if not by_client:
                continue
            for ip, qids in by_client.items():
                logger.warning(
                    "DGA finding: client=%s domain=%s score=%.2f samples=%d",
                    ip, domain, score, len(qids),
                )
                findings_db.record_finding(
                    conn,
                    finding_type="dga",
                    severity=_severity_from_dga(score),
                    client_ip=ip,
                    domain=domain,
                    score=float(score),
                    details={"score": score, "occurrences": len(qids)},
                    sample_queries=qids[:25],
                    detected_at=run_at,
                )
                dga_findings += 1
        findings_emitted += dga_findings

        # 3. NXDOMAIN spike per client (short window). Strip infrastructure
        # clients (Docker bridge gateways etc.) — they aggregate container
        # traffic and false-positive on per-client analyses. The set is
        # the union of (a) auto-discovered Docker bridge gateways and
        # (b) the operator's manual escape-hatch list from config. DGA
        # above is per-domain so it sees the full query stream; only
        # the per-client detectors filter.
        infrastructure_clients = resolve_infrastructure_clients(
            cfg.infrastructure_clients_extra,
        )
        endpoint_short = filter_infrastructure_clients(
            short_queries, infrastructure_clients,
        )
        endpoint_beacon = filter_infrastructure_clients(
            beacon_queries, infrastructure_clients,
        )
        nx_by_client = nxdomain_rate_per_client(endpoint_short)
        nx_findings = 0
        for ip, stats in nx_by_client.items():
            if stats["total"] < 20:
                continue
            if stats["rate"] < cfg.nxdomain_rate_threshold:
                continue
            severity = _severity_from_nx_rate(stats["rate"], stats["total"])
            logger.warning(
                "NXDOMAIN spike: client=%s rate=%.2f total=%d nx=%d",
                ip, stats["rate"], stats["total"], stats["nxdomain"],
            )
            findings_db.record_finding(
                conn,
                finding_type="nxdomain_spike",
                severity=severity,
                client_ip=ip,
                score=float(stats["rate"]),
                details={
                    "rate": stats["rate"],
                    "nxdomain": stats["nxdomain"],
                    "total": stats["total"],
                    "lookback_minutes": cfg.lookback_minutes,
                },
                detected_at=run_at,
            )
            nx_findings += 1
        findings_emitted += nx_findings

        # 4. Volume anomaly vs baseline (infrastructure clients filtered)
        baselines = findings_db.all_baseline_qps(conn)
        volume_findings = query_volume_anomalies(
            endpoint_short,
            baselines,
            window_seconds=cfg.lookback_minutes * 60.0,
            sigma_threshold=cfg.volume_sigma_threshold,
        )
        for f in volume_findings:
            logger.warning(
                "Volume anomaly: client=%s observed_qps=%.3f baseline=%.3f sigma=%.2f",
                f["client_ip"], f["observed_qps"], f["baseline_qps"],
                f["deviation_sigma"],
            )
            findings_db.record_finding(
                conn,
                finding_type="volume_anomaly",
                severity=f["severity"],
                client_ip=f["client_ip"],
                score=float(f["deviation_sigma"]),
                details={
                    "observed_qps": f["observed_qps"],
                    "baseline_qps": f["baseline_qps"],
                    "window_seconds": cfg.lookback_minutes * 60.0,
                },
                detected_at=run_at,
            )
        findings_emitted += len(volume_findings)

        # 5. Beacon detection on the longer window (infrastructure-filtered)
        beacon_findings_list = detect_beacons(
            endpoint_beacon,
            min_occurrences=cfg.beacon_min_occurrences,
            max_cv=cfg.beacon_max_interval_cv,
            lookback_minutes=cfg.beacon_lookback_minutes,
        )
        for f in beacon_findings_list:
            logger.warning(
                "Beacon: client=%s domain=%s occ=%d mean=%.1fs cv=%.3f",
                f["client_ip"], f["domain"], f["occurrences"],
                f["mean_interval_sec"], f["cv"],
            )
            findings_db.record_finding(
                conn,
                finding_type="beacon",
                severity=_severity_from_beacon(f["cv"], f["occurrences"]),
                client_ip=f["client_ip"],
                domain=f["domain"],
                score=float(f["cv"]),
                details={
                    "occurrences": f["occurrences"],
                    "mean_interval_sec": f["mean_interval_sec"],
                    "cv": f["cv"],
                    "first_seen": f["first_seen"],
                    "last_seen": f["last_seen"],
                    "lookback_minutes": cfg.beacon_lookback_minutes,
                },
                detected_at=run_at,
            )
        findings_emitted += len(beacon_findings_list)

        # 6. Update baselines on this short window (infrastructure-filtered
        # so gateway IPs don't accumulate poisoned baselines)
        update_baselines(conn, endpoint_short)

        # 7. LLM triage -- gated on cfg.triage.interval_hours so the
        # 5-min hot path stays fast. With interval_hours=24 this fires
        # roughly 1 in 288 cycles. Best-effort: a failure here logs a
        # warning and never aborts the cycle.
        if cfg.triage.enabled:
            tuning = load_dynamic_config()
            last_triage_at = (tuning.get("_meta") or {}).get("last_triage_at")
            if _triage_due(cfg.triage.interval_hours, last_triage_at):
                logger.info(
                    "triage due (interval=%.1fh, last=%s); running batch...",
                    cfg.triage.interval_hours, last_triage_at or "never",
                )
                try:
                    tcounts = triage_mod.triage_borderline_findings(
                        conn,
                        ollama_url=cfg.ollama_url,
                        model=cfg.triage.model,
                        score_min=cfg.triage.score_min,
                        score_max=cfg.triage.score_max,
                        max_per_run=cfg.triage.max_per_run,
                        timeout_seconds=cfg.triage.timeout_seconds,
                    )
                    logger.info(
                        "triage: considered=%d classified=%d errors=%d",
                        tcounts["considered"], tcounts["classified"],
                        tcounts["errors"],
                    )
                    # Stamp _meta.last_triage_at unconditionally on a
                    # completed run -- even an empty batch counts as
                    # "we checked" and resets the interval clock.
                    write_dynamic_config({}, last_triage_at=_now_iso())
                except Exception as exc:  # noqa: BLE001 -- best-effort
                    logger.warning("triage layer failed (non-fatal): %s", exc)

    except PiHoleAPIError as exc:
        err_msg = f"PiHoleAPIError: {exc}"
        logger.error("pihole-watch failed: %s", err_msg)
    except Exception as exc:  # noqa: BLE001 -- logged + re-recorded, then re-raised
        err_msg = f"{type(exc).__name__}: {exc}"
        logger.error("pihole-watch failed: %s", err_msg, exc_info=True)
    finally:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        if conn is not None:
            try:
                findings_db.record_run(
                    conn,
                    run_at=run_at,
                    queries_seen=queries_seen,
                    findings_emitted=findings_emitted,
                    elapsed_ms=elapsed_ms,
                    error=err_msg,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error("failed to record run_log: %s", exc, exc_info=True)
            finally:
                conn.close()

    if err_msg is not None:
        print(
            f"pihole-watch FAIL queries={queries_seen} findings={findings_emitted} "
            f"elapsed_ms={elapsed_ms} error={err_msg}"
        )
        return 1
    print(
        f"pihole-watch OK queries={queries_seen} findings={findings_emitted} "
        f"elapsed_ms={elapsed_ms}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
