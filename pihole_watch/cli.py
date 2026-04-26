"""
--------------------------------------------------------------------------------
FILE:        cli.py
PATH:        ~/projects/pihole-watch/pihole_watch/cli.py
DESCRIPTION: CLI for pihole-watch — list/triage findings, summary report,
             weekly markdown report. Uses the same findings.db as the daemon.

USAGE:
  python -m pihole_watch.cli list [--limit N] [--outcome STATUS] [--type TYPE]
  python -m pihole_watch.cli triage FINDING_ID --outcome STATUS [--note "..."]
  python -m pihole_watch.cli summary [--since YYYY-MM-DD]
  python -m pihole_watch.cli weekly-report

CHANGELOG:
2026-04-25            Claude      [Feature] Initial implementation.
2026-04-26            Claude      [Feature] Add `calibrate` and
                                      `show-calibration` subcommands for
                                      autonomous threshold tuning.
--------------------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

sys.path.insert(0, "/home/pistrommy/projects")

from pihole_watch import findings as findings_db  # noqa: E402
from pihole_watch.config import load_config  # noqa: E402
from pihole_watch import calibrate as calibrate_mod  # noqa: E402


_OUTCOMES: tuple[str, ...] = ("confirmed", "false_positive", "ignored", "pending")
_TYPES: tuple[str, ...] = ("dga", "nxdomain_spike", "volume_anomaly", "beacon")


def _connect(db_path: str | None = None) -> sqlite3.Connection:
    if db_path is None:
        cfg = load_config()
        db_path = cfg.db_path
    return findings_db.connect(db_path)


def _fmt_finding_row(row: sqlite3.Row | dict) -> str:
    """Format a single finding for the `list` command."""
    if not isinstance(row, dict):
        row = dict(row)
    score = row.get("score")
    score_s = f"{score:.3f}" if isinstance(score, (int, float)) else "-"
    domain = row.get("domain") or "-"
    return (
        f"#{row['id']:<5} {row['detected_at']:<25} "
        f"{row['finding_type']:<15} {row['severity']:<7} "
        f"{row['client_ip']:<16} {domain:<40} "
        f"score={score_s} triage={row.get('triage_outcome') or 'pending'}"
    )


# -- subcommands -------------------------------------------------------------


def cmd_list(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    where: list[str] = []
    params: list[Any] = []
    if args.outcome:
        if args.outcome not in _OUTCOMES:
            print(
                f"error: --outcome must be one of {_OUTCOMES}", file=sys.stderr
            )
            return 2
        where.append("COALESCE(triage_outcome, 'pending') = ?")
        params.append(args.outcome)
    if args.type:
        if args.type not in _TYPES:
            print(f"error: --type must be one of {_TYPES}", file=sys.stderr)
            return 2
        where.append("finding_type = ?")
        params.append(args.type)
    sql = "SELECT * FROM findings"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(int(args.limit))

    rows = list(conn.execute(sql, params))
    if not rows:
        print("(no findings)")
        return 0
    print(
        f"{'ID':<6} {'DETECTED':<25} {'TYPE':<15} {'SEV':<7} "
        f"{'CLIENT':<16} {'DOMAIN':<40} EXTRA"
    )
    for r in rows:
        print(_fmt_finding_row(r))
    return 0


def cmd_triage(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    try:
        row = findings_db.triage_finding(
            conn, args.finding_id, args.outcome, args.note
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        f"triaged finding #{row['id']}: {row['finding_type']} "
        f"client={row['client_ip']} -> {row['triage_outcome']}"
        + (f" (note: {row['triage_note']})" if row.get("triage_note") else "")
    )
    return 0


def _precision(confirmed: int, fp: int) -> float | None:
    denom = confirmed + fp
    if denom == 0:
        return None
    return confirmed / denom * 100.0


def cmd_summary(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    since_iso: str | None = None
    if args.since:
        # Accept YYYY-MM-DD; treat as midnight UTC
        try:
            dt = datetime.strptime(args.since, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
        except ValueError as exc:
            print(f"error: --since {args.since!r}: {exc}", file=sys.stderr)
            return 2
        since_iso = dt.isoformat(timespec="seconds")

    summary = findings_db.triage_summary(conn, since_iso=since_iso)
    total = sum(sum(b.values()) for b in summary.values())
    print(f"pihole-watch summary{f' since {args.since}' if args.since else ''}")
    print(f"  total findings: {total}")
    if not summary:
        print("  (no findings)")
        return 0

    print()
    header = (
        f"  {'Detector':<18} {'Confirmed':>10} {'FalsePos':>10} "
        f"{'Ignored':>10} {'Pending':>10} {'Precision':>11}"
    )
    print(header)
    print("  " + "-" * (len(header) - 2))
    for ftype in sorted(summary.keys()):
        b = summary[ftype]
        prec = _precision(b["confirmed"], b["false_positive"])
        prec_s = f"{prec:.1f}%" if prec is not None else "n/a"
        print(
            f"  {ftype:<18} {b['confirmed']:>10} {b['false_positive']:>10} "
            f"{b['ignored']:>10} {b['pending']:>10} {prec_s:>11}"
        )

    latest = findings_db.latest_snapshot(conn)
    if latest is not None:
        print()
        print("Pi-hole latest snapshot:")
        print(
            f"  at={latest['snapshot_at']} total={latest['total_queries']} "
            f"blocked={latest['blocked_queries']} "
            f"block_rate={latest['block_rate_pct']:.2f}% "
            f"cache_hit={latest['cache_hit_rate_pct']:.2f}% "
            f"active_clients={latest['active_clients']}"
        )
    return 0


def _safe_top_client_query(conn: sqlite3.Connection, since_iso: str) -> tuple[str, int] | None:
    row = conn.execute(
        "SELECT client_ip, COUNT(*) AS n FROM findings "
        "WHERE detected_at >= ? GROUP BY client_ip "
        "ORDER BY n DESC LIMIT 1",
        (since_iso,),
    ).fetchone()
    if row is None:
        return None
    return row["client_ip"], int(row["n"])


def cmd_weekly_report(
    args: argparse.Namespace, conn: sqlite3.Connection
) -> int:
    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)
    since_iso = week_ago.isoformat(timespec="seconds")

    snapshots = findings_db.snapshots_since(conn, since_iso)
    findings_rows = findings_db.list_findings_since(conn, since_iso)
    summary = findings_db.triage_summary(conn, since_iso=since_iso)

    end_label = now.date().isoformat()
    start_label = week_ago.date().isoformat()

    out: list[str] = []
    out.append(f"# pihole-watch weekly report — {start_label} → {end_label}")
    out.append("")

    # -- Pi-hole metrics -----------------------------------------------------
    out.append("## Pi-hole metrics")
    if not snapshots:
        out.append("- (no snapshots recorded in the window)")
    else:
        first = snapshots[0]
        last = snapshots[-1]
        delta = last["block_rate_pct"] - first["block_rate_pct"]
        out.append(
            f"- Block rate trend: {first['block_rate_pct']:.1f}% → "
            f"{last['block_rate_pct']:.1f}% ({delta:+.1f}pp)"
        )
        # Daily query average (use min/max totals as crude estimate)
        total_max = max(s["total_queries"] for s in snapshots)
        total_min = min(s["total_queries"] for s in snapshots)
        # If snapshots span multiple Pi-hole "days", min may reset; prefer
        # the simple average of total_queries values as a proxy.
        avg = sum(s["total_queries"] for s in snapshots) / len(snapshots)
        out.append(
            f"- Avg total_queries reading: {avg:,.0f} "
            f"(min {total_min:,}, max {total_max:,})"
        )
        # Top blocked domain (mode across snapshots)
        from collections import Counter

        blocked_counter: Counter[str] = Counter(
            s["top_blocked_domain"] for s in snapshots if s.get("top_blocked_domain")
        )
        if blocked_counter:
            dom, n = blocked_counter.most_common(1)[0]
            out.append(
                f"- Top blocked domain (week): {dom} (top in {n}/"
                f"{len(snapshots)} snapshots)"
            )
        client_counter: Counter[str] = Counter(
            s["top_querying_client"] for s in snapshots if s.get("top_querying_client")
        )
        if client_counter:
            cli, n = client_counter.most_common(1)[0]
            out.append(
                f"- Most active client: {cli} (top in {n}/"
                f"{len(snapshots)} snapshots)"
            )
    out.append("")

    # -- Findings totals -----------------------------------------------------
    total_findings = len(findings_rows)
    by_type: dict[str, int] = {}
    for r in findings_rows:
        by_type[r["finding_type"]] = by_type.get(r["finding_type"], 0) + 1
    out.append(f"## Findings emitted: {total_findings}")
    type_label = {
        "dga": "DGA",
        "nxdomain_spike": "NXDOMAIN spike",
        "volume_anomaly": "Volume anomaly",
        "beacon": "Beacon",
    }
    for ftype in ("dga", "nxdomain_spike", "volume_anomaly", "beacon"):
        out.append(f"- {type_label[ftype]}: {by_type.get(ftype, 0)}")
    out.append("")

    # -- Triage --------------------------------------------------------------
    triaged = sum(
        1
        for r in findings_rows
        if (r["triage_outcome"] or "pending") != "pending"
    )
    confirmed = sum(
        1 for r in findings_rows if (r["triage_outcome"] or "") == "confirmed"
    )
    fp = sum(
        1
        for r in findings_rows
        if (r["triage_outcome"] or "") == "false_positive"
    )
    ignored = sum(
        1 for r in findings_rows if (r["triage_outcome"] or "") == "ignored"
    )
    pending = total_findings - triaged
    pct = (triaged / total_findings * 100.0) if total_findings else 0.0
    overall_prec = _precision(confirmed, fp)
    overall_prec_s = (
        f" (precision: {overall_prec:.0f}%)" if overall_prec is not None else ""
    )
    out.append("## Triage")
    out.append(
        f"- Triaged: {triaged}/{total_findings} ({pct:.0f}%)"
    )
    out.append(f"- Confirmed threats: {confirmed}")
    out.append(f"- False positives: {fp}{overall_prec_s}")
    out.append(f"- Ignored: {ignored}")
    out.append(f"- Pending: {pending}")
    out.append("")

    # -- Per-detector precision ---------------------------------------------
    out.append("## Per-detector precision")
    if not summary:
        out.append("- (no findings)")
    else:
        for ftype in ("dga", "nxdomain_spike", "volume_anomaly", "beacon"):
            b = summary.get(ftype)
            if b is None:
                out.append(f"- {type_label[ftype]}: 0/0 (no findings)")
                continue
            denom = b["confirmed"] + b["false_positive"]
            if denom == 0:
                out.append(
                    f"- {type_label[ftype]}: {b['confirmed']}/{denom} "
                    f"(insufficient data)"
                )
                continue
            prec = b["confirmed"] / denom * 100.0
            hint = ""
            if ftype == "dga" and prec < 25 and denom >= 5:
                hint = " (consider raising WATCH_DGA_THRESHOLD)"
            out.append(
                f"- {type_label[ftype]}: {b['confirmed']}/{denom} "
                f"= {prec:.0f}%{hint}"
            )
    out.append("")

    # -- Top noisy clients ---------------------------------------------------
    client_finds: dict[str, int] = {}
    for r in findings_rows:
        client_finds[r["client_ip"]] = client_finds.get(r["client_ip"], 0) + 1
    top_clients = sorted(
        client_finds.items(), key=lambda kv: kv[1], reverse=True
    )[:5]
    out.append("## Top noisy clients (most flagged)")
    if not top_clients:
        out.append("- (none)")
    else:
        for ip, n in top_clients:
            out.append(f"- {ip}: {n} findings")
    out.append("")

    print("\n".join(out))
    return 0


# -- calibrate ---------------------------------------------------------------


_CAL_DEFAULTS: dict[str, float] = {
    "dga_threshold": calibrate_mod.DEFAULT_DGA_THRESHOLD,
    "nxdomain_rate_threshold": calibrate_mod.DEFAULT_NXDOMAIN_RATE_THRESHOLD,
    "beacon_cv_threshold": calibrate_mod.DEFAULT_BEACON_CV_THRESHOLD,
    "volume_sigma_threshold": calibrate_mod.DEFAULT_VOLUME_SIGMA_THRESHOLD,
}


def _print_dga_diag(res: dict[str, Any]) -> None:
    metrics = res.get("metrics") or {}
    details = res.get("details") or {}
    print(
        f"    metrics: tpr={metrics.get('tpr_at_optimal'):.3f} "
        f"fpr={metrics.get('fpr_at_optimal'):.3f} "
        f"f1={metrics.get('f1_at_optimal'):.3f} "
        f"auroc={metrics.get('auroc'):.3f}"
    )
    print(
        f"    corpus: negative={details.get('negative_corpus_size')} "
        f"positive={details.get('positive_corpus_size')} "
        f"target_fpr={details.get('target_fpr')}"
    )
    fps = details.get("top_legitimate_false_positives") or []
    if fps:
        print("    top legitimate FP candidates (highest-scoring real domains):")
        for d in fps[:10]:
            print(f"      - {d}")
    tps = details.get("top_dga_true_positives") or []
    if tps:
        print("    top synthetic DGA samples (highest-scoring fakes):")
        for d in tps[:5]:
            print(f"      - {d}")


def _print_percentile_diag(res: dict[str, Any]) -> None:
    metrics = res.get("metrics") or {}
    sample_size = metrics.get("sample_size")
    floor = metrics.get("floor")
    ceiling = metrics.get("ceiling")
    print(
        f"    metrics: samples={sample_size} "
        f"floor={floor} ceiling={ceiling}"
    )
    extras: list[str] = []
    for key in ("p5", "p50", "p95", "p99"):
        if key in metrics and metrics[key] is not None:
            extras.append(f"{key}={float(metrics[key]):.4f}")
    if extras:
        print("    distribution: " + " ".join(extras))


def cmd_calibrate(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    """Pull traffic, run all calibrations, store results, print summary."""
    from pihole_watch.api import PiHoleAPIError, PiHoleClient

    cfg = load_config()
    print("Running calibration ...")
    print(f"  Pi-hole URL: {cfg.pihole_url}")
    print(f"  DB:          {cfg.db_path}")
    print(f"  lookback:    {args.lookback_days} days")
    print()

    try:
        client = PiHoleClient(cfg.pihole_url, cfg.pihole_password)
        client.authenticate()
    except PiHoleAPIError as exc:
        print(f"error: Pi-hole authentication failed: {exc}", file=sys.stderr)
        return 1

    try:
        results = calibrate_mod.calibrate_all(
            client,
            conn,
            lookback_days=args.lookback_days,
            n_synthetic_dga=args.n_synthetic_dga,
            target_fpr=args.target_fpr,
            beacon_lookback_hours=args.beacon_lookback_hours,
        )
    except (PiHoleAPIError, RuntimeError) as exc:
        print(f"error: calibration failed: {exc}", file=sys.stderr)
        return 1

    print("Calibration results:")
    print()
    for param, res in results.items():
        default = _CAL_DEFAULTS.get(param)
        new = res.get("optimal_value")
        method = res.get("method")
        if isinstance(new, (int, float)) and isinstance(default, (int, float)):
            delta = new - default
            arrow = "->"
            print(
                f"  {param}: {default:.4f} {arrow} {new:.4f} "
                f"(delta {delta:+.4f}, method {method})"
            )
        else:
            print(f"  {param}: {new} (method {method})")
        if param == "dga_threshold":
            _print_dga_diag(res)
        else:
            _print_percentile_diag(res)
        print()
    print("Calibration table updated. Use `show-calibration` to view current values.")
    return 0


def cmd_show_calibration(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    """Print the current calibration values vs built-in defaults."""
    cal = findings_db.get_all_calibrations(conn)
    print(
        f"  {'parameter':<26} {'default':>10} {'current':>10} "
        f"{'method':<12} {'updated_at'}"
    )
    print("  " + "-" * 90)
    rows = 0
    for param, default in _CAL_DEFAULTS.items():
        row = cal.get(param)
        if row is None:
            print(
                f"  {param:<26} {default:>10.4f} {'(unset)':>10} "
                f"{'-':<12} -"
            )
            continue
        rows += 1
        print(
            f"  {param:<26} {default:>10.4f} {row['value']:>10.4f} "
            f"{row['method']:<12} {row['updated_at']}"
        )
    if not rows:
        print()
        print("  (no calibration recorded -- run `calibrate` to populate)")
    # Show recent history (last 10 events).
    history = findings_db.calibration_history(conn, limit=10)
    if history:
        print()
        print("Recent calibration history:")
        for h in history:
            old = (
                f"{h['old_value']:.4f}" if h["old_value"] is not None else "(none)"
            )
            print(
                f"  {h['calibrated_at']}  {h['parameter']:<26} "
                f"{old} -> {h['new_value']:.4f}  ({h['method']})"
            )
    return 0


# -- argparse plumbing -------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pihole-watch",
        description="Triage findings and view summary reports.",
    )
    parser.add_argument(
        "--db", help="Override path to findings.db (default: from .env)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="List recent findings")
    p_list.add_argument("--limit", type=int, default=20)
    p_list.add_argument("--outcome", choices=_OUTCOMES, default=None)
    p_list.add_argument("--type", choices=_TYPES, default=None)
    p_list.set_defaults(func=cmd_list)

    p_triage = sub.add_parser("triage", help="Mark a finding's outcome")
    p_triage.add_argument("finding_id", type=int)
    p_triage.add_argument(
        "--outcome", required=True, choices=_OUTCOMES
    )
    p_triage.add_argument("--note", default=None)
    p_triage.set_defaults(func=cmd_triage)

    p_sum = sub.add_parser("summary", help="Per-detector triage rollup")
    p_sum.add_argument("--since", default=None, help="YYYY-MM-DD UTC")
    p_sum.set_defaults(func=cmd_summary)

    p_week = sub.add_parser(
        "weekly-report", help="Markdown report for the last 7 days"
    )
    p_week.set_defaults(func=cmd_weekly_report)

    p_cal = sub.add_parser(
        "calibrate", help="Run autonomous threshold calibration now"
    )
    p_cal.add_argument("--lookback-days", type=int, default=7)
    p_cal.add_argument("--n-synthetic-dga", type=int, default=2000)
    p_cal.add_argument("--target-fpr", type=float, default=0.02)
    p_cal.add_argument("--beacon-lookback-hours", type=int, default=24)
    p_cal.set_defaults(func=cmd_calibrate)

    p_show = sub.add_parser(
        "show-calibration",
        help="Print current calibrated thresholds vs defaults",
    )
    p_show.set_defaults(func=cmd_show_calibration)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    conn = _connect(getattr(args, "db", None))
    try:
        return int(args.func(args, conn))
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
