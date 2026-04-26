"""
--------------------------------------------------------------------------------
FILE:        config.py
PATH:        ~/projects/pihole-watch/pihole_watch/config.py
DESCRIPTION: Two-layer config loader for pihole-watch.

  Layer 1 (.env)             — secrets and paths only.
  Layer 2 (dynamic_config.json) — all tuning values, hot-reloadable.

  The weekly calibrator writes Layer 2 atomically; detection cycles
  re-read Layer 2 every run, so a manual edit (A/B test, override)
  takes effect on the next 5-min tick without restart.

  Design principle: config changes never require code changes. The
  calibration_history table in findings.db remains the audit trail of
  threshold evolution; this file is the current-values SSOT.

CHANGELOG:
2026-04-25            Claude      [Feature] Initial implementation -- env-driven
                                      config with fail-loud required keys.
2026-04-26            Claude      [Feature] Add WATCH_VOLUME_SIGMA_THRESHOLD
                                      so the volume-anomaly detector can be
                                      tuned alongside the others.
2026-04-26            Claude      [Refactor] Split config: .env keeps only
                                      secrets/paths; tuning moves to
                                      dynamic_config.json. Adds atomic-write
                                      helper used by the calibrator.
--------------------------------------------------------------------------------
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import dataclass
from typing import Any

sys.path.insert(0, "/home/pistrommy/projects")

from shared.config_service import ConfigError, get, load_env, require  # noqa: E402


_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DOTENV_PATH = os.path.join(_BASE, ".env")
_DYNAMIC_CONFIG_PATH = os.path.join(_BASE, "dynamic_config.json")
_DYNAMIC_CONFIG_EXAMPLE = os.path.join(_BASE, "dynamic_config.example.json")


_TUNABLE_FIELDS: tuple[str, ...] = (
    "lookback_minutes",
    "beacon_lookback_minutes",
    "beacon_min_occurrences",
    "dga_threshold",
    "nxdomain_rate_threshold",
    "beacon_max_interval_cv",
    "volume_sigma_threshold",
)

_TRIAGE_FIELDS: tuple[str, ...] = (
    "enabled",
    "model",
    "score_min",
    "score_max",
    "max_per_run",
    "interval_hours",
    "timeout_seconds",
)


@dataclass(frozen=True)
class TriageConfig:
    """Local-LLM triage layer settings.

    interval_hours is the cadence: triage runs at most once per
    interval_hours, gated against _meta.last_triage_at. Setting it to
    0 means "every cycle" (useful for testing); 24 is daily.
    """
    enabled: bool
    model: str
    score_min: float
    score_max: float
    max_per_run: int
    interval_hours: float
    timeout_seconds: float


@dataclass(frozen=True)
class WatchConfig:
    """Frozen runtime config for the pihole-watch service.

    Layer 1 (secrets/paths from .env): pihole_url, pihole_password,
        db_path, log_path, ollama_url.
    Layer 2 (tuning from dynamic_config.json): everything else.
    """

    pihole_url: str
    pihole_password: str
    db_path: str
    log_path: str
    ollama_url: str
    lookback_minutes: int
    dga_threshold: float
    nxdomain_rate_threshold: float
    beacon_min_occurrences: int
    beacon_max_interval_cv: float
    beacon_lookback_minutes: int
    volume_sigma_threshold: float
    triage: TriageConfig


def load_dynamic_config(path: str | None = None) -> dict[str, Any]:
    """Load the JSON tuning layer.

    Falls back to dynamic_config.example.json if the live file is absent.
    Raises ConfigError on missing required keys -- never silently substitute
    a hardcoded default for a missing tuning value.
    """
    p = path or _DYNAMIC_CONFIG_PATH
    src = p
    if not os.path.exists(p):
        if not os.path.exists(_DYNAMIC_CONFIG_EXAMPLE):
            raise ConfigError(
                f"dynamic_config.json not found at {p} and example missing at "
                f"{_DYNAMIC_CONFIG_EXAMPLE}"
            )
        src = _DYNAMIC_CONFIG_EXAMPLE
    with open(src, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ConfigError(f"dynamic_config.json must be a JSON object (got {type(data).__name__})")
    missing = [k for k in _TUNABLE_FIELDS if k not in data]
    if missing:
        raise ConfigError(
            f"dynamic_config.json missing required tuning keys: {missing} (source: {src})"
        )
    return data


def write_dynamic_config(
    updates: dict[str, Any],
    path: str | None = None,
    *,
    last_calibrated_at: str | None = None,
    last_triage_at: str | None = None,
) -> dict[str, Any]:
    """Atomically merge ``updates`` into dynamic_config.json.

    Reads current JSON, merges in ``updates`` (only known tunable keys are
    accepted), writes via temp file + os.replace for crash safety. Updates
    ``_meta.last_calibrated_at`` and/or ``_meta.last_triage_at`` if
    provided -- these are operation timestamps that piggyback on the
    config file (not tuning values, but precedented by last_calibrated_at).

    Returns the new config dict (the version actually written to disk).
    Raises ConfigError on unknown keys or write failure.
    """
    p = path or _DYNAMIC_CONFIG_PATH
    unknown = set(updates) - set(_TUNABLE_FIELDS)
    if unknown:
        raise ConfigError(
            f"refused to write unknown tuning keys to dynamic_config.json: "
            f"{sorted(unknown)}"
        )

    # Read current state if it exists; otherwise seed from example.
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as fh:
            current = json.load(fh)
    elif os.path.exists(_DYNAMIC_CONFIG_EXAMPLE):
        with open(_DYNAMIC_CONFIG_EXAMPLE, "r", encoding="utf-8") as fh:
            current = json.load(fh)
    else:
        current = {"_meta": {"schema_version": 1}}

    if not isinstance(current, dict):
        raise ConfigError(
            f"dynamic_config.json must be a JSON object (got {type(current).__name__})"
        )

    current.update(updates)
    meta = current.setdefault("_meta", {})
    if isinstance(meta, dict):
        if last_calibrated_at is not None:
            meta["last_calibrated_at"] = last_calibrated_at
        if last_triage_at is not None:
            meta["last_triage_at"] = last_triage_at
    # Atomic write: tempfile in same dir, then os.replace.
    parent = os.path.dirname(os.path.abspath(p)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".dynamic_config.", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(current, fh, indent=2, sort_keys=False)
            fh.write("\n")
        os.replace(tmp, p)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    return current


def load_config(
    dotenv_path: str | None = None,
    dynamic_config_path: str | None = None,
) -> WatchConfig:
    """Load full config: secrets/paths from .env, tuning from JSON.

    Args:
        dotenv_path: Override path to a .env. Defaults to repo-root .env.
        dynamic_config_path: Override path to dynamic_config.json.

    Raises:
        ConfigError: If .env is missing PIHOLE_PASSWORD or JSON is missing
            required tuning keys.
    """
    env_path = dotenv_path or _DOTENV_PATH
    load_env(env_path, expect_key="PIHOLE_PASSWORD")

    tuning = load_dynamic_config(dynamic_config_path)

    triage_raw = tuning.get("triage")
    if not isinstance(triage_raw, dict):
        raise ConfigError(
            "dynamic_config.json missing 'triage' object (LLM triage settings)"
        )
    triage_missing = [k for k in _TRIAGE_FIELDS if k not in triage_raw]
    if triage_missing:
        raise ConfigError(
            f"dynamic_config.json triage missing keys: {triage_missing}"
        )
    triage = TriageConfig(
        enabled=bool(triage_raw["enabled"]),
        model=str(triage_raw["model"]),
        score_min=float(triage_raw["score_min"]),
        score_max=float(triage_raw["score_max"]),
        max_per_run=int(triage_raw["max_per_run"]),
        interval_hours=float(triage_raw["interval_hours"]),
        timeout_seconds=float(triage_raw["timeout_seconds"]),
    )

    return WatchConfig(
        pihole_url=get("PIHOLE_URL", "http://localhost:8080") or "http://localhost:8080",
        pihole_password=require("PIHOLE_PASSWORD"),
        db_path=get("WATCH_DB_PATH", os.path.join(_BASE, "findings.db"))
        or os.path.join(_BASE, "findings.db"),
        log_path=get("LOG_PATH", os.path.join(_BASE, "watch.log"))
        or os.path.join(_BASE, "watch.log"),
        ollama_url=get("OLLAMA_URL", "http://127.0.0.1:11434") or "http://127.0.0.1:11434",
        lookback_minutes=int(tuning["lookback_minutes"]),
        dga_threshold=float(tuning["dga_threshold"]),
        nxdomain_rate_threshold=float(tuning["nxdomain_rate_threshold"]),
        beacon_min_occurrences=int(tuning["beacon_min_occurrences"]),
        beacon_max_interval_cv=float(tuning["beacon_max_interval_cv"]),
        beacon_lookback_minutes=int(tuning["beacon_lookback_minutes"]),
        volume_sigma_threshold=float(tuning["volume_sigma_threshold"]),
        triage=triage,
    )


__all__ = [
    "WatchConfig",
    "TriageConfig",
    "load_config",
    "load_dynamic_config",
    "write_dynamic_config",
    "ConfigError",
]
