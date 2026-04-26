"""
--------------------------------------------------------------------------------
FILE:        config.py
PATH:        ~/projects/pihole-watch/pihole_watch/config.py
DESCRIPTION: SSOT config loader for pihole-watch. Reads .env via
             shared.config_service. Fail-loud on missing required values.

CHANGELOG:
2026-04-25            Claude      [Feature] Initial implementation -- env-driven
                                      config with fail-loud required keys.
2026-04-26            Claude      [Feature] Add WATCH_VOLUME_SIGMA_THRESHOLD
                                      so the volume-anomaly detector can be
                                      tuned alongside the others.
--------------------------------------------------------------------------------
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

sys.path.insert(0, "/home/pistrommy/projects")

from shared.config_service import ConfigError, get, load_env, require  # noqa: E402


_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DOTENV_PATH = os.path.join(_BASE, ".env")


@dataclass(frozen=True)
class WatchConfig:
    """Frozen runtime config for the pihole-watch service."""

    pihole_url: str
    pihole_password: str
    db_path: str
    log_path: str
    lookback_minutes: int
    dga_threshold: float
    nxdomain_rate_threshold: float
    beacon_min_occurrences: int
    beacon_max_interval_cv: float
    beacon_lookback_minutes: int
    volume_sigma_threshold: float


def load_config(dotenv_path: str | None = None) -> WatchConfig:
    """Load pihole-watch config from a .env file.

    Args:
        dotenv_path: Override path to a .env. Defaults to repo-root .env.

    Raises:
        ConfigError: If .env is missing or required keys are absent.
    """
    path = dotenv_path or _DOTENV_PATH
    load_env(path, expect_key="PIHOLE_PASSWORD")

    return WatchConfig(
        pihole_url=get("PIHOLE_URL", "http://localhost:8080") or "http://localhost:8080",
        pihole_password=require("PIHOLE_PASSWORD"),
        db_path=get("WATCH_DB_PATH", os.path.join(_BASE, "findings.db"))
        or os.path.join(_BASE, "findings.db"),
        log_path=get("LOG_PATH", os.path.join(_BASE, "watch.log"))
        or os.path.join(_BASE, "watch.log"),
        lookback_minutes=int(get("WATCH_LOOKBACK_MIN", "6") or "6"),
        dga_threshold=float(get("WATCH_DGA_THRESHOLD", "0.65") or "0.65"),
        nxdomain_rate_threshold=float(
            get("WATCH_NXDOMAIN_RATE_THRESHOLD", "0.30") or "0.30"
        ),
        beacon_min_occurrences=int(
            get("WATCH_BEACON_MIN_OCCURRENCES", "6") or "6"
        ),
        beacon_max_interval_cv=float(
            get("WATCH_BEACON_MAX_INTERVAL_CV", "0.15") or "0.15"
        ),
        beacon_lookback_minutes=int(
            get("WATCH_BEACON_LOOKBACK_MIN", "60") or "60"
        ),
        volume_sigma_threshold=float(
            get("WATCH_VOLUME_SIGMA_THRESHOLD", "3.0") or "3.0"
        ),
    )


__all__ = ["WatchConfig", "load_config", "ConfigError"]
