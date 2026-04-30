"""
--------------------------------------------------------------------------------
FILE:        discovery.py
PATH:        ~/projects/pihole-watch/pihole_watch/discovery.py
DESCRIPTION: Runtime discovery of "infrastructure" client IPs that should
             be excluded from per-client DNS analyses. Source of truth is
             whichever subsystem owns the IP (Docker daemon, etc.) — never
             a hardcoded list in this repo.

             Currently supported:
               - Docker bridge-network gateways (queried via `docker
                 network ls` + `docker network inspect`)

             ## Why discovery, not whitelist

             Whitelists rot: every new Docker network on the host is a
             new entry someone forgets to add. Docker itself knows
             exactly which IPs it owns; we ask it. The discovered list
             auto-updates whenever the host's Docker state changes,
             with no human maintenance.

             ## Cost

             ~38 ms total on Pi 5 (one `docker network ls` + one batched
             `docker network inspect`), called once per detection cycle.
             Acceptable overhead vs the ~350 ms hot-path budget.

             ## Failure modes (all silent, return empty set)

               - Docker not installed → FileNotFoundError on subprocess
               - Docker daemon not running → non-zero exit
               - User lacks docker group permission → non-zero exit
               - Slow daemon → 3 s timeout

             Each maps to "no IPs discovered" — pihole-watch then falls
             back to whatever's in `infrastructure_clients_extra` from
             the config (which may also be empty). This is the correct
             behavior on a host with no Docker at all: nothing to
             exclude, so the per-client detectors see all queries.

CHANGELOG:
2026-04-30            Claude      [Feature] Initial — Docker bridge
                                      gateway discovery via subprocess.
--------------------------------------------------------------------------------
"""

from __future__ import annotations

import json
import logging
import subprocess

log = logging.getLogger(__name__)

_DOCKER_TIMEOUT_SECONDS = 3.0


def discover_docker_bridge_gateways() -> frozenset[str]:
    """Query Docker for all bridge-network gateway IPs.

    Returns a frozenset of gateway IPs (as strings) — these are the
    addresses Docker assigns to itself as the gateway of each bridge
    network it creates. They are infrastructure by definition: every
    container on a given bridge network appears (to the host) to send
    its DNS queries through the bridge gateway, which means a single
    gateway IP aggregates traffic from N containers and false-positives
    on per-client volume / NXDOMAIN / beacon analyses.

    Returns ``frozenset()`` if Docker isn't installed, isn't running,
    isn't accessible, or returns garbage. The caller should treat the
    empty case as "no Docker infrastructure to exclude."
    """
    try:
        ls = subprocess.run(
            ["docker", "network", "ls", "--filter", "driver=bridge",
             "--format", "{{.ID}}"],
            capture_output=True, text=True,
            timeout=_DOCKER_TIMEOUT_SECONDS, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.debug("docker network ls unavailable: %s", e)
        return frozenset()
    if ls.returncode != 0:
        log.debug("docker network ls returned %d: %s", ls.returncode, ls.stderr.strip())
        return frozenset()

    ids = [line for line in ls.stdout.strip().split("\n") if line]
    if not ids:
        return frozenset()

    try:
        ins = subprocess.run(
            ["docker", "network", "inspect", *ids],
            capture_output=True, text=True,
            timeout=_DOCKER_TIMEOUT_SECONDS, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.debug("docker network inspect unavailable: %s", e)
        return frozenset()
    if ins.returncode != 0:
        log.debug("docker network inspect returned %d: %s",
                  ins.returncode, ins.stderr.strip())
        return frozenset()

    try:
        nets = json.loads(ins.stdout)
    except json.JSONDecodeError as e:
        log.warning("docker network inspect returned non-JSON: %s", e)
        return frozenset()

    gateways: set[str] = set()
    for net in nets:
        ipam = net.get("IPAM") or {}
        for cfg in (ipam.get("Config") or []):
            gw = cfg.get("Gateway")
            if isinstance(gw, str) and gw:
                gateways.add(gw)
    return frozenset(gateways)


def resolve_infrastructure_clients(extra: frozenset[str]) -> frozenset[str]:
    """Merge discovery results with the manual escape-hatch list from config.

    ``extra`` is whatever the operator put in
    ``dynamic_config.json::infrastructure_clients_extra`` — typically
    empty, but available for non-Docker infrastructure (a router IP,
    a smart-home hub, etc.) that auto-discovery can't see.
    """
    discovered = discover_docker_bridge_gateways()
    if discovered:
        log.info("discovered %d Docker bridge gateway(s): %s",
                 len(discovered), sorted(discovered))
    return discovered | extra


__all__ = [
    "discover_docker_bridge_gateways",
    "resolve_infrastructure_clients",
]
