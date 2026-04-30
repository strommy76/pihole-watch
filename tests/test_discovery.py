"""Discovery tests — Docker bridge gateway introspection.

We mock subprocess.run so the tests run hermetically (no real Docker
daemon required). The fast happy-path test runs against the live
daemon when present and is skipped otherwise.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from unittest import mock

import pytest

from pihole_watch.discovery import (
    discover_docker_bridge_gateways,
    resolve_infrastructure_clients,
)


# --- mocked subprocess paths ------------------------------------------------


def _fake_run(returncode: int, stdout: str = "", stderr: str = ""):
    """Build a CompletedProcess look-alike for monkeypatching."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


def test_discover_returns_empty_when_docker_missing(monkeypatch):
    """`docker` binary not installed → FileNotFoundError → empty set, no raise."""
    def raises(*a, **k):
        raise FileNotFoundError("docker")
    monkeypatch.setattr("pihole_watch.discovery.subprocess.run", raises)
    assert discover_docker_bridge_gateways() == frozenset()


def test_discover_returns_empty_on_nonzero_exit(monkeypatch):
    """Daemon down or permission denied → ls returns nonzero → empty set."""
    monkeypatch.setattr(
        "pihole_watch.discovery.subprocess.run",
        lambda *a, **k: _fake_run(1, stderr="permission denied"),
    )
    assert discover_docker_bridge_gateways() == frozenset()


def test_discover_extracts_gateways_from_inspect(monkeypatch):
    """ls returns 2 IDs → inspect returns JSON with 2 networks → 2 gateways."""
    payloads = iter([
        _fake_run(0, stdout="abc123\ndef456\n"),
        _fake_run(0, stdout=json.dumps([
            {"IPAM": {"Config": [{"Gateway": "172.17.0.1"}]}},
            {"IPAM": {"Config": [{"Gateway": "172.19.0.1"}]}},
        ])),
    ])
    monkeypatch.setattr(
        "pihole_watch.discovery.subprocess.run",
        lambda *a, **k: next(payloads),
    )
    out = discover_docker_bridge_gateways()
    assert out == frozenset({"172.17.0.1", "172.19.0.1"})


def test_discover_handles_network_with_no_ipam(monkeypatch):
    """Network without IPAM.Config (e.g. some macvlan setups) is skipped
    silently rather than erroring."""
    payloads = iter([
        _fake_run(0, stdout="abc123\n"),
        _fake_run(0, stdout=json.dumps([{"IPAM": {}}])),
    ])
    monkeypatch.setattr(
        "pihole_watch.discovery.subprocess.run",
        lambda *a, **k: next(payloads),
    )
    assert discover_docker_bridge_gateways() == frozenset()


def test_discover_returns_empty_on_garbage_json(monkeypatch):
    payloads = iter([
        _fake_run(0, stdout="abc123\n"),
        _fake_run(0, stdout="<html>not docker</html>"),
    ])
    monkeypatch.setattr(
        "pihole_watch.discovery.subprocess.run",
        lambda *a, **k: next(payloads),
    )
    assert discover_docker_bridge_gateways() == frozenset()


def test_resolve_unions_discovery_with_extra(monkeypatch):
    """resolve_infrastructure_clients returns discovered ∪ extra."""
    monkeypatch.setattr(
        "pihole_watch.discovery.discover_docker_bridge_gateways",
        lambda: frozenset({"172.17.0.1", "172.19.0.1"}),
    )
    out = resolve_infrastructure_clients(frozenset({"192.168.1.1"}))
    assert out == frozenset({"172.17.0.1", "172.19.0.1", "192.168.1.1"})


def test_resolve_falls_back_to_extra_alone_when_no_docker(monkeypatch):
    """No Docker → discovery returns empty → resolve returns just the
    operator's escape-hatch list (which itself may be empty)."""
    monkeypatch.setattr(
        "pihole_watch.discovery.discover_docker_bridge_gateways",
        lambda: frozenset(),
    )
    assert resolve_infrastructure_clients(frozenset()) == frozenset()
    assert resolve_infrastructure_clients(
        frozenset({"10.0.0.1"})) == frozenset({"10.0.0.1"})


# --- live happy-path (requires real docker daemon) --------------------------


@pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="docker binary not installed",
)
def test_discover_live_daemon_returns_dotted_quads():
    """If a real Docker daemon is reachable, discovery should return
    valid IPv4 dotted-quads (or empty if no bridges exist)."""
    result = discover_docker_bridge_gateways()
    for ip in result:
        parts = ip.split(".")
        assert len(parts) == 4, f"not an IPv4 dotted-quad: {ip!r}"
        for octet in parts:
            assert 0 <= int(octet) <= 255, f"bad octet in {ip!r}"


def test_discover_uses_subprocess_timeout():
    """Sanity: the subprocess calls pass a non-trivial timeout so a
    hung daemon can't block the 5-min hot path indefinitely."""
    with mock.patch("pihole_watch.discovery.subprocess.run") as run:
        run.return_value = _fake_run(0, "")
        discover_docker_bridge_gateways()
        # First call (network ls) — verify timeout kwarg present
        first_call = run.call_args_list[0]
        assert "timeout" in first_call.kwargs
        assert first_call.kwargs["timeout"] > 0
