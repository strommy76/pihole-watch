"""
--------------------------------------------------------------------------------
FILE:        triage.py
PATH:        ~/projects/pihole-watch/pihole_watch/triage.py
DESCRIPTION: Local-LLM triage layer for borderline DGA findings.

  The heuristic DGA scorer (dga.py) produces a confidence in [0.0, 1.0].
  Findings above the calibrated threshold get flagged. The borderline
  band (default 0.65-0.85) is where the heuristic is least confident
  and where an LLM that knows what real cloud/CDN/tracker hostnames
  look like can add the most value.

  This module:
    - reads pending DGA findings whose score falls in the borderline band
    - calls a local Ollama instance with a structured JSON schema asking
      "is this domain a likely DGA, a legitimate domain, or unclear?"
    - writes the LLM's classification into the existing triage_outcome
      column (confirmed / false_positive / ignored) using the same DAO
      a human operator would use

  Failure modes (Ollama down, parse error, timeout) leave the finding
  pending and log a warning -- never crash the detection cycle.

CHANGELOG:
2026-04-26            Claude      [Feature] Initial implementation. Targets
                                      qwen3:4b on Pi 5 via Ollama loopback.
--------------------------------------------------------------------------------
"""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

import requests

from pihole_watch import findings as findings_db

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------


_SYSTEM = (
    "Classify a single domain. Output ONLY one JSON object — no prose, "
    "no markdown, no <think> blocks, no explanation outside the JSON.\n"
    "Classes:\n"
    "  dga: random-looking, no real word/brand/hash pattern.\n"
    "  legitimate: known cloud/CDN/tracker/SaaS/brand.\n"
    "  unclear: not enough signal.\n"
    "Keep rationale under 100 characters. One short sentence."
)

_USER_TEMPLATE = (
    "Domain: {domain}\n"
    "Heuristic DGA score: {score:.2f} (1.0 = certain DGA)\n"
    "Sample query count from this client in the last 6 minutes: {samples}\n"
    "Classify."
)


_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "classification": {
            "type": "string",
            "enum": ["dga", "legitimate", "unclear"],
        },
        "rationale": {"type": "string", "maxLength": 100},
    },
    "required": ["classification", "rationale"],
}


# Map the LLM's three classes -> the four triage outcomes used by the DAO.
# The human-only 'ignored' state is kept human-only; the LLM uses 'unclear'
# which we leave as 'pending' so a human still gets the chance to look.
_CLASSIFICATION_TO_OUTCOME: dict[str, str | None] = {
    "dga":          "confirmed",
    "legitimate":   "false_positive",
    "unclear":      None,         # leave pending
}


# ---------------------------------------------------------------------------
# Ollama client
# ---------------------------------------------------------------------------


class OllamaError(RuntimeError):
    """Anything Ollama-related that we want to surface to the operator."""


def classify_domain(
    domain: str,
    score: float,
    samples: int,
    *,
    ollama_url: str,
    model: str,
    timeout_seconds: float = 90.0,
) -> dict[str, str]:
    """Send a single domain to Ollama, get back {classification, rationale}.

    Raises OllamaError on network / parse / schema failure.
    """
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": _USER_TEMPLATE.format(
                domain=domain, score=score, samples=samples,
            )},
        ],
        "format": _RESPONSE_SCHEMA,
        "stream": False,
        # Disable qwen3-style thinking blocks. Without this, the model
        # burns its token budget on hidden chain-of-thought before any
        # JSON content. Ollama 0.21+ surfaces this as a top-level field.
        "think": False,
        "options": {
            "temperature": 0.0,   # deterministic — we want repeatable triage
            "num_predict": 120,   # 1 short rationale fits in <=100 tokens
        },
    }
    try:
        resp = requests.post(
            f"{ollama_url.rstrip('/')}/api/chat",
            json=payload,
            timeout=timeout_seconds,
        )
    except requests.RequestException as exc:
        raise OllamaError(f"network error talking to Ollama: {exc}") from exc

    if resp.status_code != 200:
        raise OllamaError(
            f"Ollama returned HTTP {resp.status_code}: {resp.text[:200]}"
        )

    try:
        body = resp.json()
        content = body["message"]["content"]
        parsed = json.loads(content)
    except (KeyError, ValueError) as exc:
        raise OllamaError(
            f"Ollama returned non-JSON or unexpected shape: {exc} body={resp.text[:200]}"
        ) from exc

    cls = parsed.get("classification")
    if cls not in _CLASSIFICATION_TO_OUTCOME:
        raise OllamaError(
            f"Ollama returned unknown classification {cls!r} (must be in "
            f"{sorted(_CLASSIFICATION_TO_OUTCOME)})"
        )
    rationale = str(parsed.get("rationale") or "")[:140]
    return {"classification": cls, "rationale": rationale}


# ---------------------------------------------------------------------------
# Borderline finding selection
# ---------------------------------------------------------------------------


def borderline_pending_findings(
    conn: sqlite3.Connection,
    *,
    score_min: float,
    score_max: float,
    limit: int,
) -> list[dict[str, Any]]:
    """Return up to ``limit`` pending DGA findings whose score falls in
    the borderline band [score_min, score_max].

    Newest first so we triage the freshest signal before older noise.
    """
    rows = conn.execute(
        "SELECT id, domain, score, sample_queries FROM findings "
        "WHERE finding_type = 'dga' "
        "  AND COALESCE(triage_outcome, 'pending') = 'pending' "
        "  AND score >= ? AND score < ? "
        "ORDER BY detected_at DESC, id DESC LIMIT ?",
        (float(score_min), float(score_max), int(limit)),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        sample_count = 0
        if r["sample_queries"]:
            try:
                samples = json.loads(r["sample_queries"])
                if isinstance(samples, list):
                    sample_count = len(samples)
            except (TypeError, ValueError):
                sample_count = 0
        out.append({
            "id": int(r["id"]),
            "domain": r["domain"],
            "score": float(r["score"]),
            "samples": sample_count,
        })
    return out


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def triage_borderline_findings(
    conn: sqlite3.Connection,
    *,
    ollama_url: str,
    model: str,
    score_min: float,
    score_max: float,
    max_per_cycle: int,
    timeout_seconds: float = 90.0,
) -> dict[str, int]:
    """Triage pending borderline DGA findings via Ollama.

    Returns counts: {"considered": N, "classified": M, "errors": E}.

    Per-finding errors are logged and skipped -- one failure does not
    halt the rest of the batch. The detection cycle treats this whole
    function as best-effort.
    """
    candidates = borderline_pending_findings(
        conn,
        score_min=score_min, score_max=score_max,
        limit=max_per_cycle,
    )
    counts = {"considered": len(candidates), "classified": 0, "errors": 0}
    if not candidates:
        return counts

    for c in candidates:
        try:
            result = classify_domain(
                c["domain"], c["score"], c["samples"],
                ollama_url=ollama_url, model=model,
                timeout_seconds=timeout_seconds,
            )
        except OllamaError as exc:
            log.warning(
                "triage failed for finding #%d (%s): %s",
                c["id"], c["domain"], exc,
            )
            counts["errors"] += 1
            continue

        outcome = _CLASSIFICATION_TO_OUTCOME[result["classification"]]
        if outcome is None:
            log.info(
                "triage: finding #%d (%s) classified UNCLEAR by %s -- "
                "leaving pending. rationale: %s",
                c["id"], c["domain"], model, result["rationale"],
            )
            continue

        note = f"[{model}] {result['classification']}: {result['rationale']}"
        try:
            findings_db.triage_finding(conn, c["id"], outcome, note=note)
        except ValueError as exc:
            log.warning(
                "triage DB write failed for finding #%d: %s", c["id"], exc,
            )
            counts["errors"] += 1
            continue

        counts["classified"] += 1
        log.info(
            "triage: finding #%d (%s, score=%.2f) -> %s by %s",
            c["id"], c["domain"], c["score"], outcome, model,
        )

    return counts


__all__ = [
    "OllamaError",
    "classify_domain",
    "borderline_pending_findings",
    "triage_borderline_findings",
]
