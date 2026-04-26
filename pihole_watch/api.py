"""
--------------------------------------------------------------------------------
FILE:        api.py
PATH:        ~/projects/pihole-watch/pihole_watch/api.py
DESCRIPTION: Pi-hole HTTP API client. Read-only -- authenticate, fetch
             queries by time range with cursor-based pagination, fetch
             summary stats. Fail-loud on connection / auth errors; auto
             re-auth once on 401.

CHANGELOG:
2026-04-25            Claude      [Feature] Initial implementation.
2026-04-25            Claude      [Feature] Add fetch_snapshot() that combines
                                      summary + top blocked + top client into
                                      a row matching pihole_snapshots schema.
--------------------------------------------------------------------------------
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import requests

log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = (5.0, 30.0)  # (connect, read) seconds
_PAGE_LENGTH = 10000


class PiHoleAPIError(RuntimeError):
    """Raised when the Pi-hole API call fails or returns an unusable shape."""


class PiHoleClient:
    """Thin Pi-hole HTTP API client. Holds a session id, auto re-auths on 401."""

    def __init__(self, base_url: str, password: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._password = password
        self._sid: str | None = None
        self._session = requests.Session()

    # -- auth --------------------------------------------------------------------

    def authenticate(self) -> None:
        """Acquire and store a session SID. Fail-loud on any non-success."""
        url = f"{self.base_url}/api/auth"
        try:
            resp = self._session.post(
                url,
                json={"password": self._password},
                timeout=_DEFAULT_TIMEOUT,
            )
        except requests.RequestException as exc:
            raise PiHoleAPIError(f"auth request failed: {exc}") from exc

        if resp.status_code != 200:
            raise PiHoleAPIError(
                f"auth status {resp.status_code}: {resp.text[:200]}"
            )

        try:
            payload = resp.json()
        except ValueError as exc:
            raise PiHoleAPIError(f"auth response not JSON: {exc}") from exc

        session = payload.get("session") or {}
        sid = session.get("sid")
        valid = session.get("valid")
        if not valid or not sid:
            raise PiHoleAPIError(f"auth payload invalid: {payload}")
        self._sid = sid
        log.info("pihole auth ok (sid len=%d)", len(sid))

    def _headers(self) -> dict[str, str]:
        if not self._sid:
            raise PiHoleAPIError("no SID -- call authenticate() first")
        return {"X-FTL-SID": self._sid, "Accept": "application/json"}

    # -- low-level GET with one re-auth retry on 401 -----------------------------

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict:
        if self._sid is None:
            self.authenticate()
        url = f"{self.base_url}{path}"
        try:
            resp = self._session.get(
                url, headers=self._headers(), params=params, timeout=_DEFAULT_TIMEOUT
            )
        except requests.RequestException as exc:
            raise PiHoleAPIError(f"GET {path} failed: {exc}") from exc

        if resp.status_code == 401:
            log.warning("pihole 401 on %s -- re-authenticating", path)
            self._sid = None
            self.authenticate()
            try:
                resp = self._session.get(
                    url,
                    headers=self._headers(),
                    params=params,
                    timeout=_DEFAULT_TIMEOUT,
                )
            except requests.RequestException as exc:
                raise PiHoleAPIError(f"GET {path} retry failed: {exc}") from exc

        if resp.status_code != 200:
            raise PiHoleAPIError(
                f"GET {path} status {resp.status_code}: {resp.text[:200]}"
            )

        try:
            return resp.json()
        except ValueError as exc:
            raise PiHoleAPIError(f"GET {path} response not JSON: {exc}") from exc

    # -- public methods ----------------------------------------------------------

    def fetch_queries(
        self,
        since_unix: float,
        until_unix: float | None = None,
        *,
        page_length: int = _PAGE_LENGTH,
        max_pages: int = 50,
    ) -> list[dict]:
        """Pull queries in [since_unix, until_unix). Paginates via cursor.

        The Pi-hole API returns oldest-first cursor pagination via the
        ``cursor`` field on the response. To request the next page we pass
        ``cursor`` of the last item to ``cursor`` parameter. We stop when the
        page is shorter than the requested length or when we've collected the
        full ``recordsTotal``.
        """
        params: dict[str, Any] = {"from": int(since_unix), "length": page_length}
        if until_unix is not None:
            params["until"] = int(until_unix)

        all_queries: list[dict] = []
        seen_ids: set[int] = set()
        last_cursor: int | None = None

        for page in range(max_pages):
            page_params = dict(params)
            if last_cursor is not None:
                page_params["cursor"] = last_cursor
            payload = self._get("/api/queries", page_params)

            queries = payload.get("queries")
            if queries is None:
                raise PiHoleAPIError(
                    f"queries response missing 'queries' key: {list(payload)[:5]}"
                )
            if not isinstance(queries, list):
                raise PiHoleAPIError(
                    f"queries field has type {type(queries).__name__}, expected list"
                )

            new_in_page = 0
            for q in queries:
                qid = q.get("id")
                if qid is not None and qid in seen_ids:
                    continue
                if qid is not None:
                    seen_ids.add(qid)
                all_queries.append(q)
                new_in_page += 1

            log.debug(
                "fetch_queries page %d: returned=%d new=%d total=%d",
                page, len(queries), new_in_page, len(all_queries),
            )

            if new_in_page == 0:
                break
            if len(queries) < page_length:
                break

            cursor = payload.get("cursor")
            if cursor is None or cursor == last_cursor:
                break
            last_cursor = cursor

        else:
            log.warning(
                "fetch_queries hit max_pages=%d; results may be truncated", max_pages
            )

        return all_queries

    def get_summary(self) -> dict:
        """Return /api/stats/summary payload."""
        return self._get("/api/stats/summary")

    def get_top_blocked_domain(self) -> tuple[str | None, int]:
        """Return (domain, count) of the most-blocked domain, or (None, 0)."""
        payload = self._get(
            "/api/stats/top_domains", {"blocked": "true", "count": 1}
        )
        items = payload.get("domains") or payload.get("top_domains") or []
        if not items:
            return None, 0
        first = items[0]
        domain = first.get("domain") if isinstance(first, dict) else None
        count = first.get("count") if isinstance(first, dict) else 0
        try:
            count = int(count or 0)
        except (TypeError, ValueError):
            count = 0
        return (domain if isinstance(domain, str) else None), count

    def get_top_querying_client(self) -> tuple[str | None, int]:
        """Return (label, count) of the most active client, or (None, 0).

        Label preference: name > ip. Pi-hole returns either ``clients`` or
        ``top_sources``-style payloads depending on version, so accept both.
        """
        payload = self._get("/api/stats/top_clients", {"count": 1})
        items = payload.get("clients") or payload.get("top_sources") or []
        if not items:
            return None, 0
        first = items[0]
        if not isinstance(first, dict):
            return None, 0
        label = first.get("name") or first.get("ip")
        count = first.get("count", 0)
        try:
            count = int(count or 0)
        except (TypeError, ValueError):
            count = 0
        return (label if isinstance(label, str) else None), count

    def fetch_snapshot(self) -> dict:
        """Combine summary + top_domains + top_clients into a snapshot dict.

        Returns a dict matching the ``pihole_snapshots`` table schema. Caller
        passes this to ``findings.record_snapshot()``. Tolerant of varying
        Pi-hole API shapes — defaults to 0 / None for missing fields.
        """
        summary = self.get_summary()
        # Pi-hole v6 puts metrics under "queries" sub-object; fall back to
        # top-level keys for older versions.
        q = summary.get("queries") if isinstance(summary, dict) else None
        if not isinstance(q, dict):
            q = summary if isinstance(summary, dict) else {}

        def _i(*keys: str) -> int:
            for k in keys:
                v = q.get(k)
                if v is None and isinstance(summary, dict):
                    v = summary.get(k)
                if isinstance(v, (int, float)):
                    return int(v)
                if isinstance(v, str) and v.replace(".", "", 1).isdigit():
                    return int(float(v))
            return 0

        total = _i("total", "dns_queries_today")
        blocked = _i("blocked", "ads_blocked_today")
        cached = _i("cached", "queries_cached")
        forwarded = _i("forwarded", "queries_forwarded")
        unique_domains = _i("unique_domains")

        # block / cache rate may be present pre-computed; fall back to compute.
        block_rate = q.get("percent_blocked")
        if block_rate is None and isinstance(summary, dict):
            block_rate = summary.get("ads_percentage_today")
        if not isinstance(block_rate, (int, float)):
            block_rate = (blocked / total * 100.0) if total > 0 else 0.0

        cache_rate = q.get("cache_hit_rate")
        if not isinstance(cache_rate, (int, float)):
            cache_rate = (cached / total * 100.0) if total > 0 else 0.0

        # active clients
        clients_obj = (
            summary.get("clients") if isinstance(summary, dict) else None
        )
        if isinstance(clients_obj, dict):
            active_clients = int(clients_obj.get("active") or 0)
        else:
            active_clients = _i("clients_ever_seen", "unique_clients")

        gravity = summary.get("gravity") if isinstance(summary, dict) else None
        if isinstance(gravity, dict):
            gravity_domains = int(gravity.get("domains_being_blocked") or 0)
        else:
            gravity_domains = _i(
                "domains_being_blocked", "gravity_domains_blocked"
            )

        try:
            top_blocked_domain, _ = self.get_top_blocked_domain()
        except PiHoleAPIError as exc:
            log.warning("top_blocked_domain fetch failed: %s", exc)
            top_blocked_domain = None
        try:
            top_querying_client, _ = self.get_top_querying_client()
        except PiHoleAPIError as exc:
            log.warning("top_querying_client fetch failed: %s", exc)
            top_querying_client = None

        snapshot_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return {
            "snapshot_at": snapshot_at,
            "total_queries": int(total),
            "blocked_queries": int(blocked),
            "cached_queries": int(cached),
            "forwarded_queries": int(forwarded),
            "block_rate_pct": float(block_rate),
            "cache_hit_rate_pct": float(cache_rate),
            "active_clients": int(active_clients),
            "unique_domains": int(unique_domains),
            "gravity_domains": int(gravity_domains),
            "top_blocked_domain": top_blocked_domain,
            "top_querying_client": top_querying_client,
        }


__all__ = ["PiHoleAPIError", "PiHoleClient"]
