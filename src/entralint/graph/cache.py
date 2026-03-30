"""SQLite-backed response cache for Microsoft Graph API data."""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import timedelta
from pathlib import Path

# Default cache location alongside the MSAL token cache.
DEFAULT_CACHE_DIR = Path.home() / ".entralint" / "cache"
DEFAULT_DB_NAME = "graph_cache.db"

# Endpoint-category TTL map.  Keys are substrings matched against the
# request path so e.g. "/identity/conditionalAccess/policies" matches "policies".
DEFAULT_TTL: dict[str, timedelta] = {
    "policies": timedelta(minutes=15),
    "organization": timedelta(hours=1),
    "users": timedelta(minutes=30),
    "applications": timedelta(minutes=30),
    "servicePrincipals": timedelta(minutes=30),
    "signInActivity": timedelta(hours=4),
    "auditLogs": timedelta(minutes=5),
    "roleManagement": timedelta(minutes=15),
    "oauth2PermissionGrants": timedelta(minutes=30),
    "namedLocations": timedelta(minutes=15),
    "reports": timedelta(hours=1),
}

FALLBACK_TTL = timedelta(minutes=15)


class GraphCache:
    """Per-tenant, per-endpoint response cache backed by SQLite."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._dir = cache_dir or DEFAULT_CACHE_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._dir / DEFAULT_DB_NAME
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._ensure_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------
    def _ensure_schema(self) -> None:
        self._conn.execute(
            """\
            CREATE TABLE IF NOT EXISTS responses (
                tenant_id  TEXT NOT NULL,
                endpoint   TEXT NOT NULL,
                data       TEXT NOT NULL,
                etag       TEXT,
                stored_at  REAL NOT NULL,
                PRIMARY KEY (tenant_id, endpoint)
            )"""
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get(self, tenant_id: str, endpoint: str) -> dict | list | None:
        """Return cached data if within TTL, otherwise ``None``."""
        row = self._conn.execute(
            "SELECT data, stored_at FROM responses WHERE tenant_id = ? AND endpoint = ?",
            (tenant_id, endpoint),
        ).fetchone()
        if row is None:
            return None
        data_str, stored_at = row
        ttl = self._ttl_for(endpoint)
        if time.time() - stored_at > ttl.total_seconds():
            return None
        return json.loads(data_str)

    def put(
        self,
        tenant_id: str,
        endpoint: str,
        data: dict | list,
        *,
        etag: str | None = None,
    ) -> None:
        """Store (or update) a response in the cache."""
        self._conn.execute(
            """\
            INSERT INTO responses (tenant_id, endpoint, data, etag, stored_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, endpoint)
            DO UPDATE SET data=excluded.data, etag=excluded.etag, stored_at=excluded.stored_at
            """,
            (tenant_id, endpoint, json.dumps(data), etag, time.time()),
        )
        self._conn.commit()

    def clear(self, tenant_id: str | None = None) -> int:
        """Delete cached entries. Returns number of rows deleted.

        If *tenant_id* is provided only that tenant's cache is cleared;
        otherwise all entries are removed.
        """
        if tenant_id:
            cur = self._conn.execute(
                "DELETE FROM responses WHERE tenant_id = ?", (tenant_id,)
            )
        else:
            cur = self._conn.execute("DELETE FROM responses")
        self._conn.commit()
        return cur.rowcount

    def status(self, tenant_id: str | None = None) -> list[dict]:
        """Return summary rows for cached entries."""
        if tenant_id:
            rows = self._conn.execute(
                "SELECT tenant_id, endpoint, stored_at FROM responses WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT tenant_id, endpoint, stored_at FROM responses"
            ).fetchall()

        result: list[dict] = []
        now = time.time()
        for tid, ep, stored_at in rows:
            ttl = self._ttl_for(ep)
            age = now - stored_at
            expired = age > ttl.total_seconds()
            result.append(
                {
                    "tenant_id": tid,
                    "endpoint": ep,
                    "age_seconds": int(age),
                    "ttl_seconds": int(ttl.total_seconds()),
                    "expired": expired,
                }
            )
        return result

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _ttl_for(endpoint: str) -> timedelta:
        """Pick the TTL based on which category substring appears in the endpoint."""
        for key, ttl in DEFAULT_TTL.items():
            if key.lower() in endpoint.lower():
                return ttl
        return FALLBACK_TTL
