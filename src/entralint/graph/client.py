"""Microsoft Graph API client with retry, throttling, and token refresh."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from entralint.core.errors import (
    AuthenticationExpiredError,
    GraphAPIError,
    GraphThrottledError,
)
from entralint.graph.cache import GraphCache

logger = logging.getLogger(__name__)

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
MAX_RETRIES = 3


@dataclass
class GraphMetrics:
    """Lightweight counters to observe cache effectiveness and API load.

    Exposed as :attr:`GraphClient.metrics`. Values are cumulative over the
    lifetime of a single client. At ``--debug`` log level a summary is
    emitted when the client closes.
    """

    cache_hits: int = 0
    cache_misses: int = 0
    requests_sent: int = 0
    retries: int = 0
    throttled: int = 0
    elapsed_s: float = 0.0
    by_status: dict[int, int] = field(default_factory=dict)

    def record_status(self, status: int) -> None:
        self.by_status[status] = self.by_status.get(status, 0) + 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "requests_sent": self.requests_sent,
            "retries": self.retries,
            "throttled": self.throttled,
            "elapsed_s": round(self.elapsed_s, 3),
            "by_status": dict(self.by_status),
        }


class GraphClient:
    """Async Microsoft Graph API client with built-in resilience.

    Parameters
    ----------
    access_token:
        A valid Microsoft Graph bearer token.
    tenant_id:
        Tenant identifier used as the cache partition key.
        When ``None``, caching is disabled.
    no_cache:
        When ``True`` all reads bypass (and don't write to) the cache.
    offline:
        When ``True`` **only** cached data is used.  Any endpoint
        missing from the cache raises ``GraphAPIError``.
    """

    def __init__(
        self,
        access_token: str,
        *,
        tenant_id: str | None = None,
        no_cache: bool = False,
        offline: bool = False,
    ) -> None:
        self._token = access_token
        self._tenant_id = tenant_id
        self._no_cache = no_cache
        self._offline = offline
        self._cache: GraphCache | None = None
        if tenant_id and not no_cache:
            self._cache = GraphCache()
        self._client = httpx.AsyncClient(
            base_url=GRAPH_BASE_URL,
            timeout=30.0,
        )
        self.metrics = GraphMetrics()

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    async def get(self, endpoint: str, params: dict[str, str] | None = None) -> Any:
        """GET a Graph API endpoint with cache awareness, retry, and error handling."""
        # --- Cache read ---
        if self._cache and self._tenant_id:
            cached = self._cache.get(self._tenant_id, endpoint)
            if cached is not None:
                self.metrics.cache_hits += 1
                logger.debug("Cache hit for %s", endpoint)
                return cached
            self.metrics.cache_misses += 1

        # In offline mode, a cache miss is fatal.
        if self._offline:
            raise GraphAPIError(
                f"Offline mode: no cached data for {endpoint}. "
                "Run a normal scan first to populate the cache.",
            )

        last_exc: Exception | None = None
        started = time.monotonic()

        for attempt in range(MAX_RETRIES):
            self.metrics.requests_sent += 1
            if attempt > 0:
                self.metrics.retries += 1
            try:
                response = await self._client.get(
                    endpoint, headers=self._auth_headers(), params=params
                )
            except httpx.TransportError as exc:
                last_exc = exc
                wait = 2 ** attempt
                logger.warning("Transport error on %s, retrying in %ds: %s", endpoint, wait, exc)
                await asyncio.sleep(wait)
                continue

            self.metrics.record_status(response.status_code)

            if response.status_code == 200:
                data = response.json()
                self.metrics.elapsed_s += time.monotonic() - started
                # --- Cache write ---
                if self._cache and self._tenant_id:
                    self._cache.put(self._tenant_id, endpoint, data)
                return data

            if response.status_code == 401:
                raise AuthenticationExpiredError(
                    "Token expired. Run 'entralint login' to re-authenticate."
                )

            if response.status_code == 403:
                raise GraphAPIError(
                    f"Forbidden: {endpoint} — check API permissions.",
                    status_code=403,
                )

            if response.status_code == 429:
                self.metrics.throttled += 1
                retry_after = int(response.headers.get("Retry-After", "10"))
                if attempt < MAX_RETRIES - 1:
                    logger.warning("Throttled on %s, waiting %ds", endpoint, retry_after)
                    await asyncio.sleep(retry_after)
                    continue
                raise GraphThrottledError(
                    "Graph API rate limit exceeded.",
                    retry_after=retry_after,
                )

            if response.status_code in (502, 503, 504):
                wait = 2 ** attempt
                if attempt < MAX_RETRIES - 1:
                    logger.warning(
                        "Transient %d on %s, retrying in %ds",
                        response.status_code, endpoint, wait,
                    )
                    await asyncio.sleep(wait)
                    continue

            raise GraphAPIError(
                f"Graph API error: {response.status_code} {response.text}",
                status_code=response.status_code,
            )

        # All retries exhausted
        if last_exc:
            raise GraphAPIError(f"Request failed after {MAX_RETRIES} retries: {last_exc}")
        raise GraphAPIError(f"Request to {endpoint} failed after {MAX_RETRIES} retries")

    async def get_all_pages(self, endpoint: str) -> list[dict[str, Any]]:
        """Fetch all pages of a paginated Graph API response."""
        results: list[dict[str, Any]] = []
        url: str | None = endpoint

        while url:
            data = await self.get(url)
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            # Strip base URL from nextLink if present
            if url and url.startswith(GRAPH_BASE_URL):
                url = url[len(GRAPH_BASE_URL):]

        return results

    async def close(self) -> None:
        await self._client.aclose()
        if self._cache:
            self._cache.close()
        # Summarise usage once per client lifecycle at debug level.
        logger.debug("Graph client metrics: %s", self.metrics.as_dict())

    async def __aenter__(self) -> GraphClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
