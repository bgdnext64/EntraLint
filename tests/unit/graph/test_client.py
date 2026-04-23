"""Tests for the async Microsoft Graph HTTP client.

We stub ``httpx.AsyncClient.get`` via a custom handler so the tests never
perform real network I/O. Focus areas:
    - Happy path returns decoded JSON.
    - Retries / backoff on 429 (throttling) and 5xx responses.
    - Error translation (401 → AuthenticationExpiredError, 403 → GraphAPIError).
    - Pagination follows ``@odata.nextLink``.
    - Cache read/write integration.
    - Offline mode behaviour.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from entralint.core.errors import (
    AuthenticationExpiredError,
    GraphAPIError,
    GraphThrottledError,
)
from entralint.graph import client as client_mod
from entralint.graph.client import GRAPH_BASE_URL, GraphClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _ScriptedTransport(httpx.AsyncBaseTransport):
    """httpx transport that yields pre-recorded responses in order."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self._responses = list(responses)
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not self._responses:
            raise AssertionError(f"No scripted response for {request.url}")
        return self._responses.pop(0)


def _make_client(responses: list[httpx.Response], **kwargs: Any) -> tuple[GraphClient, _ScriptedTransport]:
    """Build a GraphClient with a scripted transport and no cache by default."""
    transport = _ScriptedTransport(responses)
    kwargs.setdefault("no_cache", True)
    gc = GraphClient(access_token="test-token", **kwargs)
    # Replace the internal httpx client with one using our scripted transport.
    gc._client = httpx.AsyncClient(base_url=GRAPH_BASE_URL, transport=transport)
    return gc, transport


def _json_response(status_code: int, body: dict | list, headers: dict | None = None) -> httpx.Response:
    return httpx.Response(status_code, json=body, headers=headers or {})


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Neutralize asyncio.sleep so retry loops don't actually wait."""

    async def _instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr(client_mod.asyncio, "sleep", _instant)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_returns_json_on_200():
    gc, transport = _make_client([_json_response(200, {"value": [{"id": "1"}]})])
    async with gc:
        data = await gc.get("/users")
    assert data == {"value": [{"id": "1"}]}
    assert transport.requests[0].headers["Authorization"] == "Bearer test-token"


@pytest.mark.asyncio
async def test_get_passes_query_params():
    gc, transport = _make_client([_json_response(200, {"value": []})])
    async with gc:
        await gc.get("/users", params={"$select": "id,displayName"})
    assert "%24select=id%2CdisplayName" in str(transport.requests[0].url) or \
        "$select=id,displayName" in str(transport.requests[0].url)


# ---------------------------------------------------------------------------
# Error translation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_401_raises_authentication_expired():
    gc, _ = _make_client([_json_response(401, {"error": "expired"})])
    async with gc:
        with pytest.raises(AuthenticationExpiredError):
            await gc.get("/users")


@pytest.mark.asyncio
async def test_403_raises_graph_api_error_with_status():
    gc, _ = _make_client([_json_response(403, {"error": "forbidden"})])
    async with gc:
        with pytest.raises(GraphAPIError) as excinfo:
            await gc.get("/users")
    assert excinfo.value.status_code == 403


# ---------------------------------------------------------------------------
# Retry / throttling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_429_then_success_is_retried():
    gc, transport = _make_client(
        [
            _json_response(429, {}, headers={"Retry-After": "1"}),
            _json_response(200, {"value": [1, 2, 3]}),
        ]
    )
    async with gc:
        data = await gc.get("/users")
    assert data == {"value": [1, 2, 3]}
    assert len(transport.requests) == 2


@pytest.mark.asyncio
async def test_persistent_429_raises_throttled():
    gc, _ = _make_client(
        [_json_response(429, {}, headers={"Retry-After": "1"})] * 3
    )
    async with gc:
        with pytest.raises(GraphThrottledError):
            await gc.get("/users")


@pytest.mark.asyncio
async def test_503_then_success_is_retried():
    gc, transport = _make_client(
        [
            _json_response(503, {}),
            _json_response(200, {"value": []}),
        ]
    )
    async with gc:
        data = await gc.get("/users")
    assert data == {"value": []}
    assert len(transport.requests) == 2


@pytest.mark.asyncio
async def test_persistent_5xx_raises_graph_api_error():
    gc, _ = _make_client([_json_response(503, {})] * 3)
    async with gc:
        with pytest.raises(GraphAPIError):
            await gc.get("/users")


@pytest.mark.asyncio
async def test_transport_error_retried_then_raised(monkeypatch):
    # Build a client whose transport *always* raises.
    class _BrokenTransport(httpx.AsyncBaseTransport):
        def __init__(self):
            self.calls = 0

        async def handle_async_request(self, request):
            self.calls += 1
            raise httpx.ConnectError("boom")

    transport = _BrokenTransport()
    gc = GraphClient(access_token="tok", no_cache=True)
    gc._client = httpx.AsyncClient(base_url=GRAPH_BASE_URL, transport=transport)
    async with gc:
        with pytest.raises(GraphAPIError):
            await gc.get("/users")
    assert transport.calls == client_mod.MAX_RETRIES


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_all_pages_follows_next_link():
    gc, transport = _make_client(
        [
            _json_response(
                200,
                {
                    "value": [{"id": "1"}, {"id": "2"}],
                    "@odata.nextLink": f"{GRAPH_BASE_URL}/users?$skiptoken=abc",
                },
            ),
            _json_response(
                200,
                {
                    "value": [{"id": "3"}],
                    "@odata.nextLink": f"{GRAPH_BASE_URL}/users?$skiptoken=def",
                },
            ),
            _json_response(200, {"value": [{"id": "4"}]}),
        ]
    )
    async with gc:
        results = await gc.get_all_pages("/users")

    assert [r["id"] for r in results] == ["1", "2", "3", "4"]
    assert len(transport.requests) == 3


@pytest.mark.asyncio
async def test_get_all_pages_single_page():
    gc, transport = _make_client([_json_response(200, {"value": [{"id": "x"}]})])
    async with gc:
        results = await gc.get_all_pages("/users")
    assert results == [{"id": "x"}]
    assert len(transport.requests) == 1


# ---------------------------------------------------------------------------
# Cache integration
# ---------------------------------------------------------------------------


class _FakeCache:
    def __init__(self):
        self.store: dict[tuple[str, str], Any] = {}
        self.get_calls = 0
        self.put_calls = 0

    def get(self, tenant_id, endpoint):
        self.get_calls += 1
        return self.store.get((tenant_id, endpoint))

    def put(self, tenant_id, endpoint, data):
        self.put_calls += 1
        self.store[(tenant_id, endpoint)] = data

    def close(self):
        pass


@pytest.mark.asyncio
async def test_cache_hit_skips_network():
    gc, transport = _make_client([], tenant_id="tenant-1", no_cache=False)
    fake = _FakeCache()
    fake.store[("tenant-1", "/users")] = {"value": ["cached"]}
    gc._cache = fake
    async with gc:
        data = await gc.get("/users")
    assert data == {"value": ["cached"]}
    assert transport.requests == []
    assert fake.put_calls == 0


@pytest.mark.asyncio
async def test_cache_miss_populates_cache():
    gc, _ = _make_client(
        [_json_response(200, {"value": ["fresh"]})],
        tenant_id="tenant-1",
        no_cache=False,
    )
    fake = _FakeCache()
    gc._cache = fake
    async with gc:
        data = await gc.get("/users")
    assert data == {"value": ["fresh"]}
    assert fake.put_calls == 1
    assert fake.store[("tenant-1", "/users")] == {"value": ["fresh"]}


@pytest.mark.asyncio
async def test_offline_mode_with_cache_miss_raises():
    gc, transport = _make_client([], tenant_id="tenant-1", no_cache=False, offline=True)
    fake = _FakeCache()
    gc._cache = fake
    async with gc:
        with pytest.raises(GraphAPIError, match="Offline mode"):
            await gc.get("/users")
    assert transport.requests == []
