"""Tests for the MSAL-based AuthProvider wrapper.

MSAL itself is mocked out — these tests focus on AuthProvider's orchestration
logic: cache file handling, permission enforcement, error translation, and
dispatch to the correct credential flow.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from unittest.mock import MagicMock, patch

import pytest

from entralint.auth import provider as provider_mod
from entralint.auth.provider import AuthMethod, AuthProvider
from entralint.core.errors import AuthenticationError

# Well-formed GUIDs used by the fake provider constructor invocations.
TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT = "22222222-2222-2222-2222-222222222222"


@pytest.fixture(autouse=True)
def _isolated_cache_dir(tmp_path, monkeypatch):
    """Redirect the cache dir to a tmp path for each test."""
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(provider_mod, "CACHE_DIR", cache_dir)
    return cache_dir


@pytest.fixture
def fake_public_app():
    """A MagicMock that mimics msal.PublicClientApplication."""
    app = MagicMock()
    app.get_accounts.return_value = []
    return app


@pytest.fixture
def fake_confidential_app():
    return MagicMock()


# ---------------------------------------------------------------------------
# Construction / configuration
# ---------------------------------------------------------------------------


def test_missing_client_id_raises():
    with pytest.raises(AuthenticationError, match="client ID"):
        AuthProvider(tenant_id=TENANT, client_id="", method=AuthMethod.DEVICE_CODE)


def test_default_credential_does_not_require_client_id():
    # Should not raise.
    ap = AuthProvider(
        tenant_id=TENANT, client_id="", method=AuthMethod.DEFAULT_CREDENTIAL
    )
    assert ap.method == AuthMethod.DEFAULT_CREDENTIAL


def test_invalid_tenant_id_rejected():
    with pytest.raises(AuthenticationError, match="Invalid tenant id"):
        AuthProvider(tenant_id="not-a-guid", client_id=CLIENT)


def test_invalid_client_id_rejected():
    with pytest.raises(AuthenticationError, match="Invalid client id"):
        AuthProvider(tenant_id=TENANT, client_id="not-a-guid")


def test_domain_tenant_id_accepted():
    ap = AuthProvider(
        tenant_id="contoso.onmicrosoft.com",
        client_id="",
        method=AuthMethod.DEFAULT_CREDENTIAL,
    )
    assert ap.tenant_id == "contoso.onmicrosoft.com"


# ---------------------------------------------------------------------------
# Token cache: permissions & persistence
# ---------------------------------------------------------------------------


def test_save_cache_sets_restrictive_permissions_on_posix(_isolated_cache_dir):
    import msal

    cache = msal.SerializableTokenCache()
    provider_mod._save_cache("tenant-abc", cache)

    path = provider_mod._cache_path("tenant-abc")
    assert path.exists()

    if sys.platform != "win32":
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_save_cache_overwrites_existing_file(_isolated_cache_dir):
    import msal

    cache = msal.SerializableTokenCache()
    provider_mod._save_cache("tenant-abc", cache)
    path = provider_mod._cache_path("tenant-abc")
    # Write pre-existing garbage
    path.write_text("GARBAGE", encoding="utf-8")
    provider_mod._save_cache("tenant-abc", cache)
    assert path.read_text(encoding="utf-8") != "GARBAGE"


def test_load_cache_roundtrip(_isolated_cache_dir):
    import msal

    cache = msal.SerializableTokenCache()
    provider_mod._save_cache("tenant-xyz", cache)
    reloaded = provider_mod._load_cache("tenant-xyz")
    # Both should serialize to equivalent (empty) JSON.
    assert json.loads(cache.serialize() or "{}") == json.loads(reloaded.serialize() or "{}")


def test_clear_cache_removes_file(_isolated_cache_dir):
    import msal

    provider_mod._save_cache("tenant-clear", msal.SerializableTokenCache())
    assert provider_mod._cache_path("tenant-clear").exists()
    assert AuthProvider.clear_cache("tenant-clear") is True
    assert not provider_mod._cache_path("tenant-clear").exists()


def test_clear_cache_missing_returns_false(_isolated_cache_dir):
    assert AuthProvider.clear_cache("no-such-tenant") is False


def test_list_cached_tenants(_isolated_cache_dir):
    import msal

    for t in ("t1", "t2", "t3"):
        provider_mod._save_cache(t, msal.SerializableTokenCache())
    assert sorted(AuthProvider.list_cached_tenants()) == ["t1", "t2", "t3"]


def test_list_cached_tenants_no_dir(_isolated_cache_dir):
    # Directory doesn't exist yet
    assert AuthProvider.list_cached_tenants() == []


# ---------------------------------------------------------------------------
# Silent acquisition
# ---------------------------------------------------------------------------


def test_acquire_token_silent_returns_none_when_no_accounts(fake_public_app):
    with patch.object(provider_mod.msal, "PublicClientApplication", return_value=fake_public_app):
        ap = AuthProvider(tenant_id=TENANT, client_id=CLIENT, method=AuthMethod.DEVICE_CODE)
    assert ap.acquire_token_silent() is None


def test_acquire_token_silent_returns_token_when_cached(fake_public_app):
    fake_public_app.get_accounts.return_value = [{"username": "alice"}]
    fake_public_app.acquire_token_silent.return_value = {"access_token": "abc123"}
    with patch.object(provider_mod.msal, "PublicClientApplication", return_value=fake_public_app):
        ap = AuthProvider(tenant_id=TENANT, client_id=CLIENT, method=AuthMethod.DEVICE_CODE)
    assert ap.acquire_token_silent() == "abc123"
    assert ap.access_token == "abc123"


def test_acquire_token_silent_returns_none_on_empty_result(fake_public_app):
    fake_public_app.get_accounts.return_value = [{"username": "alice"}]
    fake_public_app.acquire_token_silent.return_value = None
    with patch.object(provider_mod.msal, "PublicClientApplication", return_value=fake_public_app):
        ap = AuthProvider(tenant_id=TENANT, client_id=CLIENT, method=AuthMethod.DEVICE_CODE)
    assert ap.acquire_token_silent() is None


# ---------------------------------------------------------------------------
# Device code flow
# ---------------------------------------------------------------------------


def test_device_code_flow_success(fake_public_app):
    fake_public_app.initiate_device_flow.return_value = {
        "user_code": "CODE",
        "verification_uri": "https://aka.ms/devicelogin",
        "message": "Go to …",
    }
    fake_public_app.acquire_token_by_device_flow.return_value = {"access_token": "tok"}

    with patch.object(provider_mod.msal, "PublicClientApplication", return_value=fake_public_app):
        ap = AuthProvider(tenant_id=TENANT, client_id=CLIENT, method=AuthMethod.DEVICE_CODE)
    callback = MagicMock()
    token = ap.acquire_token_device_code(callback=callback)
    assert token == "tok"
    callback.assert_called_once()


def test_device_code_flow_no_user_code_raises(fake_public_app):
    fake_public_app.initiate_device_flow.return_value = {
        "error_description": "bad thing happened"
    }
    with patch.object(provider_mod.msal, "PublicClientApplication", return_value=fake_public_app):
        ap = AuthProvider(tenant_id=TENANT, client_id=CLIENT, method=AuthMethod.DEVICE_CODE)
    with pytest.raises(AuthenticationError, match="bad thing happened"):
        ap.acquire_token_device_code()


def test_device_code_flow_authentication_failure(fake_public_app):
    fake_public_app.initiate_device_flow.return_value = {"user_code": "CODE"}
    fake_public_app.acquire_token_by_device_flow.return_value = {
        "error": "authorization_declined",
        "error_description": "user said no",
    }
    with patch.object(provider_mod.msal, "PublicClientApplication", return_value=fake_public_app):
        ap = AuthProvider(tenant_id=TENANT, client_id=CLIENT, method=AuthMethod.DEVICE_CODE)
    with pytest.raises(AuthenticationError, match="authorization_declined"):
        ap.acquire_token_device_code()


# ---------------------------------------------------------------------------
# Client credentials flow
# ---------------------------------------------------------------------------


def test_client_credentials_success(fake_confidential_app):
    fake_confidential_app.acquire_token_for_client.return_value = {"access_token": "svc-tok"}
    with patch.object(
        provider_mod.msal,
        "ConfidentialClientApplication",
        return_value=fake_confidential_app,
    ):
        ap = AuthProvider(
            tenant_id=TENANT,
            client_id=CLIENT,
            method=AuthMethod.CLIENT_CREDENTIALS,
            client_secret="secret",
        )
    assert ap.acquire_token_client_credentials() == "svc-tok"


def test_client_credentials_failure(fake_confidential_app):
    fake_confidential_app.acquire_token_for_client.return_value = {
        "error": "invalid_client",
        "error_description": "bad secret",
    }
    with patch.object(
        provider_mod.msal,
        "ConfidentialClientApplication",
        return_value=fake_confidential_app,
    ):
        ap = AuthProvider(
            tenant_id=TENANT,
            client_id=CLIENT,
            method=AuthMethod.CLIENT_CREDENTIALS,
            client_secret="wrong",
        )
    with pytest.raises(AuthenticationError, match="invalid_client"):
        ap.acquire_token_client_credentials()


def test_client_credentials_with_certificate_reads_file(tmp_path, fake_confidential_app):
    cert_path = tmp_path / "cert.pem"
    cert_path.write_text("-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n")

    captured: dict[str, object] = {}

    def _factory(**kwargs):
        captured.update(kwargs)
        return fake_confidential_app

    with patch.object(
        provider_mod.msal, "ConfidentialClientApplication", side_effect=_factory
    ):
        AuthProvider(
            tenant_id=TENANT,
            client_id=CLIENT,
            method=AuthMethod.CLIENT_CREDENTIALS,
            client_certificate_path=str(cert_path),
        )

    cred = captured["client_credential"]
    assert isinstance(cred, dict)
    assert "private_key" in cred
    assert "BEGIN PRIVATE KEY" in cred["private_key"]
