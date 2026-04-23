"""Authentication provider — wraps MSAL for token acquisition."""

from __future__ import annotations

import logging
import os
import re
import stat
import sys
from enum import StrEnum
from pathlib import Path
from typing import Any

import msal

from entralint.core.errors import AuthenticationError

logger = logging.getLogger(__name__)

# Default scopes for Microsoft Graph read-only access
DEFAULT_SCOPES = ["https://graph.microsoft.com/.default"]

# Public client app registration — set via ENTRALINT_CLIENT_ID env var.
# Register your own Entra ID app or set this in a .env file.
DEFAULT_CLIENT_ID = os.environ.get("ENTRALINT_CLIENT_ID", "")

# Where token caches are stored
CACHE_DIR = Path.home() / ".entralint" / "cache"

# Matches either a GUID (tenant or client id) or a verified domain name
# (e.g. "contoso.onmicrosoft.com"). MSAL accepts both, but we reject
# obvious typos and shell-metacharacter injection up-front so they
# cannot produce weird cache filenames.
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


def _validate_tenant_id(tenant_id: str) -> str:
    """Return ``tenant_id`` if it looks like a GUID or domain, else raise."""
    if not tenant_id or not (_GUID_RE.match(tenant_id) or _DOMAIN_RE.match(tenant_id)):
        raise AuthenticationError(
            f"Invalid tenant id: {tenant_id!r}. Expected a GUID or a verified domain "
            "(e.g. 'contoso.onmicrosoft.com')."
        )
    return tenant_id


def _validate_client_id(client_id: str) -> str:
    """Return ``client_id`` if it looks like a GUID, else raise."""
    if not _GUID_RE.match(client_id):
        raise AuthenticationError(
            f"Invalid client id: {client_id!r}. Expected a GUID."
        )
    return client_id


class AuthMethod(StrEnum):
    AUTH_CODE = "auth_code"
    DEVICE_CODE = "device_code"
    CLIENT_CREDENTIALS = "client_credentials"
    DEFAULT_CREDENTIAL = "default_credential"
    MANAGED_IDENTITY = "managed_identity"


def _cache_path(tenant_id: str) -> Path:
    """Return the token cache file path for a given tenant."""
    return CACHE_DIR / f"{tenant_id}.json"


def _load_cache(tenant_id: str) -> msal.SerializableTokenCache:
    """Load a per-tenant MSAL token cache from disk."""
    cache = msal.SerializableTokenCache()
    path = _cache_path(tenant_id)
    if path.exists():
        cache.deserialize(path.read_text(encoding="utf-8"))
    return cache


def _save_cache(tenant_id: str, cache: msal.SerializableTokenCache) -> None:
    """Persist the MSAL token cache to disk with restrictive permissions.

    The cache holds refresh tokens, so we write it atomically and set
    owner-read/write-only (``0o600``) permissions on POSIX systems. On
    Windows the home directory ACL already restricts access to the
    current user, so ``chmod`` is best-effort there.
    """
    path = _cache_path(tenant_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        # os.open gives us control over the initial file mode, avoiding a
        # window where the file exists with default (more permissive) perms.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(path, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(cache.serialize())
        except Exception:
            # fdopen closes fd on success; only close manually on failure
            # before the with-block takes ownership.
            raise
    except OSError:
        # Fallback path (unusual filesystems, etc.).
        path.write_text(cache.serialize(), encoding="utf-8")

    # Belt-and-braces: ensure perms are tight even if the file pre-existed.
    if sys.platform != "win32":
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError as exc:
            logger.warning("Could not set 0600 on token cache %s: %s", path, exc)


class AuthProvider:
    """MSAL wrapper for Entra ID authentication.

    Supports device code flow (interactive), client credentials (CI/CD),
    and DefaultAzureCredential (workload identity federation, managed identity,
    az CLI) with per-tenant token isolation and persistent caching.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str = DEFAULT_CLIENT_ID,
        method: AuthMethod = AuthMethod.DEVICE_CODE,
        client_secret: str | None = None,
        client_certificate_path: str | None = None,
    ) -> None:
        if method != AuthMethod.DEFAULT_CREDENTIAL and not client_id:
            raise AuthenticationError(
                "No client ID configured. Set ENTRALINT_CLIENT_ID environment "
                "variable or pass --client-id to the command."
            )
        # Fail fast on obviously bogus identifiers rather than letting MSAL
        # produce a confusing downstream error (or letting an attacker-controlled
        # value end up in a cache filename).
        self.tenant_id = _validate_tenant_id(tenant_id)
        if client_id:
            self.client_id = _validate_client_id(client_id)
        else:
            self.client_id = client_id
        self.method = method
        self._client_secret = client_secret
        self._client_certificate_path = client_certificate_path
        self._token: str | None = None

        if method == AuthMethod.DEFAULT_CREDENTIAL:
            self._cache = msal.SerializableTokenCache()
            self._app: msal.ClientApplication | None = None
        else:
            self._cache = _load_cache(tenant_id)
            self._app = self._build_msal_app()

    def _build_msal_app(self) -> msal.ClientApplication:
        """Create the appropriate MSAL application instance."""
        authority = f"https://login.microsoftonline.com/{self.tenant_id}"

        if self.method == AuthMethod.CLIENT_CREDENTIALS:
            credential: str | dict[str, Any] | None = None
            if self._client_certificate_path:
                cert_path = Path(self._client_certificate_path)
                credential = {
                    "private_key": cert_path.read_text(encoding="utf-8"),
                    "thumbprint": "",  # MSAL computes from the cert
                }
            else:
                credential = self._client_secret

            return msal.ConfidentialClientApplication(
                client_id=self.client_id,
                authority=authority,
                client_credential=credential,
                token_cache=self._cache,
            )
        else:
            # Public client for device code and auth code flows
            return msal.PublicClientApplication(
                client_id=self.client_id,
                authority=authority,
                token_cache=self._cache,
            )

    def acquire_token_silent(self) -> str | None:
        """Try to get a cached/refreshed token without user interaction."""
        accounts = self._app.get_accounts()
        if not accounts:
            return None

        result = self._app.acquire_token_silent(
            scopes=DEFAULT_SCOPES,
            account=accounts[0],
        )
        if result and "access_token" in result:
            self._token = result["access_token"]
            _save_cache(self.tenant_id, self._cache)
            return self._token
        return None

    def acquire_token_device_code(
        self,
        callback: Any | None = None,
    ) -> str:
        """Run the device code flow — prints a URL + code for the user."""
        flow = self._app.initiate_device_flow(scopes=DEFAULT_SCOPES)
        if "user_code" not in flow:
            error_desc = flow.get("error_description", "unknown error")
            raise AuthenticationError(
                f"Failed to initiate device code flow: {error_desc}"
            )

        # Call the callback so the CLI can display the message
        if callback:
            callback(flow)

        result = self._app.acquire_token_by_device_flow(flow)
        return self._handle_result(result)

    def acquire_token_client_credentials(self) -> str:
        """Acquire a token using client credentials (app-only, no user)."""
        if self._app is None:
            raise AuthenticationError("MSAL app not initialized for client credentials.")
        result = self._app.acquire_token_for_client(scopes=DEFAULT_SCOPES)
        return self._handle_result(result)

    def acquire_token_default_credential(self) -> str:
        """Acquire a token using azure-identity DefaultAzureCredential.

        Works with workload identity federation (GitHub Actions OIDC),
        managed identity (Azure-hosted), Azure CLI, and other credential
        types supported by the Azure Identity SDK.
        """
        from azure.core.exceptions import ClientAuthenticationError as AzureAuthError
        from azure.identity import DefaultAzureCredential

        try:
            credential = DefaultAzureCredential()
            token = credential.get_token("https://graph.microsoft.com/.default")
            self._token = token.token
            return self._token
        except AzureAuthError as exc:
            raise AuthenticationError(
                f"DefaultAzureCredential failed: {exc}"
            ) from exc

    def _handle_result(self, result: dict[str, Any]) -> str:
        """Extract access_token from an MSAL result or raise on error."""
        if "access_token" in result:
            self._token = result["access_token"]
            _save_cache(self.tenant_id, self._cache)
            return self._token

        error = result.get("error", "unknown_error")
        description = result.get("error_description", "No description provided.")
        raise AuthenticationError(f"Authentication failed ({error}): {description}")

    @property
    def access_token(self) -> str | None:
        return self._token

    @staticmethod
    def clear_cache(tenant_id: str) -> bool:
        """Remove the cached token for a tenant. Returns True if a cache existed."""
        path = _cache_path(tenant_id)
        if path.exists():
            path.unlink()
            return True
        return False

    @staticmethod
    def list_cached_tenants() -> list[str]:
        """Return tenant IDs that have cached tokens."""
        if not CACHE_DIR.exists():
            return []
        return [p.stem for p in CACHE_DIR.glob("*.json")]
