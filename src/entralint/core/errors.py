"""Error taxonomy for EntraLint scan results."""

from __future__ import annotations


class EntraLintError(Exception):
    """Base exception for all EntraLint errors."""


class AuthenticationError(EntraLintError):
    """Raised when authentication fails or tokens cannot be acquired."""


class AuthenticationExpiredError(AuthenticationError):
    """Raised when a token expires mid-scan and cannot be refreshed."""


class ConfigError(EntraLintError):
    """Raised for configuration file parsing or validation errors."""


class ConfigSecurityError(ConfigError):
    """Raised when a configuration file contains inline secrets."""


class GraphAPIError(EntraLintError):
    """Raised for unexpected Microsoft Graph API errors."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class GraphThrottledError(GraphAPIError):
    """Raised when Graph API returns 429 (too many requests)."""

    def __init__(self, message: str, retry_after: int | None = None) -> None:
        super().__init__(message, status_code=429)
        self.retry_after = retry_after


class InsufficientPermissionError(EntraLintError):
    """Raised when the app lacks a required Graph API permission."""

    def __init__(self, message: str, missing_permissions: list[str] | None = None) -> None:
        super().__init__(message)
        self.missing_permissions = missing_permissions or []


class LicenseRequiredError(EntraLintError):
    """Raised when a check requires a license tier the tenant doesn't have."""

    def __init__(self, message: str, required_license: str | None = None) -> None:
        super().__init__(message)
        self.required_license = required_license
