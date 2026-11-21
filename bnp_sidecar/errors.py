"""Erreurs typées du sidecar et codes de sortie CLI."""

from __future__ import annotations

from typing import Any


class SidecarError(Exception):
    """Erreur attendue, sérialisable en JSON."""

    code = "SIDECAR_ERROR"
    exit_code = 1

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.details = details or {}


class UsageError(SidecarError):
    code = "USAGE_ERROR"
    exit_code = 2


class ConfigError(SidecarError):
    code = "CONFIG_ERROR"
    exit_code = 3


class SecretFileError(ConfigError):
    code = "SECRET_FILE_ERROR"


class SessionError(SidecarError):
    code = "SESSION_ERROR"
    exit_code = 3


class SessionExpired(SessionError):
    code = "SESSION_EXPIRED"


class AuthenticationError(SidecarError):
    code = "AUTH_FAILED"
    exit_code = 4


class ConsentDenied(AuthenticationError):
    code = "CONSENT_DENIED"


class LinkStateError(AuthenticationError):
    code = "LINK_STATE_INVALID"


class UpstreamError(SidecarError):
    code = "UPSTREAM_ERROR"
    exit_code = 5


class NotFoundError(SidecarError):
    code = "NOT_FOUND"
    exit_code = 7


class AmbiguousAccount(NotFoundError):
    code = "AMBIGUOUS_ACCOUNT"
