"""Redaction des secrets dans les messages et les sorties de diagnostic.

Le sidecar ne doit jamais écrire une clé privée, un JWT, un code
d'autorisation ou un identifiant de session dans un log, une erreur ou un
fichier de diagnostic. Les valeurs connues sont enregistrées dans un
``Redactor`` ; les motifs génériques couvrent en plus les secrets qui
n'auraient pas été enregistrés explicitement.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

REDACTED = "[REDACTED]"
MIN_SECRET_LENGTH = 4

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        re.compile(r"(?i)\b(authorization\s*:\s*bearer\s+)[^\s,;\"']+"),
        r"\1" + REDACTED,
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"),
        "[REDACTED_JWT]",
    ),
    (
        re.compile(
            r"(?i)\b(access_token|refresh_token|session_id|authorization_id|"
            r"code|state|private_key|client_secret)\b\s*[=:]\s*"
            r"(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
        ),
        r"\1=" + REDACTED,
    ),
    (
        re.compile(r"(?i)\b(code|state)=([^&\s\"']+)"),
        r"\1=" + REDACTED,
    ),
)

_IBAN_PATTERN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{1,4}\b")


def _usable_secret(secret: str) -> bool:
    return isinstance(secret, str) and len(secret) >= MIN_SECRET_LENGTH and secret.strip() != ""


class Redactor:
    """Ensemble de secrets connus + motifs génériques."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        self._secrets: list[str] = []
        self.add_many(secrets)

    def add(self, secret: str | None) -> None:
        if secret and _usable_secret(secret) and secret not in self._secrets:
            # Les secrets les plus longs d'abord : un JWT contient parfois un
            # identifiant plus court qui ne doit pas être remplacé avant lui.
            self._secrets.append(secret)
            self._secrets.sort(key=len, reverse=True)

    def add_many(self, secrets: Iterable[str]) -> None:
        for secret in secrets:
            self.add(secret)

    def text(self, value: str, *, redact_iban: bool = False) -> str:
        result = value
        for secret in self._secrets:
            result = result.replace(secret, REDACTED)
        for pattern, replacement in _PATTERNS:
            result = pattern.sub(replacement, result)
        if redact_iban:
            result = _IBAN_PATTERN.sub("[REDACTED_IBAN]", result)
        return result

    def value(self, value: Any, *, redact_iban: bool = False) -> Any:
        if isinstance(value, str):
            return self.text(value, redact_iban=redact_iban)
        if isinstance(value, dict):
            return {
                self.text(str(key), redact_iban=redact_iban): self.value(
                    item, redact_iban=redact_iban
                )
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple, set)):
            return [self.value(item, redact_iban=redact_iban) for item in value]
        return value


def redact(value: str, secrets: Iterable[str] = ()) -> str:
    return Redactor(secrets).text(value)


def redact_value(value: Any, secrets: Iterable[str] = ()) -> Any:
    return Redactor(secrets).value(value)
