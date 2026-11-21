"""Tests de la redaction des secrets."""

from __future__ import annotations

from bnp_sidecar.redact import REDACTED, Redactor, redact, redact_value

PRIVATE_KEY = "\n".join(
    (
        "-----BEGIN " + "PRIVATE KEY-----",
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7",
        "-----END " + "PRIVATE KEY-----",
    )
)


def test_redacts_private_key_block() -> None:
    result = redact(f"erreur avec {PRIVATE_KEY} dans le message")
    assert "BEGIN PRIVATE KEY" not in result
    assert "[REDACTED_PRIVATE_KEY]" in result


def test_redacts_registered_secret() -> None:
    secret = "cf589be3-3755-465b-a8df-a90a16a31403"
    assert secret not in redact(f"app={secret}", [secret])
    assert REDACTED in redact(f"app={secret}", [secret])


def test_ignores_short_secrets() -> None:
    assert redact("value abc", ["abc"]) == "value abc"


def test_redacts_jwt_and_bearer() -> None:
    jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJlbmFibGViYW5raW5nLmNvbSJ9.c2ln"
    text = f"Authorization: Bearer {jwt}"
    result = redact(text)
    assert jwt not in result
    assert "[REDACTED_JWT]" in result or "[REDACTED]" in result


def test_redacts_code_and_state_parameters() -> None:
    result = redact("https://localhost/callback?code=super-secret&state=another-secret")
    assert "super-secret" not in result
    assert "another-secret" not in result


def test_redacts_nested_values() -> None:
    redactor = Redactor(["secret-value"])
    payload = {
        "message": "secret-value",
        "nested": [{"token": "secret-value"}],
        "number": 42,
    }
    cleaned = redactor.value(payload)
    assert cleaned["message"] == REDACTED
    assert cleaned["nested"][0]["token"] == REDACTED
    assert cleaned["number"] == 42


def test_redact_value_helper() -> None:
    assert redact_value({"a": "top-secret"}, ["top-secret"]) == {"a": REDACTED}


def test_redacts_iban_when_requested() -> None:
    redactor = Redactor()
    assert "FR76" not in redactor.text("IBAN FR7630006000011234567890189", redact_iban=True)
    assert "FR76" in redactor.text("IBAN FR7630006000011234567890189")
