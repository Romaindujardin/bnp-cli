"""Tests du JWT RS256 Enable Banking."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from bnp_sidecar.errors import ConfigError
from bnp_sidecar.jwt import (
    b64url_decode,
    create_jwt,
    load_private_key,
    public_key_fingerprint,
)

APPLICATION_ID = "cf589be3-3755-465b-a8df-a90a16a31403"


def test_jwt_header_and_payload(private_key_pem: str) -> None:
    token = create_jwt(APPLICATION_ID, private_key_pem, now=1_700_000_000, ttl_seconds=600)
    header_b64, payload_b64, signature_b64 = token.split(".")
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    assert header == {"typ": "JWT", "alg": "RS256", "kid": APPLICATION_ID}
    assert payload == {
        "iss": "enablebanking.com",
        "aud": "api.enablebanking.com",
        "iat": 1_700_000_000,
        "exp": 1_700_000_600,
    }
    assert b64url_decode(signature_b64)


def test_jwt_signature_is_valid(private_key_pem: str) -> None:
    token = create_jwt(APPLICATION_ID, private_key_pem, now=1_700_000_000)
    signing_input, signature_b64 = token.rsplit(".", 1)
    key = load_private_key(private_key_pem)
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key = load_pem_public_key(public_pem)
    public_key.verify(
        b64url_decode(signature_b64),
        signing_input.encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_jwt_rejects_invalid_ttl(private_key_pem: str) -> None:
    with pytest.raises(ConfigError):
        create_jwt(APPLICATION_ID, private_key_pem, ttl_seconds=10)
    with pytest.raises(ConfigError):
        create_jwt(APPLICATION_ID, private_key_pem, ttl_seconds=86401)


def test_jwt_rejects_missing_application_id(private_key_pem: str) -> None:
    with pytest.raises(ConfigError):
        create_jwt("", private_key_pem)


def test_jwt_rejects_bad_pem() -> None:
    with pytest.raises(ConfigError, match="absente ou invalide"):
        create_jwt(APPLICATION_ID, "not a key")


def test_jwt_accepts_escaped_newlines(private_key_pem: str) -> None:
    escaped = private_key_pem.replace("\n", "\\n")
    token = create_jwt(APPLICATION_ID, escaped, now=1_700_000_000)
    assert token.count(".") == 2


def test_fingerprint_is_stable(private_key_pem: str) -> None:
    key = load_private_key(private_key_pem)
    assert public_key_fingerprint(key) == public_key_fingerprint(key)
    assert len(public_key_fingerprint(key)) == 16
