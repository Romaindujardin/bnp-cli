"""Construction du JWT RS256 attendu par Enable Banking.

Le JWT n'est jamais stocké : il est signé à la volée pour chaque requête, avec
une durée de vie courte (une heure par défaut). La clé privée reste en mémoire
le temps du processus et n'est jamais écrite ailleurs que dans son fichier
``0600``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .errors import ConfigError

JWT_ISSUER = "enablebanking.com"
JWT_AUDIENCE = "api.enablebanking.com"
DEFAULT_TTL_SECONDS = 3600
MAX_TTL_SECONDS = 86400
MIN_RSA_BITS = 2048


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def normalize_pem(value: str) -> str:
    """Acepte un PEM avec des ``\\n`` littéraux (copier/coller)."""
    return value.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r\n", "\n").strip()


def load_private_key(private_key_pem: str) -> rsa.RSAPrivateKey:
    """Charge et valide une clé privée RSA non chiffrée."""
    if not private_key_pem or "PRIVATE KEY" not in private_key_pem:
        raise ConfigError(
            "Clé privée Enable Banking absente ou invalide : un PEM RSA est attendu."
        )
    try:
        key = serialization.load_pem_private_key(
            normalize_pem(private_key_pem).encode("utf-8"),
            password=None,
        )
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ConfigError(
            "Clé privée Enable Banking illisible. Utilisez une clé RSA PEM non "
            "chiffrée, générée pour l'application Enable Banking."
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ConfigError("La clé privée Enable Banking doit être une clé RSA.")
    if key.key_size < MIN_RSA_BITS:
        raise ConfigError(
            f"La clé privée Enable Banking fait {key.key_size} bits; "
            f"{MIN_RSA_BITS} bits minimum sont requis."
        )
    return key


def public_key_fingerprint(private_key: rsa.RSAPrivateKey) -> str:
    """Empreinte SHA-256 courte de la clé publique, pour vérification humaine."""
    der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:16]


def create_jwt(
    application_id: str,
    private_key_pem: str,
    *,
    now: int | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> str:
    """Retourne un JWT RS256 signé pour l'API Enable Banking.

    ``kid`` porte l'application ID, ``iss`` vaut ``enablebanking.com`` et
    ``aud`` vaut ``api.enablebanking.com``, conformément à la documentation.
    """
    if not application_id or not application_id.strip():
        raise ConfigError("Application ID Enable Banking manquant.")
    if ttl_seconds < 60 or ttl_seconds > MAX_TTL_SECONDS:
        raise ConfigError(
            f"Durée de vie JWT invalide ({ttl_seconds}s): "
            f"attendu entre 60 et {MAX_TTL_SECONDS} secondes."
        )

    key = load_private_key(private_key_pem)
    issued_at = int(time.time() if now is None else now)
    header: dict[str, Any] = {"typ": "JWT", "alg": "RS256", "kid": application_id}
    payload: dict[str, Any] = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": issued_at,
        "exp": issued_at + ttl_seconds,
    }
    signing_input = ".".join(
        (
            b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
        )
    )
    signature = key.sign(
        signing_input.encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return f"{signing_input}.{b64url_encode(signature)}"
