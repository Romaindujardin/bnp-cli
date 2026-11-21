"""Configuration locale Enable Banking.

La configuration ne contient **jamais** la clé privée : celle-ci vit dans
``config/private-key.pem``, un fichier séparé en ``0600``. Le fichier
``config/config.json`` ne contient que des paramètres non secrets (application
ID, URL de redirection, établissement, langue).

L'URL de base de l'API est volontairement figée : un fichier de configuration
modifié ne peut pas rediriger un JWT ou une session vers un hôte arbitraire.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .errors import ConfigError
from .jwt import (
    load_private_key,
    normalize_pem,
    public_key_fingerprint,
)
from .paths import SidecarPaths
from .private_files import (
    private_file_info,
    read_private_json,
    read_private_text,
    write_private_json,
    write_private_text,
)

DEFAULT_BASE_URL = "https://api.enablebanking.com"
DEFAULT_REDIRECT_URI = "https://localhost:8787/callback"
DEFAULT_ASPSP = "BNP Paribas"
DEFAULT_COUNTRY = "FR"
DEFAULT_PSU_TYPE = "personal"
DEFAULT_LANGUAGE = "fr"
CONFIG_SCHEMA = "bnp-sidecar/config/v1"
MAX_CONSENT_SECONDS = 180 * 24 * 3600
CONSENT_SAFETY_MARGIN_SECONDS = 60

_APPLICATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_LANGUAGE_RE = re.compile(r"^[a-z]{2}$")
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
def validate_redirect_uri(value: str) -> str:
    """Valide une redirect URI de callback.

    HTTPS est obligatoire, sauf pour une boucle locale HTTP explicitement
    utilisée pour le serveur de callback du sidecar.
    """
    candidate = (value or "").strip()
    if not candidate:
        raise ConfigError("L'URL de redirection est vide.")
    if len(candidate) > 2048:
        raise ConfigError("L'URL de redirection est trop longue (2048 caractères max).")
    parts = urlsplit(candidate)
    if parts.scheme not in {"https", "http"}:
        raise ConfigError("L'URL de redirection doit utiliser https (ou http sur localhost).")
    if parts.username or parts.password:
        raise ConfigError("L'URL de redirection ne doit pas contenir d'identifiants.")
    if parts.fragment:
        raise ConfigError("L'URL de redirection ne doit pas contenir de fragment (#).")
    if not parts.hostname:
        raise ConfigError("L'URL de redirection doit contenir un hôte.")
    if parts.scheme == "http" and parts.hostname not in _LOOPBACK_HOSTS:
        raise ConfigError(
            "HTTP n'est autorisé que pour localhost. Utilisez https pour les autres hôtes."
        )
    if not parts.path or not parts.path.startswith("/"):
        raise ConfigError("L'URL de redirection doit contenir un chemin absolu.")
    try:
        port = parts.port
    except ValueError as exc:
        raise ConfigError("Le port de l'URL de redirection est invalide.") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ConfigError("Le port de l'URL de redirection est invalide.")
    return candidate


def redirect_is_loopback(value: str) -> bool:
    try:
        return urlsplit(value).hostname in _LOOPBACK_HOSTS
    except ValueError:
        return False


def validate_base_url(value: str) -> str:
    if value != DEFAULT_BASE_URL:
        raise ConfigError(
            "L'URL de base Enable Banking doit être "
            f"{DEFAULT_BASE_URL} (le sandbox utilise le même hôte)."
        )
    return value


@dataclass(frozen=True)
class AppConfig:
    application_id: str
    redirect_uri: str = DEFAULT_REDIRECT_URI
    aspsp_name: str = DEFAULT_ASPSP
    aspsp_country: str = DEFAULT_COUNTRY
    psu_type: str = DEFAULT_PSU_TYPE
    language: str = DEFAULT_LANGUAGE
    base_url: str = DEFAULT_BASE_URL

    def validate(self) -> AppConfig:
        application_id = (self.application_id or "").strip()
        if not _APPLICATION_ID_RE.match(application_id):
            raise ConfigError(
                "Application ID Enable Banking invalide (128 caractères "
                "alphanumériques, '.', '_', ':' ou '-' attendus)."
            )
        aspsp_name = (self.aspsp_name or "").strip()
        if not aspsp_name or len(aspsp_name) > 128:
            raise ConfigError("Le nom de l'établissement est vide ou trop long.")
        country = (self.aspsp_country or "").strip().upper()
        if not _COUNTRY_RE.match(country):
            raise ConfigError("Le pays de l'établissement doit être un code ISO à deux lettres.")
        psu_type = (self.psu_type or "").strip().lower()
        if psu_type not in {"personal", "business"}:
            raise ConfigError("psu_type doit valoir 'personal' ou 'business'.")
        language = (self.language or "").strip().lower()
        if not _LANGUAGE_RE.match(language):
            raise ConfigError("La langue doit être un code ISO à deux lettres.")
        return AppConfig(
            application_id=application_id,
            redirect_uri=validate_redirect_uri(self.redirect_uri),
            aspsp_name=aspsp_name,
            aspsp_country=country,
            psu_type=psu_type,
            language=language,
            base_url=validate_base_url(self.base_url),
        )

    def to_json(self) -> dict[str, Any]:
        config = self.validate()
        return {
            "schema": CONFIG_SCHEMA,
            "applicationId": config.application_id,
            "redirectUri": config.redirect_uri,
            "aspsp": config.aspsp_name,
            "country": config.aspsp_country,
            "psuType": config.psu_type,
            "language": config.language,
            "baseUrl": config.base_url,
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> AppConfig:
        if not isinstance(payload, dict):
            raise ConfigError("La configuration doit être un objet JSON.")
        schema = payload.get("schema")
        if schema not in (None, CONFIG_SCHEMA):
            raise ConfigError(f"Schéma de configuration inconnu: {schema!r}.")
        try:
            config = cls(
                application_id=str(payload["applicationId"]),
                redirect_uri=str(payload.get("redirectUri") or DEFAULT_REDIRECT_URI),
                aspsp_name=str(payload.get("aspsp") or DEFAULT_ASPSP),
                aspsp_country=str(payload.get("country") or DEFAULT_COUNTRY),
                psu_type=str(payload.get("psuType") or DEFAULT_PSU_TYPE),
                language=str(payload.get("language") or DEFAULT_LANGUAGE),
                base_url=str(payload.get("baseUrl") or DEFAULT_BASE_URL),
            )
        except KeyError as exc:
            raise ConfigError("La configuration Enable Banking est incomplète.") from exc
        return config.validate()


def load_config(
    paths: SidecarPaths, *, require_private_key: bool = True
) -> tuple[AppConfig, str | None]:
    """Charge la configuration et, si demandé, la clé privée."""
    payload = read_private_json(
        paths.config_file, error_cls=ConfigError, label="Configuration Enable Banking"
    )
    config = AppConfig.from_json(payload).validate()
    if not require_private_key:
        return config, None
    private_key = read_private_text(
        paths.private_key_file,
        error_cls=ConfigError,
        label="Clé privée Enable Banking",
    )
    # Valide la clé avant tout appel réseau.
    load_private_key(private_key)
    return config, normalize_pem(private_key)


def save_config(paths: SidecarPaths, config: AppConfig, private_key_pem: str) -> None:
    """Écrit d'abord la clé, puis la configuration qui la référence."""
    validated = config.validate()
    load_private_key(private_key_pem)
    paths.ensure()
    write_private_text(paths.private_key_file, normalize_pem(private_key_pem) + "\n")
    write_private_json(paths.config_file, validated.to_json())
    # Vérifie que le couple écrit reste lisible et cohérent.
    load_private_key(
        read_private_text(
            paths.private_key_file,
            error_cls=ConfigError,
            label="Clé privée Enable Banking",
        )
    )


def delete_config(paths: SidecarPaths) -> list[str]:
    """Supprime la configuration et la clé privée (sans suivre de lien)."""
    removed: list[str] = []
    for path in (paths.config_file, paths.private_key_file):
        if path.is_symlink():
            raise ConfigError(
                f"Le fichier {path} est un lien symbolique; suppression refusée. "
                "Supprimez-le manuellement après vérification."
            )
        if path.exists():
            path.unlink()
            removed.append(path.name)
    return removed


def mask_application_id(value: str) -> str:
    cleaned = (value or "").strip()
    if len(cleaned) <= 8:
        return "…"
    return f"{cleaned[:8]}…"


def config_summary(paths: SidecarPaths, config: AppConfig, private_key_pem: str | None) -> dict[str, Any]:
    key_info = private_file_info(paths.private_key_file)
    fingerprint = None
    if private_key_pem:
        fingerprint = public_key_fingerprint(load_private_key(private_key_pem))
    return {
        "applicationIdMasked": mask_application_id(config.application_id),
        "redirectUri": config.redirect_uri,
        "aspsp": config.aspsp_name,
        "country": config.aspsp_country,
        "psuType": config.psu_type,
        "language": config.language,
        "baseUrl": config.base_url,
        "keyFingerprint": fingerprint,
        "privateKey": key_info,
    }


def config_secrets(config: AppConfig, private_key_pem: str | None) -> list[str]:
    secrets = [config.application_id]
    if private_key_pem:
        secrets.append(private_key_pem)
        for line in private_key_pem.splitlines():
            if line and not line.startswith("-----"):
                secrets.append(line)
    return secrets
