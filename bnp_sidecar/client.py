"""Client HTTP lecture seule pour l'API Enable Banking (PSD2/AIS).

Le client n'implémente que les opérations d'information sur les comptes :
application, catalogue ASPSP, autorisation de session, session, détails,
soldes et transactions. Aucun endpoint de paiement n'est exposé.

Sécurité réseau :
- TLS vérifié par la bibliothèque standard ;
- redirections HTTP refusées (un 3xx n'est jamais suivi) ;
- JWT RS256 signé à la volée et jamais journalisé ;
- taille de réponse bornée ;
- URL de base limitée à l'API Enable Banking (ou à une boucle locale en test).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import __version__
from .config import (
    CONSENT_SAFETY_MARGIN_SECONDS,
    DEFAULT_BASE_URL,
    MAX_CONSENT_SECONDS,
    AppConfig,
    redirect_is_loopback,
)
from .errors import (
    AuthenticationError,
    ConfigError,
    NotFoundError,
    SessionExpired,
    UpstreamError,
)
from .jwt import create_jwt, load_private_key, normalize_pem

REQUEST_TIMEOUT_SECONDS = 30.0
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
USER_AGENT = f"bnp-sidecar/{__version__}"
AUTH_FAILURE_CODES = {"EXPIRED_SESSION", "SESSION_EXPIRED", "ACCESS_DENIED", "UNAUTHORIZED"}
REDIRECT_CODES = {301, 302, 303, 307, 308}


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _validate_base_url(value: str) -> str:
    parts = urllib.parse.urlsplit(value)
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ConfigError("URL de base Enable Banking invalide.")
    if parts.path not in ("", "/"):
        raise ConfigError("URL de base Enable Banking invalide (chemin inattendu).")
    if parts.scheme == "https" and parts.hostname:
        return value.rstrip("/")
    if parts.scheme == "http" and parts.hostname in {"localhost", "127.0.0.1", "::1"}:
        # Uniquement pour les tests locaux et le faux serveur PSD2.
        return value.rstrip("/")
    raise ConfigError(
        "L'URL de base Enable Banking doit utiliser https "
        "(http n'est accepté que sur la boucle locale)."
    )


def _error_message(payload: Any) -> str:
    if isinstance(payload, dict):
        for key in ("message", "error_description", "detail", "error"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _provider_code(payload: Any) -> str | None:
    if isinstance(payload, dict):
        for key in ("code", "error", "error_code"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().upper()
    return None


def _parse_json(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


@dataclass
class TransactionsResult:
    transactions: list[dict[str, Any]] = field(default_factory=list)
    pages: int = 0
    truncated: bool = False
    continuation_key: str | None = None
    warnings: list[str] = field(default_factory=list)


class EnableBankingClient:
    def __init__(
        self,
        config: AppConfig,
        private_key_pem: str,
        *,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
        base_url: str | None = None,
    ) -> None:
        self.config = config.validate()
        self._private_key_pem = normalize_pem(private_key_pem)
        # Valide la clé dès la construction du client.
        load_private_key(self._private_key_pem)
        if timeout <= 0 or timeout > 120:
            raise ConfigError("Le délai réseau doit être compris entre 1 et 120 secondes.")
        self.timeout = timeout
        self.base_url = _validate_base_url(base_url or self.config.base_url or DEFAULT_BASE_URL)
        self._opener = urllib.request.build_opener(_NoRedirectHandler())
        self.last_request_id: str | None = None

    # -- transport ---------------------------------------------------------

    def _authorization_header(self) -> str:
        token = create_jwt(self.config.application_id, self._private_key_pem)
        return f"Bearer {token}"

    def _build_url(self, path: str, query: dict[str, Any] | None = None) -> str:
        if not path.startswith("/"):
            raise ConfigError("Chemin d'API invalide.")
        url = f"{self.base_url}{path}"
        if query:
            filtered = {
                key: str(value)
                for key, value in query.items()
                if value is not None and value != ""
            }
            if filtered:
                url = f"{url}?{urllib.parse.urlencode(filtered)}"
        return url

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
    ) -> Any:
        url = self._build_url(path, query)
        data = None
        headers = {
            "Authorization": self._authorization_header(),
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Cache-Control": "no-store",
            "User-Agent": USER_AGENT,
        }
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        self.last_request_id = None

        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                self.last_request_id = response.headers.get("X-Request-Id")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            self.last_request_id = exc.headers.get("X-Request-Id") if exc.headers else None
            raw = exc.read(MAX_RESPONSE_BYTES + 1) if exc.fp else b""
            self._raise_http_error(exc.code, raw, path)
            raise AssertionError("unreachable")  # pragma: no cover
        except TimeoutError as exc:
            raise UpstreamError(
                "Enable Banking n'a pas répondu dans le délai imparti.",
                details={"timeoutSeconds": self.timeout},
            ) from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            raise UpstreamError(
                "Enable Banking est injoignable. Vérifiez la connexion réseau.",
                details={"reason": str(reason)},
            ) from exc
        except OSError as exc:
            raise UpstreamError(
                "Erreur réseau lors de l'appel à Enable Banking.",
                details={"reason": str(exc)},
            ) from exc

        if len(raw) > MAX_RESPONSE_BYTES:
            raise UpstreamError("La réponse d'Enable Banking dépasse la taille maximale autorisée.")
        payload = _parse_json(raw)
        if payload is None:
            raise UpstreamError(
                "Enable Banking a renvoyé une réponse JSON invalide.",
                details={"path": path},
            )
        return payload

    def _raise_http_error(self, status: int, raw: bytes, path: str) -> None:
        payload = _parse_json(raw)
        provider_code = _provider_code(payload)
        message = _error_message(payload)

        if status in REDIRECT_CODES:
            raise UpstreamError(
                "Enable Banking a tenté une redirection HTTP; elle a été refusée.",
                details={"status": status, "path": path},
            )

        if status in (401, 403) and (
            provider_code in AUTH_FAILURE_CODES or provider_code is None or status == 401
        ):
            if "session" in path.lower() and path.split("?")[0].rstrip("/").count("/") <= 2:
                raise SessionExpired(
                    "La session Enable Banking est expirée, révoquée ou invalide. "
                    "Relancez 'bnp-sidecar auth link'.",
                    details={"status": status, "providerCode": provider_code},
                )
            raise AuthenticationError(
                "Enable Banking a refusé l'authentification. Vérifiez "
                "l'application ID et la clé privée.",
                details={"status": status, "providerCode": provider_code},
            )

        if status == 404:
            if "/accounts/" in path:
                raise NotFoundError(
                    "Compte ou transaction introuvable dans la session Enable Banking.",
                    details={"status": status, "providerCode": provider_code},
                )
            if path.startswith("/sessions/"):
                raise SessionExpired(
                    "La session Enable Banking n'existe plus ou a expiré. "
                    "Relancez 'bnp-sidecar auth link'.",
                    details={"status": status, "providerCode": provider_code},
                )
            raise NotFoundError(
                message or "Ressource Enable Banking introuvable.",
                details={"status": status, "providerCode": provider_code},
            )

        if status == 429:
            raise UpstreamError(
                "Enable Banking limite temporairement les requêtes. Réessayez plus tard.",
                details={"status": status, "providerCode": provider_code},
            )

        if provider_code in AUTH_FAILURE_CODES:
            raise SessionExpired(
                "La session Enable Banking est expirée ou révoquée.",
                details={"status": status, "providerCode": provider_code},
            )

        if status >= 500:
            raise UpstreamError(
                "Enable Banking rencontre une erreur côté serveur. Réessayez plus tard.",
                details={"status": status, "providerCode": provider_code},
            )

        raise UpstreamError(
            message or f"Requête Enable Banking refusée (HTTP {status}).",
            details={"status": status, "providerCode": provider_code},
        )

    # -- endpoints ---------------------------------------------------------

    def get_application(self) -> dict[str, Any]:
        payload = self._request("GET", "/application")
        return payload if isinstance(payload, dict) else {}

    def list_aspsps(self, country: str | None = None) -> list[dict[str, Any]]:
        payload = self._request(
            "GET", "/aspsps", query={"country": country or self.config.aspsp_country}
        )
        aspsps = payload.get("aspsps") if isinstance(payload, dict) else None
        if not isinstance(aspsps, list):
            raise UpstreamError("Réponse /aspsps invalide: liste d'établissements absente.")
        return [item for item in aspsps if isinstance(item, dict)]

    def find_aspsp(self, name: str | None = None, country: str | None = None) -> dict[str, Any]:
        wanted = (name or self.config.aspsp_name).strip()
        country_code = (country or self.config.aspsp_country).upper()
        candidates = [
            item
            for item in self.list_aspsps(country_code)
            if str(item.get("country") or country_code).upper() == country_code
        ]
        exact = [
            item
            for item in candidates
            if str(item.get("name") or "").strip().casefold() == wanted.casefold()
        ]
        if len(exact) == 1:
            return exact[0]
        if len(exact) > 1:
            raise UpstreamError(
                f"Plusieurs établissements correspondent à {wanted!r}. "
                "Précisez avec --country."
            )
        partial = [
            item
            for item in candidates
            if wanted.casefold() in str(item.get("name") or "").casefold()
        ]
        if len(partial) == 1:
            return partial[0]
        if not partial:
            raise NotFoundError(
                f"L'établissement {wanted!r} n'est pas disponible dans le pays {country_code}."
            )
        names = ", ".join(str(item.get("name")) for item in partial[:5])
        raise UpstreamError(
            f"Plusieurs établissements correspondent à {wanted!r}: {names}. "
            "Utilisez un nom exact."
        )

    def maximum_consent_seconds(self, aspsp: dict[str, Any]) -> int:
        try:
            maximum = int(aspsp.get("maximum_consent_validity"))
        except (TypeError, ValueError):
            maximum = MAX_CONSENT_SECONDS
        if maximum <= 0:
            maximum = MAX_CONSENT_SECONDS
        # Toujours rester sous le plafond de 180 jours et sous le maximum banque.
        return max(60, min(MAX_CONSENT_SECONDS, maximum) - CONSENT_SAFETY_MARGIN_SECONDS)

    def start_authorization(
        self,
        state: str,
        valid_until: datetime,
        *,
        aspsp_name: str | None = None,
        country: str | None = None,
        redirect_uri: str | None = None,
    ) -> dict[str, Any]:
        target_redirect = redirect_uri or self.config.redirect_uri
        if not state:
            raise ConfigError("État OAuth manquant pour démarrer l'autorisation.")
        payload = self._request(
            "POST",
            "/auth",
            body={
                "access": {"valid_until": valid_until.astimezone(UTC).isoformat()},
                "aspsp": {
                    "name": aspsp_name or self.config.aspsp_name,
                    "country": (country or self.config.aspsp_country).upper(),
                },
                "state": state,
                "redirect_url": target_redirect,
                "psu_type": self.config.psu_type,
                "language": self.config.language,
            },
        )
        if not isinstance(payload, dict) or not isinstance(payload.get("url"), str):
            raise UpstreamError("Réponse /auth invalide: URL d'autorisation absente.")
        auth_url = payload["url"].strip()
        parts = urllib.parse.urlsplit(auth_url)
        if parts.scheme != "https" or not parts.hostname:
            raise UpstreamError("L'URL d'autorisation renvoyée par Enable Banking n'est pas sûre.")
        return payload

    def create_session(self, code: str) -> dict[str, Any]:
        if not code or not code.strip():
            raise ConfigError("Code d'autorisation manquant.")
        payload = self._request("POST", "/sessions", body={"code": code.strip()})
        if not isinstance(payload, dict):
            raise UpstreamError("Réponse /sessions invalide.")
        if not payload.get("session_id"):
            raise UpstreamError("Réponse /sessions invalide: identifiant de session absent.")
        return payload

    def get_session(self, session_id: str) -> dict[str, Any]:
        if not session_id:
            raise ConfigError("Identifiant de session manquant.")
        payload = self._request(
            "GET", f"/sessions/{urllib.parse.quote(session_id, safe='')}"
        )
        if not isinstance(payload, dict):
            raise UpstreamError("Réponse de session invalide.")
        return payload

    def delete_session(self, session_id: str) -> None:
        if not session_id:
            return
        self._request("DELETE", f"/sessions/{urllib.parse.quote(session_id, safe='')}")

    def get_account_details(self, account_uid: str) -> dict[str, Any]:
        if not account_uid:
            raise ConfigError("Identifiant de compte manquant.")
        payload = self._request(
            "GET",
            f"/accounts/{urllib.parse.quote(account_uid, safe='')}/details",
        )
        if isinstance(payload, dict) and isinstance(payload.get("account"), dict):
            payload = payload["account"]
        if not isinstance(payload, dict):
            raise UpstreamError("Réponse de détails de compte invalide.")
        return payload

    def get_account_balances(self, account_uid: str) -> list[dict[str, Any]]:
        if not account_uid:
            raise ConfigError("Identifiant de compte manquant.")
        payload = self._request(
            "GET",
            f"/accounts/{urllib.parse.quote(account_uid, safe='')}/balances",
        )
        balances = payload.get("balances") if isinstance(payload, dict) else None
        if not isinstance(balances, list):
            raise UpstreamError("Réponse de soldes invalide: liste absente.")
        return [item for item in balances if isinstance(item, dict)]

    def get_transactions_page(
        self,
        account_uid: str,
        *,
        date_from: str | None = None,
        date_to: str | None = None,
        continuation_key: str | None = None,
        transaction_status: str | None = None,
        strategy: str | None = None,
    ) -> dict[str, Any]:
        if not account_uid:
            raise ConfigError("Identifiant de compte manquant.")
        payload = self._request(
            "GET",
            f"/accounts/{urllib.parse.quote(account_uid, safe='')}/transactions",
            query={
                "date_from": date_from,
                "date_to": date_to,
                "continuation_key": continuation_key,
                "transaction_status": transaction_status,
                "strategy": strategy,
            },
        )
        return payload if isinstance(payload, dict) else {}

    def get_all_transactions(
        self,
        account_uid: str,
        *,
        date_from: str | None = None,
        date_to: str | None = None,
        transaction_status: str | None = None,
        strategy: str | None = None,
        max_pages: int = 50,
    ) -> TransactionsResult:
        result = TransactionsResult()
        continuation_key: str | None = None
        seen_keys: set[str] = set()
        while True:
            payload = self.get_transactions_page(
                account_uid,
                date_from=date_from,
                date_to=date_to,
                continuation_key=continuation_key,
                transaction_status=transaction_status,
                strategy=strategy,
            )
            transactions = payload.get("transactions")
            if isinstance(transactions, list):
                result.transactions.extend(
                    item for item in transactions if isinstance(item, dict)
                )
            result.pages += 1
            next_key = payload.get("continuation_key")
            continuation_key = str(next_key).strip() if next_key else None
            if not continuation_key:
                break
            if continuation_key in seen_keys:
                result.warnings.append(
                    "Enable Banking a répété une clé de pagination; l'export est interrompu."
                )
                result.truncated = True
                result.continuation_key = continuation_key
                break
            seen_keys.add(continuation_key)
            if result.pages >= max_pages:
                result.warnings.append(
                    f"Limite de {max_pages} pages atteinte; l'export est tronqué."
                )
                result.truncated = True
                result.continuation_key = continuation_key
                break
        return result


def client_secrets(client: EnableBankingClient) -> list[str]:
    secrets = [client.config.application_id, client._private_key_pem]
    for line in client._private_key_pem.splitlines():
        if line and not line.startswith("-----"):
            secrets.append(line)
    return secrets


def is_loopback_redirect(uri: str) -> bool:
    return redirect_is_loopback(uri)
