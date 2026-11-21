"""Client direct BNP Paribas, en lecture seule.

Le flux de connexion actuel de BNP est un formulaire PingFederate protégé par
Akamai. Un client HTTP qui présente une empreinte TLS de Chrome (``curl_cffi``)
peut charger la page et soumettre le formulaire. Le mot de passe est converti
en positions de clavier, puis n'est plus conservé.

Aucun endpoint d'écriture bancaire n'est exposé par ce module.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Self
from urllib.parse import parse_qs, urljoin, urlparse

from ..errors import (
    AuthenticationError,
    ConfigError,
    SessionExpired,
    SidecarError,
    UpstreamError,
    UsageError,
)
from ..serialize import now_iso, totals_by_currency
from .login import (
    LOGIN_ENTRY,
    LoginForm,
    MfaChallenge,
    MfaForm,
    build_login_form_data,
    is_mfa_page,
    parse_login_page,
    parse_mfa_page,
)

_FAMILY_TO_TYPE: dict[int, tuple[str, str, str]] = {
    1: ("checking", "Compte courant", "banking"),
    2: ("savings", "Épargne", "savings"),
    3: ("deposit", "Dépôt", "deposit"),
    4: ("securities", "Compte-titres", "trading"),
    5: ("life_insurance", "Assurance-vie", "insurance"),
    6: ("life_insurance", "Assurance-vie", "insurance"),
    8: ("loan", "Crédit", "loan"),
    9: ("loan", "Crédit", "loan"),
}

_TRANSACTION_TYPES: dict[int, str] = {
    1: "check",
    2: "check",
    3: "cash_deposit",
    4: "transfer",
    5: "transfer",
    6: "loan_payment",
    7: "card",
    8: "card",
    9: "securities",
    10: "trade_bill",
    11: "withdrawal",
    12: "international",
    13: "card",
    14: "withdrawal",
    15: "bank_fee",
    30: "other",
}

_READ_ENDPOINTS = {
    "/serviceinfosclient-wspl/rpc/InfosClient",
    "/udc-wspl/rest/getlstcpt",
    "/rib-wspl/rpc/comptes",
}

_READ_POST_ENDPOINTS = {
    "/rop2-wspl/rest/releveOp",
    # Ancien endpoint, encore actif pour certains profils et nécessaire pour
    # obtenir plus d'un an d'historique.
    "/rop-wspl/rest/releveOp",
}

_ALLOWED_REDIRECT_HOSTS = {
    "mabanque.bnpparibas",
    "mabanqueprivee.bnpparibas",
    "connexion.mabanque.bnpparibas",
    "content.connexion.mabanque.bnpparibas",
    "www.hellobank.fr",
    "connexion.hellobank.fr",
    "espace-client.hellobank.fr",
}

_IBAN_RE = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}")


class DirectMFARequired(AuthenticationError):
    """Une validation forte BNP est nécessaire pour terminer la connexion."""

    code = "MFA_REQUIRED"


MfaDecision = dict[str, Any]
MfaHandler = Callable[[MfaChallenge], MfaDecision | None]


def _mfa_details(challenge: MfaChallenge) -> dict[str, Any]:
    return {"kind": challenge.kind, "structure": challenge.structure}


def _load_curl_cffi() -> Any:
    try:
        from curl_cffi import requests as curl_requests
    except ImportError as exc:  # pragma: no cover - dépend de l'environnement
        raise ConfigError(
            "Le mode direct nécessite le paquet curl_cffi. "
            "Installez-le avec: pip install 'bnp-sidecar[direct]'."
        ) from exc
    return curl_requests


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        if any(
            key in value
            for key in ("libelleOperation", "dateOperation", "idOperation", "montant")
        ):
            return [value]
        return [item for item in value.values() if isinstance(item, dict)]
    return list(value)


def _iter_dicts(value: Any) -> Iterable[dict[str, Any]]:
    """Parcourt récursivement les dictionnaires d'une réponse JSON."""
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _iter_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_dicts(child)


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_amount(value: Any) -> float | None:
    """Convertit un montant BNP (nombre, chaîne, ou objet ``montant``)."""
    for _ in range(3):
        if isinstance(value, dict):
            value = value.get("montant", value.get("amount"))
            continue
        break
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, str):
        text = value.replace("\u00a0", "").replace("\u202f", "")
        text = text.replace(" ", "").replace(",", ".")
    else:
        return None
    if not text:
        return None
    try:
        parsed = Decimal(text)
    except InvalidOperation:
        return None
    if not parsed.is_finite():
        return None
    return float(parsed)


def parse_bnp_date(value: Any) -> str | None:
    """Normalise les dates BNP en ``YYYY-MM-DD``.

    Les opérations utilisent ``JJ-MM-AAAA`` ; les soldes peuvent utiliser une
    autre forme. Les formats ISO et à slash sont acceptés par prudence.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip()[:10]
    if not candidate:
        return None
    for fmt in ("%d-%m-%Y", "%d/%m/%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(candidate, fmt).date().isoformat()
        except ValueError:
            continue
    return None


def normalize_iban(value: Any) -> str | None:
    """Retourne un IBAN valide, ou ``None``.

    BNP renvoie parfois un RIB de 21 chiffres dans le champ ``iban``. Il n'est
    pas accepté comme IBAN : mieux vaut un champ vide qu'un identifiant faux.
    """
    if not isinstance(value, str):
        return None
    candidate = re.sub(r"\s+", "", value).upper()
    if not _IBAN_RE.fullmatch(candidate):
        return None
    rearranged = candidate[4:] + candidate[:4]
    numeric = "".join(
        str(int(character, 36)) if character.isalpha() else character
        for character in rearranged
    )
    try:
        if int(numeric) % 97 != 1:
            return None
    except ValueError:
        return None
    return candidate


def rib_to_iban(value: Any) -> str | None:
    """Convertit un RIB français (21 ou 23 chiffres) en IBAN validé.

    Certains comptes BNP (livrets notamment) exposent un RIB plutôt qu'un
    IBAN. La clé du RIB est recalculée ; un RIB fourni avec une clé
    incorrecte est refusé.
    """
    if not isinstance(value, str):
        return None
    digits = re.sub(r"\s+", "", value)
    if not digits.isdigit() or len(digits) not in (21, 23):
        return None
    rib = digits[:21]
    try:
        rest = (
            89 * int(rib[:5]) + 15 * int(rib[5:10]) + 3 * int(rib[10:21])
        ) % 97
    except ValueError:
        return None
    key = 97 - rest
    if len(digits) == 23 and int(digits[21:23]) != key:
        return None
    iban_body = f"{rib}{key:02d}"
    rearranged = iban_body + "FR00"
    numeric = "".join(
        str(int(char, 36)) if char.isalpha() else char for char in rearranged
    )
    checksum = 98 - int(numeric) % 97
    return normalize_iban(f"FR{checksum:02d}{iban_body}")


def account_type(family_id: int, product: str | None) -> tuple[str, str, str]:
    """Mappe une famille BNP vers le type normalisé du sidecar."""
    label = (product or "").casefold()
    if "pea" in label:
        return ("pea", "PEA", "trading")
    if any(term in label for term in ("livret", "ldds", "lep", "pel", "cel")):
        return ("savings", "Épargne", "savings")
    if any(term in label for term in ("assurance vie", "assurance-vie", "multisupport")):
        return ("life_insurance", "Assurance-vie", "insurance")
    if any(term in label for term in ("crédit", "credit", "prêt", "pret", "loan")):
        return ("loan", "Crédit", "loan")
    return _FAMILY_TO_TYPE.get(int(family_id or 0), ("unknown", "Compte", "unknown"))


@dataclass
class DirectAccount:
    key: str
    family_id: int
    name: str
    product: str | None
    currency: str
    balance: float | None
    available_balance: float | None
    coming_balance: float | None
    masked_number: str | None
    iban: str | None
    type_key: str
    type_label: str
    kind: str
    balance_date: str | None = None
    raw: dict[str, Any] | None = None

    def to_payload(
        self,
        transactions: list[dict[str, Any]] | None = None,
        *,
        include_raw: bool = False,
    ) -> dict[str, Any]:
        balances: list[dict[str, Any]] = []
        if self.balance is not None:
            balances.append(
                {
                    "type": "CLBD",
                    "name": "Solde",
                    "amount": self.balance,
                    "currency": self.currency,
                    "referenceDate": self.balance_date,
                    "lastChangeDateTime": None,
                }
            )
        if self.available_balance is not None and self.available_balance != self.balance:
            balances.append(
                {
                    "type": "CLAV",
                    "name": "Solde disponible",
                    "amount": self.available_balance,
                    "currency": self.currency,
                    "referenceDate": self.balance_date,
                    "lastChangeDateTime": None,
                }
            )
        payload: dict[str, Any] = {
            "uid": self.key,
            "externalId": f"bnp_{self.key}",
            "identificationHash": None,
            "name": self.name,
            "product": self.product,
            "iban": self.iban,
            "currency": self.currency,
            "type": self.type_key.lower(),
            "typeLabel": self.type_label,
            "kind": self.kind,
            "cashAccountType": None,
            "usage": None,
            "balance": self.balance,
            "balanceType": "CLBD" if self.balance is not None else None,
            "balanceDate": self.balance_date,
            "availableBalance": self.available_balance,
            "availableBalanceType": "CLAV"
            if self.available_balance is not None
            else None,
            "creditLimit": None,
            "balances": balances,
            "comingBalance": self.coming_balance,
            "maskedNumber": self.masked_number,
        }
        if transactions is not None:
            payload["transactions"] = transactions
            payload["transactionPages"] = 1
            payload["transactionsTruncated"] = False
        if include_raw and self.raw is not None:
            payload["raw"] = self.raw
        return payload


@dataclass
class DirectTransaction:
    id: str
    booking_date: str | None
    value_date: str | None
    label: str
    amount: float
    category: str | None
    kind: str
    raw: dict[str, Any] | None = None

    def to_payload(
        self,
        *,
        account_key: str,
        currency: str,
        include_raw: bool = False,
    ) -> dict[str, Any]:
        lines = [self.label] if self.label else ["Transaction"]
        payload: dict[str, Any] = {
            "id": self.id,
            "dedupKey": f"bnp:{account_key}:{self.id}",
            "entryReference": self.id,
            "transactionId": self.id,
            "bookingDate": self.booking_date,
            "valueDate": self.value_date,
            "transactionDate": self.booking_date,
            "status": "BOOK",
            "direction": "DBIT" if self.amount < 0 else "CRDT",
            "amount": self.amount,
            "currency": currency,
            "description": " ".join(lines),
            "descriptionLines": lines,
            "counterparty": None,
            "merchantCategoryCode": None,
            "referenceNumber": None,
            "bankTransactionCode": None,
            "bankTransactionLabel": None,
            "balanceAfter": None,
            "note": None,
            "category": self.category,
            "type": self.kind,
        }
        if include_raw and self.raw is not None:
            payload["raw"] = self.raw
        return payload


def parse_accounts_payload(
    payload: Mapping[str, Any],
    ibans: Mapping[str, str] | None = None,
    *,
    include_raw: bool = False,
) -> tuple[list[DirectAccount], list[str]]:
    """Extrait les comptes de ``getlstcpt`` et applique les types BNP."""
    data = payload.get("data") if isinstance(payload, dict) else None
    info = data.get("infoUdc") if isinstance(data, dict) else None
    if not isinstance(info, dict):
        info = {}
    families = _as_list(info.get("familleCompte"))
    iban_map = dict(ibans or {})
    accounts: list[DirectAccount] = []
    warnings: list[str] = []

    for family in families:
        if not isinstance(family, dict):
            continue
        try:
            family_id = int(family.get("idFamilleCompte") or 0)
        except (TypeError, ValueError):
            family_id = 0
        for item in _as_list(family.get("compte")):
            if not isinstance(item, dict):
                continue
            key = _text(item.get("key")) or _text(item.get("ibanCrypte"))
            if not key:
                warnings.append("Un compte BNP sans identifiant a été ignoré.")
                continue
            product = _text(item.get("libelleProduit"))
            name = (
                _text(item.get("libellePersoProduit"))
                or product
                or "Compte BNP"
            )
            type_key, type_label, kind = account_type(family_id, product or name)
            currency = (_text(item.get("devise")) or "EUR").upper()
            # ``soldeComptable`` est le solde comptabilisé (CLBD). Le solde
            # disponible ne doit pas le remplacer : il peut inclure des
            # opérations non encore comptabilisées.
            balance = parse_amount(item.get("soldeComptable"))
            if balance is None:
                balance = parse_amount(item.get("solde"))
            if balance is None:
                balance = parse_amount(item.get("soldeDispo"))
            available = parse_amount(item.get("soldeDispo"))
            if available is None:
                available = balance
            coming = parse_amount(item.get("soldeAVenir"))
            iban = (
                iban_map.get(key)
                or normalize_iban(item.get("iban"))
                or rib_to_iban(item.get("iban"))
            )
            accounts.append(
                DirectAccount(
                    key=key,
                    family_id=family_id,
                    name=name,
                    product=product,
                    currency=currency,
                    balance=balance,
                    available_balance=available,
                    coming_balance=coming,
                    masked_number=_text(item.get("value")),
                    iban=iban,
                    type_key=type_key,
                    type_label=type_label,
                    kind=kind,
                    balance_date=parse_bnp_date(
                        item.get("dateSolde") or item.get("dateMouvement")
                    ),
                    raw=dict(item) if include_raw else None,
                )
            )
    if not accounts:
        warnings.append("Aucun compte BNP n'a été trouvé dans la réponse.")
    return accounts, warnings


def _transaction_id(
    operation: Mapping[str, Any],
    *,
    account_key: str,
    index: int,
    amount: float,
    label: str,
    booking_date: str | None,
) -> str:
    explicit = _text(operation.get("idOperation"))
    if explicit:
        return explicit
    seed = "|".join(
        (
            account_key,
            booking_date or "",
            str(amount),
            label,
            str(index),
        )
    )
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def parse_transactions_payload(
    payload: Mapping[str, Any],
    *,
    account_key: str,
    currency: str = "EUR",
    include_raw: bool = False,
) -> list[DirectTransaction]:
    """Extrait les opérations passées de ``releveOp``."""
    data = payload.get("data") if isinstance(payload, dict) else None
    operations = data.get("listerOperations") if isinstance(data, dict) else None
    compte = operations.get("compte") if isinstance(operations, dict) else None
    raw_operations = _as_list((compte or {}).get("operationPassee"))
    transactions: list[DirectTransaction] = []

    for index, operation in enumerate(raw_operations):
        if not isinstance(operation, dict):
            continue
        label = _text(operation.get("libelleOperation")) or "Transaction"
        amount = parse_amount(operation.get("montant"))
        if amount is None:
            continue
        booking_date = parse_bnp_date(operation.get("dateOperation"))
        montant = operation.get("montant")
        value_date = None
        if isinstance(montant, dict):
            value_date = parse_bnp_date(montant.get("valueDate"))
        try:
            code = int((operation.get("operationType") or {}).get("codeFamille") or 0)
        except (TypeError, ValueError):
            code = 0
        transactions.append(
            DirectTransaction(
                id=_transaction_id(
                    operation,
                    account_key=account_key,
                    index=index,
                    amount=amount,
                    label=label,
                    booking_date=booking_date,
                ),
                booking_date=booking_date,
                value_date=value_date,
                label=label,
                amount=amount,
                category=_text(operation.get("categorie")),
                kind=_TRANSACTION_TYPES.get(code, "other"),
                raw=dict(operation) if include_raw else None,
            )
        )
    return transactions


def _merge_transactions(
    primary: Iterable[DirectTransaction],
    older: Iterable[DirectTransaction],
) -> list[DirectTransaction]:
    """Fusionne deux historiques en dédupliquant par identifiant BNP.

    Les opérations identiques d'un même historique restent distinctes : seule
    une opération déjà connue par son ``idOperation`` est écartée.
    """
    merged: dict[str, DirectTransaction] = {item.id: item for item in primary}
    for item in older:
        merged.setdefault(item.id, item)
    return list(merged.values())


def _parse_iso_date(value: str | None, label: str) -> date:
    if not value:
        return date.today()
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise UsageError(f"{label} doit être au format YYYY-MM-DD.") from exc


def _one_year_before(value: date) -> date:
    """Recule d'un an, y compris depuis un 29 février."""
    try:
        return value.replace(year=value.year - 1)
    except ValueError:
        return value.replace(year=value.year - 1, day=28)


class BnpDirectClient:
    """Session BNP directe, sans persistance des cookies ni du mot de passe."""

    def __init__(
        self,
        *,
        session: Any | None = None,
        timeout: float = 30.0,
        include_raw: bool = False,
        mfa_handler: MfaHandler | None = None,
    ) -> None:
        self._session = session
        self._timeout = timeout
        self._include_raw = include_raw
        self._mfa_handler = mfa_handler
        self._base_url: str | None = None
        self.warnings: list[str] = []

    # ------------------------------------------------------------------ session
    @property
    def session(self) -> Any:
        if self._session is None:
            curl_requests = _load_curl_cffi()
            self._session = curl_requests.Session(impersonate="chrome")
        return self._session

    @property
    def base_url(self) -> str | None:
        return self._base_url

    def _send(self, method: str, url: str, **kwargs: Any) -> Any:
        """Envoie une requête HTTP et convertit les erreurs réseau."""
        try:
            return self.session.request(method, url, **kwargs)
        except Exception as exc:
            raise UpstreamError(
                "Impossible de joindre BNP. Vérifiez la connexion réseau "
                "et réessayez."
            ) from exc

    def close(self) -> None:
        session = self._session
        self._session = None
        self._base_url = None
        if session is not None:
            with contextlib.suppress(Exception):  # pragma: no cover - best effort
                session.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------- login
    def probe_login_page(self) -> LoginForm:
        """Charge la page de connexion sans soumettre d'identifiant."""
        response = self._send(
            "GET",
            LOGIN_ENTRY,
            allow_redirects=True,
            timeout=self._timeout,
            headers={
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,*/*;q=0.8"
                ),
                "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
                "Upgrade-Insecure-Requests": "1",
            },
        )
        if response.status_code == 403:
            raise UpstreamError(
                "BNP a bloqué la requête de connexion (Akamai 403). "
                "Le client HTTP n'a pas pu se faire passer pour un navigateur."
            )
        if response.status_code >= 400:
            raise UpstreamError(
                f"La page de connexion BNP a répondu HTTP {response.status_code}."
            )
        return parse_login_page(response.text, response.url)

    def login(self, customer_id: str, password: str) -> str:
        """Ouvre une session BNP et retourne l'URL de base du site connecté."""
        form = self.probe_login_page()
        data = build_login_form_data(form, customer_id, password)
        del password
        action_parts = urlparse(form.action)
        headers = {
            "Referer": form.page_url,
            "Origin": f"{action_parts.scheme}://{action_parts.netloc}",
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded",
            "Upgrade-Insecure-Requests": "1",
        }
        try:
            response = self._send(
                "POST",
                form.action,
                data=data,
                headers=headers,
                allow_redirects=False,
                timeout=self._timeout,
            )
        finally:
            data.clear()

        response = self._follow_redirects(response)
        response = self._resolve_mfa(response)
        self._raise_for_login_error(response)
        self._base_url = self._landing_base(response.url)
        self._verify_session()
        # Rejoue la dernière étape sur l'hôte de base pour les cookies de session.
        # Un échec ici n'invalide pas la session déjà vérifiée par InfosClient.
        with contextlib.suppress(SidecarError):
            self._get_html("/fr/secure/comptes-et-contrats")
        return self._base_url

    def _follow_redirects(self, response: Any) -> Any:
        for _ in range(20):
            if response.status_code not in (301, 302, 303, 307, 308):
                return response
            location = response.headers.get("location")
            if not location:
                return response
            next_url = urljoin(response.url, location)
            if not self._redirect_allowed(next_url):
                raise UpstreamError(
                    "La connexion BNP a été redirigée vers un hôte inattendu."
                )
            if response.status_code in (307, 308):
                raise UpstreamError(
                    "La connexion BNP a demandé une redirection non gérée."
                )
            response = self._send(
                "GET",
                next_url,
                allow_redirects=False,
                timeout=self._timeout,
                headers={
                    "Referer": response.url,
                    "Accept": (
                        "text/html,application/xhtml+xml,application/xml;q=0.9,"
                        "image/avif,image/webp,*/*;q=0.8"
                    ),
                    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
                },
            )
        raise UpstreamError("Trop de redirections lors de la connexion BNP.")

    @staticmethod
    def _redirect_allowed(url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return host in _ALLOWED_REDIRECT_HOSTS

    @staticmethod
    def _landing_base(url: str) -> str:
        host = (urlparse(url).hostname or "").lower()
        if host in ("mabanque.bnpparibas", "mabanqueprivee.bnpparibas"):
            return f"https://{host}"
        if host in _ALLOWED_REDIRECT_HOSTS:
            return f"https://{host}"
        return "https://mabanque.bnpparibas"

    # -------------------------------------------------------------------- MFA
    def _resolve_mfa(self, response: Any) -> Any:
        """Rejoue la validation forte avec l'aide de l'utilisateur.

        Le gestionnaire fourni par la CLI choisit l'action (code SMS, attente
        d'une validation dans l'application, formulaire ou lien). Sans
        gestionnaire, une erreur structurée est renvoyée, sans aucun secret.
        """
        for _ in range(6):
            html = response.text or ""
            if not is_mfa_page(html, response.url):
                return response
            challenge = parse_mfa_page(html, response.url)
            if self._mfa_handler is None:
                raise DirectMFARequired(
                    "BNP demande une validation forte. Terminez la validation "
                    "dans l'application BNP, puis relancez la commande.",
                    details=_mfa_details(challenge),
                )
            decision = self._mfa_handler(challenge)
            if not decision:
                raise DirectMFARequired(
                    "Validation forte BNP non terminée.",
                    details=_mfa_details(challenge),
                )
            response = self._apply_mfa_decision(challenge, decision)
            response = self._follow_redirects(response)
            self._raise_for_non_mfa_error(response)
        raise UpstreamError(
            "La validation forte BNP n'a pas abouti après plusieurs étapes."
        )

    def _apply_mfa_decision(
        self, challenge: MfaChallenge, decision: Mapping[str, Any]
    ) -> Any:
        action = str(decision.get("type") or "")
        if action == "code":
            code = str(decision.get("code") or "")
            if not re.fullmatch(r"[0-9]{4,10}", code):
                raise UsageError(
                    "Le code de validation BNP doit contenir 4 à 10 chiffres."
                )
            return self._submit_mfa_code(challenge, code)
        if action == "form":
            try:
                form_index = int(decision["form"])
            except (KeyError, TypeError, ValueError) as exc:
                raise UsageError("Formulaire de validation BNP invalide.") from exc
            raw_button = decision.get("button")
            try:
                button_index = int(raw_button) if raw_button is not None else None
            except (TypeError, ValueError) as exc:
                raise UsageError("Bouton de validation BNP invalide.") from exc
            return self._submit_mfa_form(challenge, form_index, button_index)
        if action == "link":
            href = str(decision.get("href") or "")
            if not href:
                raise UsageError("Lien de validation BNP invalide.")
            return self._open_mfa_link(challenge, href)
        if action == "continue":
            return self._continue_mfa(challenge)
        raise UsageError("Action de validation BNP inconnue.")

    @staticmethod
    def _mfa_form_data(form: MfaForm, skip: set[str]) -> dict[str, str]:
        data: dict[str, str] = {}
        for field in form.fields:
            if field.name in skip:
                continue
            if field.type in ("submit", "button", "reset", "file", "image"):
                continue
            if field.type in ("checkbox", "radio") and not field.checked:
                continue
            data[field.name] = field.value
        return data

    @staticmethod
    def _add_mfa_button(
        form: MfaForm,
        data: dict[str, str],
        button_index: int | None,
    ) -> None:
        buttons = [button for button in form.buttons if button.type in ("submit", "")]
        if not buttons:
            return
        if button_index is None:
            preferred = next(
                (
                    button
                    for button in buttons
                    if any(
                        word in button.label.casefold()
                        for word in ("valider", "continuer", "envoyer", "accéder", "confirmer")
                    )
                ),
                buttons[0],
            )
        else:
            if button_index < 0 or button_index >= len(form.buttons):
                raise UsageError("Bouton de validation BNP introuvable.")
            preferred = form.buttons[button_index]
        if preferred.name:
            data[preferred.name] = preferred.value or ""

    def _submit_mfa_code(self, challenge: MfaChallenge, code: str) -> Any:
        if not challenge.code_fields:
            raise UsageError("Aucun champ de code BNP n'a été trouvé.")
        form = next(
            (
                candidate
                for candidate in challenge.forms
                if any(
                    field.name == challenge.code_fields[0]
                    for field in candidate.fields
                )
            ),
            None,
        )
        if form is None:
            raise UsageError("Formulaire de code BNP introuvable.")
        data = self._mfa_form_data(form, set(challenge.code_fields))
        if len(challenge.code_fields) == 1:
            data[challenge.code_fields[0]] = code
        else:
            digits = list(code)
            if len(digits) != len(challenge.code_fields):
                raise UsageError(
                    "Le code de validation BNP n'a pas la longueur attendue."
                )
            for name, digit in zip(challenge.code_fields, digits):
                data[name] = digit
        self._add_mfa_button(form, data, None)
        return self._send_mfa_form(challenge, form, data)

    def _submit_mfa_form(
        self,
        challenge: MfaChallenge,
        form_index: int,
        button_index: int | None,
    ) -> Any:
        if form_index < 0 or form_index >= len(challenge.forms):
            raise UsageError("Formulaire de validation BNP introuvable.")
        form = challenge.forms[form_index]
        data = self._mfa_form_data(form, set())
        self._add_mfa_button(form, data, button_index)
        return self._send_mfa_form(challenge, form, data)

    def _send_mfa_form(
        self,
        challenge: MfaChallenge,
        form: MfaForm,
        data: dict[str, str],
    ) -> Any:
        action = urljoin(challenge.page_url, form.action)
        if not self._redirect_allowed(action):
            raise UpstreamError(
                "Le formulaire de validation BNP pointe vers un hôte inattendu."
            )
        parts = urlparse(action)
        headers = {
            "Referer": challenge.page_url,
            "Origin": f"{parts.scheme}://{parts.netloc}",
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
            "Upgrade-Insecure-Requests": "1",
        }
        try:
            if form.method == "get":
                response = self._send(
                    "GET",
                    action,
                    params=data,
                    allow_redirects=False,
                    timeout=self._timeout,
                    headers=headers,
                )
            else:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                response = self._send(
                    "POST",
                    action,
                    data=data,
                    allow_redirects=False,
                    timeout=self._timeout,
                    headers=headers,
                )
        finally:
            data.clear()
        return response

    def _continue_mfa(self, challenge: MfaChallenge) -> Any:
        return self._send(
            "GET",
            challenge.page_url,
            allow_redirects=False,
            timeout=self._timeout,
            headers={
                "Referer": challenge.page_url,
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,*/*;q=0.8"
                ),
                "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
            },
        )

    def _open_mfa_link(self, challenge: MfaChallenge, href: str) -> Any:
        url = urljoin(challenge.page_url, href)
        if not self._redirect_allowed(url):
            raise UpstreamError(
                "Le lien de validation BNP pointe vers un hôte inattendu."
            )
        return self._send(
            "GET",
            url,
            allow_redirects=False,
            timeout=self._timeout,
            headers={
                "Referer": challenge.page_url,
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,*/*;q=0.8"
                ),
                "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
            },
        )

    def _raise_for_login_error(self, response: Any) -> None:
        html = response.text or ""
        if is_mfa_page(html, response.url):
            challenge = parse_mfa_page(html, response.url)
            raise DirectMFARequired(
                "BNP demande une validation forte. Terminez la validation "
                "dans l'application BNP, puis relancez la commande.",
                details=_mfa_details(challenge),
            )
        self._raise_for_non_mfa_error(response)

    def _raise_for_non_mfa_error(self, response: Any) -> None:
        parsed = urlparse(response.url)
        query = parse_qs(parsed.query)
        error_code = (query.get("error_code") or query.get("errorCode") or [None])[0]
        if error_code:
            raise AuthenticationError(
                f"Connexion BNP refusée (code {error_code}).",
                details={"errorCode": error_code},
            )
        body = response.text or ""
        lowered_url = response.url.casefold()
        if any(
            marker in lowered_url
            for marker in (
                "mot-de-passe-expire",
                "changer-son-mot-de-passe",
                "/100-connexion",
            )
        ):
            raise AuthenticationError(
                "Le code secret BNP doit être changé sur le site BNP avant "
                "de pouvoir utiliser l'accès direct."
            )
        if (
            parsed.hostname in {"connexion.mabanque.bnpparibas", "connexion.hellobank.fr"}
            and 'id="identForm"' in body
        ):
            raise AuthenticationError(
                "Connexion BNP refusée : identifiants invalides ou étape "
                "supplémentaire demandée."
            )
        if response.status_code >= 400:
            raise AuthenticationError(
                f"La connexion BNP a échoué (HTTP {response.status_code})."
            )

    def _verify_session(self) -> None:
        last_error: SidecarError | None = None
        for attempt in range(2):
            try:
                payload = self._get_json(
                    "/serviceinfosclient-wspl/rpc/InfosClient",
                    params={"modeAppel": "0"},
                )
            except SidecarError as exc:
                last_error = exc
                if attempt == 0:
                    try:
                        self._get_html("/fr/secure/comptes-et-contrats")
                    except SidecarError:
                        pass
                    continue
                raise
            code = str(payload.get("codeRetour", ""))
            message = str(payload.get("message", ""))
            if code in ("", "0", "None") and message.upper() in ("", "OK"):
                return
            last_error = AuthenticationError(
                "La session BNP n'est pas authentifiée.",
                details={"codeRetour": code, "message": message[:200]},
            )
        if last_error is not None:
            raise last_error
        raise AuthenticationError("La session BNP n'est pas authentifiée.")

    # -------------------------------------------------------------------- HTTP
    def _url(self, path: str) -> str:
        if not self._base_url:
            raise UpstreamError("La session BNP n'est pas ouverte.")
        return urljoin(self._base_url + "/", path.lstrip("/"))

    @staticmethod
    def _endpoint_allowed(method: str, path: str) -> bool:
        clean = path.split("?", 1)[0]
        if method == "GET":
            return clean in _READ_ENDPOINTS
        if method == "POST":
            return clean in _READ_POST_ENDPOINTS
        return False

    def _read_request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, str] | None = None,
        json_body: Mapping[str, Any] | None = None,
    ) -> Any:
        """Exécute une lecture en suivant les redirections de façon contrôlée.

        ``curl_cffi`` suivrait automatiquement une redirection vers n'importe
        quel hôte. Ici chaque saut est validé avant d'envoyer la requête, afin
        qu'aucun cookie de session ne puisse être dirigé vers un domaine
        inattendu.
        """
        current_method = method.upper()
        current_url = url
        current_params = params
        current_body = json_body
        current_headers = dict(headers)
        for _ in range(10):
            kwargs: dict[str, Any] = {
                "allow_redirects": False,
                "timeout": self._timeout,
                "headers": current_headers,
            }
            if current_params is not None:
                kwargs["params"] = current_params
            if current_body is not None:
                kwargs["json"] = current_body
            response = self._send(current_method, current_url, **kwargs)
            if response.status_code not in (301, 302, 303, 307, 308):
                if not self._redirect_allowed(response.url):
                    raise UpstreamError(
                        "La réponse BNP provient d'un hôte inattendu."
                    )
                return response
            location = response.headers.get("location")
            if not location:
                return response
            next_url = urljoin(response.url, location)
            if not self._redirect_allowed(next_url):
                raise UpstreamError(
                    "La réponse BNP a été redirigée vers un hôte inattendu."
                )
            if response.status_code in (301, 302, 303):
                current_method = "GET"
                current_params = None
                current_body = None
                current_headers = {
                    key: value
                    for key, value in current_headers.items()
                    if key.lower() != "content-type"
                }
            current_url = next_url
            current_headers["Referer"] = response.url
        raise UpstreamError("Trop de redirections lors de la lecture BNP.")

    def _get_html(self, path: str) -> Any:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
        }
        if self._base_url:
            headers["Referer"] = self._base_url + "/"
        response = self._read_request(
            "GET",
            self._url(path),
            headers=headers,
        )
        if response.status_code == 401:
            raise SessionExpired("La session BNP est expirée; reconnectez-vous.")
        if response.status_code >= 400:
            raise UpstreamError(
                f"La page BNP {path} a répondu HTTP {response.status_code}."
            )
        return response

    def _get_json(
        self,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        if not self._endpoint_allowed("GET", path):
            raise UsageError(f"Endpoint BNP non autorisé en lecture: {path}")
        response = self._read_request(
            "GET",
            self._url(path),
            params=params,
            headers={
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
                "Referer": self._base_url + "/fr/secure/comptes-et-contrats",
            },
        )
        if response.status_code == 401:
            raise SessionExpired("La session BNP est expirée; reconnectez-vous.")
        if response.status_code >= 400:
            raise UpstreamError(
                f"L'endpoint BNP {path} a répondu HTTP {response.status_code}."
            )
        try:
            payload = response.json()
        except Exception as exc:
            raise UpstreamError(
                f"L'endpoint BNP {path} n'a pas renvoyé de JSON valide."
            ) from exc
        if not isinstance(payload, dict):
            raise UpstreamError(f"L'endpoint BNP {path} a renvoyé un JSON inattendu.")
        self._check_payload(payload)
        return payload

    def _post_json(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        if not self._endpoint_allowed("POST", path):
            raise UsageError(f"Endpoint BNP non autorisé en lecture: {path}")
        response = self._read_request(
            "POST",
            self._url(path),
            json_body=body,
            headers={
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
                "Content-Type": "application/json",
                "Referer": self._base_url + "/fr/secure/comptes-et-contrats",
            },
        )
        if response.status_code == 401:
            raise SessionExpired("La session BNP est expirée; reconnectez-vous.")
        if response.status_code >= 400:
            raise UpstreamError(
                f"L'endpoint BNP {path} a répondu HTTP {response.status_code}."
            )
        try:
            payload = response.json()
        except Exception as exc:
            raise UpstreamError(
                f"L'endpoint BNP {path} n'a pas renvoyé de JSON valide."
            ) from exc
        if not isinstance(payload, dict):
            raise UpstreamError(f"L'endpoint BNP {path} a renvoyé un JSON inattendu.")
        self._check_payload(payload)
        return payload

    @staticmethod
    def _check_payload(payload: Mapping[str, Any]) -> None:
        code = payload.get("codeRetour")
        if code is None or str(code) == "0":
            return
        message = str(payload.get("message") or "")[:200]
        if str(code) in ("-10", "-30"):
            raise SessionExpired(
                "La session BNP est expirée; reconnectez-vous.",
                details={"codeRetour": str(code)},
            )
        raise UpstreamError(
            f"BNP a renvoyé une erreur (code {code}).",
            details={"codeRetour": str(code), "message": message},
        )

    # ------------------------------------------------------------------- data
    def _ibans(self) -> dict[str, str]:
        try:
            payload = self._get_json("/rib-wspl/rpc/comptes")
        except SidecarError as exc:
            self.warnings.append(f"IBAN indisponibles: {exc}")
            return {}
        data = payload.get("data") if isinstance(payload, dict) else None
        result: dict[str, str] = {}
        # La forme de ``listeRib`` varie : objet unique, liste, ou dictionnaire
        # indexé. On cherche donc récursivement les couples ibanCrypte/iban.
        for info in _iter_dicts(data):
            key = _text(info.get("ibanCrypte"))
            if not key or key in result:
                continue
            iban = normalize_iban(info.get("iban")) or rib_to_iban(info.get("iban"))
            if iban:
                result[key] = iban
        if not result:
            self.warnings.append(
                "Les IBAN n'ont pas pu être extraits de la réponse BNP."
            )
        return result

    def accounts(self) -> list[DirectAccount]:
        if not self._base_url:
            raise UpstreamError("La session BNP n'est pas ouverte.")
        payload = self._get_json("/udc-wspl/rest/getlstcpt")
        accounts, warnings = parse_accounts_payload(
            payload,
            self._ibans(),
            include_raw=self._include_raw,
        )
        self.warnings.extend(warnings)
        return accounts

    def transactions(
        self,
        account: DirectAccount,
        *,
        since: date,
        until: date,
    ) -> list[DirectTransaction]:
        if since > until:
            raise UsageError("La date de début doit précéder la date de fin.")
        body = {
            "ibanCrypte": account.key,
            "pastOrPending": 1,
            "triAV": 0,
            "startDate": since.strftime("%d%m%Y"),
            "endDate": until.strftime("%d%m%Y"),
        }
        payload = self._post_json("/rop2-wspl/rest/releveOp", body)
        transactions = parse_transactions_payload(
            payload,
            account_key=account.key,
            currency=account.currency,
            include_raw=self._include_raw,
        )
        # Le nouvel endpoint ne renvoie qu'environ un an d'historique. Pour les
        # périodes plus anciennes, l'ancien endpoint autorise jusqu'à trois ans.
        if since < date.today() - timedelta(days=365):
            transactions = self._with_old_history(
                account, body, transactions, since=since
            )
        return transactions

    def _with_old_history(
        self,
        account: DirectAccount,
        body: Mapping[str, Any],
        transactions: list[DirectTransaction],
        *,
        since: date,
    ) -> list[DirectTransaction]:
        old_body = dict(body)
        oldest = date.today() - timedelta(days=365 * 3)
        if since < oldest:
            old_body["startDate"] = oldest.strftime("%d%m%Y")
        try:
            payload = self._post_json("/rop-wspl/rest/releveOp", old_body)
        except SidecarError as exc:
            self.warnings.append(
                "Historique BNP de plus d'un an indisponible pour "
                f"{account.name}: {exc}"
            )
            return transactions
        older = parse_transactions_payload(
            payload,
            account_key=account.key,
            currency=account.currency,
            include_raw=self._include_raw,
        )
        if not older:
            return transactions
        return _merge_transactions(transactions, older)

    # ------------------------------------------------------------------ export
    def accounts_payload(self) -> dict[str, Any]:
        accounts = self.accounts()
        account_payloads = [
            account.to_payload(include_raw=self._include_raw) for account in accounts
        ]
        return {
            "schema": "bnp-sidecar/accounts/v1",
            "source": "direct",
            "generatedAt": now_iso(),
            "aspsp": "BNP Paribas",
            "country": "FR",
            "accounts": account_payloads,
            "totals": {"balances": totals_by_currency(account_payloads)},
            "status": "ok",
            "errors": [],
            "warnings": list(self.warnings),
        }

    def export(
        self,
        *,
        since: str | None = None,
        until: str | None = None,
        account_selectors: Iterable[str] | None = None,
        include_transactions: bool = True,
    ) -> dict[str, Any]:
        end = _parse_iso_date(until, "La date de fin")
        start = _parse_iso_date(since, "La date de début") if since else end
        if not since:
            start = _one_year_before(end)
        if start > end:
            raise UsageError("La date de début doit précéder la date de fin.")

        accounts = self.accounts()
        selected = self._select_accounts(accounts, account_selectors)
        account_payloads: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        total_transactions = 0
        returned_dates: list[str] = []

        for account in selected:
            transactions: list[dict[str, Any]] = []
            truncated = False
            if include_transactions:
                try:
                    parsed = self.transactions(account, since=start, until=end)
                except SidecarError as exc:
                    truncated = True
                    errors.append(
                        {
                            "account": account.key,
                            "step": "transactions",
                            "code": exc.code,
                            "message": str(exc),
                        }
                    )
                else:
                    transactions = [
                        transaction.to_payload(
                            account_key=account.key,
                            currency=account.currency,
                            include_raw=self._include_raw,
                        )
                        for transaction in parsed
                    ]
                    transactions.sort(
                        key=lambda item: item.get("bookingDate") or "", reverse=True
                    )
                    total_transactions += len(transactions)
                    returned_dates.extend(
                        transaction["bookingDate"]
                        for transaction in transactions
                        if transaction.get("bookingDate")
                    )
            account_payload = account.to_payload(
                transactions,
                include_raw=self._include_raw,
            )
            account_payload["transactionsTruncated"] = truncated
            account_payloads.append(account_payload)

        return {
            "schema": "bnp-sidecar/export/v1",
            "source": "direct",
            "generatedAt": now_iso(),
            "status": "ok" if not errors else "partial",
            "aspsp": "BNP Paribas",
            "country": "FR",
            "dateFrom": start.isoformat(),
            "dateTo": end.isoformat(),
            "returnedDateFrom": min(returned_dates) if returned_dates else None,
            "returnedDateTo": max(returned_dates) if returned_dates else None,
            "accounts": account_payloads,
            "totals": {
                "balances": totals_by_currency(account_payloads),
                "accounts": len(account_payloads),
                "transactions": total_transactions,
            },
            "errors": errors,
            "warnings": list(self.warnings),
        }

    @staticmethod
    def _select_accounts(
        accounts: list[DirectAccount],
        selectors: Iterable[str] | None,
    ) -> list[DirectAccount]:
        wanted = [selector.strip().casefold() for selector in (selectors or []) if selector.strip()]
        if not wanted:
            return accounts
        selected: list[DirectAccount] = []
        for account in accounts:
            haystack = " ".join(
                value
                for value in (
                    account.key,
                    f"bnp_{account.key}",
                    account.name,
                    account.product,
                    account.iban,
                )
                if value
            ).casefold()
            if any(selector in haystack for selector in wanted):
                selected.append(account)
        if not selected:
            raise UsageError("Aucun compte BNP ne correspond au sélecteur fourni.")
        return selected
