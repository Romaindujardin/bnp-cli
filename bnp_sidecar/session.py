"""Persistance de la session PSD2 et de l'état de liaison en cours.

La session Enable Banking est un bearer token : elle est traitée comme un
secret et stockée dans ``data/session.json`` en ``0600``. L'état de liaison
(``data/pending-link.json``) contient le ``state`` OAuth, à usage unique, et
expire rapidement.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .errors import SessionError, SessionExpired, UsageError
from .paths import SidecarPaths
from .private_files import read_private_json, write_private_json

SESSION_SCHEMA = "bnp-sidecar/session/v1"
PENDING_SCHEMA = "bnp-sidecar/pending-link/v1"
PENDING_TTL = timedelta(minutes=15)
STATE_BYTES = 32


def utc_now() -> datetime:
    return datetime.now(UTC)


def isoformat(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds")


def parse_datetime(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def new_state() -> str:
    return secrets.token_urlsafe(STATE_BYTES)


@dataclass(frozen=True)
class SessionAccount:
    uid: str
    identification_hash: str | None = None
    name: str | None = None
    product: str | None = None
    currency: str | None = None
    iban: str | None = None
    cash_account_type: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "identificationHash": self.identification_hash,
            "name": self.name,
            "product": self.product,
            "currency": self.currency,
            "iban": self.iban,
            "cashAccountType": self.cash_account_type,
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> SessionAccount:
        uid = str(payload.get("uid") or "").strip()
        if not uid:
            raise SessionError("Un compte de session n'a pas d'UID.")
        return cls(
            uid=uid,
            identification_hash=_optional_text(payload.get("identificationHash")),
            name=_optional_text(payload.get("name")),
            product=_optional_text(payload.get("product")),
            currency=_optional_text(payload.get("currency")),
            iban=_optional_text(payload.get("iban")),
            cash_account_type=_optional_text(payload.get("cashAccountType")),
        )


@dataclass
class SessionRecord:
    session_id: str
    created_at: str
    valid_until: str | None
    aspsp_name: str
    aspsp_country: str
    psu_type: str
    redirect_uri: str
    accounts: list[SessionAccount] = field(default_factory=list)
    authorized_at: str | None = None
    status: str | None = None
    schema: str = SESSION_SCHEMA

    def expires_at(self) -> datetime | None:
        return parse_datetime(self.valid_until)

    def is_expired(self, *, now: datetime | None = None) -> bool:
        expires = self.expires_at()
        if expires is None:
            return False
        return (now or utc_now()) >= expires

    def days_remaining(self, *, now: datetime | None = None) -> int | None:
        expires = self.expires_at()
        if expires is None:
            return None
        delta = expires - (now or utc_now())
        return max(0, delta.days)

    def summary(self) -> dict[str, Any]:
        return {
            "idMasked": mask_value(self.session_id),
            "status": self.status or ("EXPIRED" if self.is_expired() else "AUTHORIZED"),
            "createdAt": self.created_at,
            "authorizedAt": self.authorized_at,
            "validUntil": self.valid_until,
            "expiresAt": self.valid_until,
            "expired": self.is_expired(),
            "daysRemaining": self.days_remaining(),
            "aspsp": self.aspsp_name,
            "country": self.aspsp_country,
            "psuType": self.psu_type,
            "accounts": len(self.accounts),
        }

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "sessionId": self.session_id,
            "createdAt": self.created_at,
            "authorizedAt": self.authorized_at,
            "validUntil": self.valid_until,
            "status": self.status,
            "aspsp": {"name": self.aspsp_name, "country": self.aspsp_country},
            "psuType": self.psu_type,
            "redirectUri": self.redirect_uri,
            "accounts": [account.to_json() for account in self.accounts],
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> SessionRecord:
        schema = payload.get("schema")
        if schema not in (None, SESSION_SCHEMA):
            raise SessionError(f"Schéma de session inconnu: {schema!r}.")
        session_id = str(payload.get("sessionId") or "").strip()
        if not session_id:
            raise SessionError("La session enregistrée n'a pas d'identifiant.")
        aspsp = payload.get("aspsp") if isinstance(payload.get("aspsp"), dict) else {}
        accounts_payload = payload.get("accounts")
        if not isinstance(accounts_payload, list):
            raise SessionError("La session enregistrée n'a pas de liste de comptes.")
        accounts = [
            SessionAccount.from_json(item)
            for item in accounts_payload
            if isinstance(item, dict)
        ]
        return cls(
            session_id=session_id,
            created_at=str(payload.get("createdAt") or isoformat(utc_now())),
            valid_until=_optional_text(payload.get("validUntil")),
            aspsp_name=str(aspsp.get("name") or aspsp.get("aspsp") or ""),
            aspsp_country=str(aspsp.get("country") or ""),
            psu_type=str(payload.get("psuType") or "personal"),
            redirect_uri=str(payload.get("redirectUri") or ""),
            accounts=accounts,
            authorized_at=_optional_text(payload.get("authorizedAt")),
            status=_optional_text(payload.get("status")),
        )


@dataclass
class PendingLink:
    state: str
    created_at: str
    expires_at: str
    aspsp_name: str
    aspsp_country: str
    psu_type: str
    redirect_uri: str
    valid_until: str | None = None
    authorization_id: str | None = None
    schema: str = PENDING_SCHEMA

    def is_expired(self, *, now: datetime | None = None) -> bool:
        expires = parse_datetime(self.expires_at)
        if expires is None:
            return True
        return (now or utc_now()) >= expires

    def matches_state(self, candidate: str) -> bool:
        if not candidate:
            return False
        return secrets.compare_digest(self.state, candidate)

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "state": self.state,
            "createdAt": self.created_at,
            "expiresAt": self.expires_at,
            "authorizationId": self.authorization_id,
            "validUntil": self.valid_until,
            "aspsp": {"name": self.aspsp_name, "country": self.aspsp_country},
            "psuType": self.psu_type,
            "redirectUri": self.redirect_uri,
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> PendingLink:
        schema = payload.get("schema")
        if schema not in (None, PENDING_SCHEMA):
            raise SessionError(f"Schéma de liaison inconnu: {schema!r}.")
        state = str(payload.get("state") or "")
        if len(state) < 16:
            raise SessionError("L'état de liaison enregistré est invalide.")
        aspsp = payload.get("aspsp") if isinstance(payload.get("aspsp"), dict) else {}
        return cls(
            state=state,
            created_at=str(payload.get("createdAt") or isoformat(utc_now())),
            expires_at=str(payload.get("expiresAt") or isoformat(utc_now() + PENDING_TTL)),
            aspsp_name=str(aspsp.get("name") or ""),
            aspsp_country=str(aspsp.get("country") or ""),
            psu_type=str(payload.get("psuType") or "personal"),
            redirect_uri=str(payload.get("redirectUri") or ""),
            valid_until=_optional_text(payload.get("validUntil")),
            authorization_id=_optional_text(payload.get("authorizationId")),
        )


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def mask_value(value: str | None) -> str:
    if not value:
        return "…"
    if len(value) <= 8:
        return "…"
    return f"{value[:4]}…{value[-4:]}"


def save_session(paths: SidecarPaths, session: SessionRecord) -> None:
    paths.ensure()
    write_private_json(paths.session_file, session.to_json())


def load_session(paths: SidecarPaths) -> SessionRecord | None:
    if not paths.session_file.exists():
        return None
    if paths.session_file.is_symlink():
        raise SessionError(
            f"Le fichier de session {paths.session_file} est un lien symbolique; refus."
        )
    payload = read_private_json(
        paths.session_file, error_cls=SessionError, label="Session Enable Banking"
    )
    return SessionRecord.from_json(payload)


def require_session(paths: SidecarPaths) -> SessionRecord:
    session = load_session(paths)
    if session is None:
        raise SessionError(
            "Aucune session BNP n'est enregistrée. Lancez "
            "'bnp-sidecar auth link' pour autoriser l'accès en lecture."
        )
    if session.is_expired():
        raise SessionExpired(
            "La session BNP a expiré. Relancez 'bnp-sidecar auth link' pour "
            "renouveler le consentement PSD2."
        )
    return session


def delete_session_file(paths: SidecarPaths) -> bool:
    path = paths.session_file
    if path.is_symlink():
        raise SessionError(
            f"Le fichier de session {path} est un lien symbolique; suppression refusée."
        )
    if path.exists():
        path.unlink()
        return True
    return False


def save_pending_link(paths: SidecarPaths, pending: PendingLink) -> None:
    paths.ensure()
    write_private_json(paths.pending_link_file, pending.to_json())


def load_pending_link(paths: SidecarPaths) -> PendingLink | None:
    if not paths.pending_link_file.exists():
        return None
    if paths.pending_link_file.is_symlink():
        raise SessionError(
            f"Le fichier de liaison {paths.pending_link_file} est un lien symbolique; refus."
        )
    payload = read_private_json(
        paths.pending_link_file, error_cls=SessionError, label="Liaison BNP en cours"
    )
    return PendingLink.from_json(payload)


def delete_pending_link(paths: SidecarPaths) -> bool:
    path = paths.pending_link_file
    if path.is_symlink():
        raise SessionError(
            f"Le fichier de liaison {path} est un lien symbolique; suppression refusée."
        )
    if path.exists():
        path.unlink()
        return True
    return False


def account_from_api(entry: Any, identification_hash: str | None = None) -> SessionAccount | None:
    if isinstance(entry, str):
        uid = entry.strip()
        if not uid:
            return None
        return SessionAccount(uid=uid, identification_hash=identification_hash)
    if not isinstance(entry, dict):
        return None
    uid = str(entry.get("uid") or entry.get("account_id", {}).get("uid") or "").strip()
    if not uid:
        return None
    account_id = entry.get("account_id") if isinstance(entry.get("account_id"), dict) else {}
    iban = account_id.get("iban") or entry.get("iban")
    return SessionAccount(
        uid=uid,
        identification_hash=_optional_text(entry.get("identification_hash"))
        or identification_hash,
        name=_optional_text(entry.get("name")),
        product=_optional_text(entry.get("product")),
        currency=_optional_text(entry.get("currency")),
        iban=_optional_text(iban),
        cash_account_type=_optional_text(entry.get("cash_account_type")),
    )


def accounts_from_session_payload(payload: dict[str, Any]) -> list[SessionAccount]:
    """Extrait les comptes d'une réponse POST ou GET /sessions."""
    hashes: dict[str, str] = {}
    accounts_data = payload.get("accounts_data")
    if isinstance(accounts_data, list):
        for item in accounts_data:
            if isinstance(item, dict) and item.get("uid"):
                value = _optional_text(item.get("identification_hash"))
                if value:
                    hashes[str(item["uid"])] = value

    result: list[SessionAccount] = []
    seen: set[str] = set()
    accounts = payload.get("accounts")
    if isinstance(accounts, list):
        for entry in accounts:
            account = account_from_api(entry, hashes.get(str(entry)) if isinstance(entry, str) else None)
            if account is None or account.uid in seen:
                continue
            seen.add(account.uid)
            if account.identification_hash is None and account.uid in hashes:
                account = SessionAccount(
                    uid=account.uid,
                    identification_hash=hashes[account.uid],
                    name=account.name,
                    product=account.product,
                    currency=account.currency,
                    iban=account.iban,
                    cash_account_type=account.cash_account_type,
                )
            result.append(account)

    for uid, value in hashes.items():
        if uid in seen:
            continue
        seen.add(uid)
        result.append(SessionAccount(uid=uid, identification_hash=value))
    return result


def session_secrets(session: SessionRecord | None) -> list[str]:
    if session is None:
        return []
    return [session.session_id]


def pending_secrets(pending: PendingLink | None) -> list[str]:
    if pending is None:
        return []
    return [pending.state, *([pending.authorization_id] if pending.authorization_id else [])]


def select_accounts(session: SessionRecord, selectors: Iterable[str]) -> list[SessionAccount]:
    """Sélectionne des comptes par UID, hash, IBAN ou nom (insensible à la casse)."""
    wanted = [item.strip() for item in selectors if item and item.strip()]
    if not wanted:
        return list(session.accounts)
    selected: list[SessionAccount] = []
    for selector in wanted:
        lowered = selector.lower()
        matches = [
            account
            for account in session.accounts
            if selector == account.uid
            or lowered == (account.iban or "").lower()
            or lowered == (account.identification_hash or "").lower()
            or lowered == (account.name or "").lower()
            or lowered == (account.product or "").lower()
        ]
        if not matches:
            raise UsageError(f"Aucun compte ne correspond à {selector!r}.")
        if len(matches) > 1:
            labels = ", ".join(account.uid for account in matches)
            raise UsageError(
                f"Le sélecteur {selector!r} correspond à plusieurs comptes ({labels}). "
                "Utilisez l'UID."
            )
        if matches[0] not in selected:
            selected.append(matches[0])
    return selected
