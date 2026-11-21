"""CLI JSON du sidecar BNP Paribas (Enable Banking, lecture seule).

Toutes les commandes écrivent un objet JSON sur stdout. Les messages
humains (URL d'autorisation, progression) vont sur stderr. Les erreurs sont
sérialisées en JSON sur stderr avec un code de sortie stable.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
import urllib.parse
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .callback import CallbackServer
from .client import EnableBankingClient
from .config import (
    DEFAULT_ASPSP,
    DEFAULT_COUNTRY,
    DEFAULT_LANGUAGE,
    DEFAULT_PSU_TYPE,
    DEFAULT_REDIRECT_URI,
    AppConfig,
    config_secrets,
    config_summary,
    delete_config,
    load_config,
    mask_application_id,
    save_config,
)
from .errors import (
    ConfigError,
    ConsentDenied,
    LinkStateError,
    SessionError,
    SidecarError,
    UpstreamError,
    UsageError,
)
from .jwt import load_private_key, public_key_fingerprint
from .paths import SidecarPaths
from .private_files import (
    MAX_PRIVATE_FILE_BYTES,
    delete_private_file,
    private_file_info,
    read_private_text,
    write_private_json,
)
from .redact import Redactor
from .serialize import (
    accounts_payload,
    now_iso,
    serialize_account,
    serialize_transaction,
    sort_transactions,
    totals_by_currency,
)
from .session import (
    PendingLink,
    SessionAccount,
    SessionRecord,
    accounts_from_session_payload,
    delete_pending_link,
    delete_session_file,
    isoformat,
    load_pending_link,
    load_session,
    mask_value,
    new_state,
    pending_secrets,
    require_session,
    save_pending_link,
    save_session,
    select_accounts,
    session_secrets,
    utc_now,
)

JsonDict = dict[str, Any]
ClientFactory = Callable[[AppConfig, str], EnableBankingClient]
BrowserOpener = Callable[[str], bool]

MAX_CALLBACK_INPUT = 16 * 1024
DEFAULT_CALLBACK_TIMEOUT = 300.0


class SidecarArgumentParser(argparse.ArgumentParser):
    """Transforme les erreurs argparse en erreurs JSON."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise UsageError(message)


@dataclass
class CommandContext:
    paths: SidecarPaths
    stdin: TextIO
    stdout: TextIO
    stderr: TextIO
    redactor: Redactor
    client_factory: ClientFactory | None = None
    browser_opener: BrowserOpener | None = None

    def load_config(self) -> tuple[AppConfig, str]:
        config, private_key = load_config(self.paths)
        assert private_key is not None
        self.redactor.add_many(config_secrets(config, private_key))
        return config, private_key

    def client(self, config: AppConfig, private_key: str) -> EnableBankingClient:
        self.redactor.add_many(config_secrets(config, private_key))
        if self.client_factory is not None:
            return self.client_factory(config, private_key)
        return EnableBankingClient(config, private_key)

    def open_browser(self, url: str) -> bool:
        opener = self.browser_opener or webbrowser.open
        try:
            return bool(opener(url))
        except (OSError, webbrowser.Error):
            return False

    def write(self, payload: JsonDict) -> None:
        _write_json(self.stdout, payload)


def _write_json(stream: TextIO, payload: Any) -> None:
    stream.write(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    stream.write("\n")
    stream.flush()


def _error_payload(exc: BaseException, redactor: Redactor, debug: bool) -> tuple[int, JsonDict]:
    if isinstance(exc, SidecarError):
        exit_code = exc.exit_code
        payload: JsonDict = {
            "schema": "bnp-sidecar/error/v1",
            "ok": False,
            "error": {
                "code": exc.code,
                "message": redactor.text(str(exc)),
                "details": redactor.value(exc.details),
            },
        }
    else:
        exit_code = 1
        payload = {
            "schema": "bnp-sidecar/error/v1",
            "ok": False,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": redactor.text(f"Erreur interne: {exc}"),
                "details": {},
            },
        }
    if debug:
        payload["error"]["traceback"] = redactor.text(traceback.format_exc())
    return exit_code, payload


# -- arguments ------------------------------------------------------------


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Répertoire de données du sidecar (défaut: ~/.local/share/bnp-sidecar).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Ajoute la trace complète (masquée) aux erreurs.",
    )


def _add_account_selector(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--account",
        action="append",
        default=None,
        metavar="UID|IBAN|NOM",
        help="Limite la commande à un compte (répétable).",
    )


def _add_transaction_filters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--from", dest="date_from", metavar="YYYY-MM-DD", help="Date de début.")
    parser.add_argument("--to", dest="date_to", metavar="YYYY-MM-DD", help="Date de fin.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--pending",
        action="store_true",
        help="Ne demande que les transactions en attente (PDNG).",
    )
    group.add_argument(
        "--status",
        choices=["BOOK", "PDNG", "INFO", "OTHR"],
        help="Filtre le statut des transactions.",
    )
    parser.add_argument(
        "--strategy",
        choices=["default", "longest"],
        default="default",
        help="Stratégie de récupération Enable Banking (défaut: default).",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=50,
        help="Nombre maximal de pages par compte (défaut: 50).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Nombre maximal de transactions conservées par compte.",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Ajoute les objets Enable Banking bruts (données personnelles).",
    )


def build_parser() -> SidecarArgumentParser:
    parser = SidecarArgumentParser(
        prog="bnp-sidecar",
        description=(
            "Sidecar BNP Paribas en lecture seule via Enable Banking (PSD2/AIS): "
            "comptes, soldes et transactions en JSON."
        ),
    )
    _add_common(parser)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    auth = subparsers.add_parser("auth", help="Configure et gère la liaison Enable Banking.")
    auth_sub = auth.add_subparsers(dest="auth_command", required=True)

    setup = auth_sub.add_parser(
        "setup", help="Enregistre l'application ID, la clé privée et l'URL de redirection."
    )
    setup.add_argument("--application-id", required=True, help="Application ID Enable Banking.")
    key_group = setup.add_mutually_exclusive_group(required=True)
    key_group.add_argument(
        "--private-key",
        type=Path,
        help="Chemin du fichier PEM 0600 contenant la clé privée RSA.",
    )
    key_group.add_argument(
        "--private-key-stdin",
        action="store_true",
        help="Lit la clé privée PEM sur stdin (jamais en argv).",
    )
    setup.add_argument(
        "--redirect-uri",
        default=DEFAULT_REDIRECT_URI,
        help=f"URL de redirection enregistrée dans Enable Banking (défaut: {DEFAULT_REDIRECT_URI}).",
    )
    setup.add_argument("--aspsp", default=DEFAULT_ASPSP, help="Nom de l'établissement.")
    setup.add_argument("--country", default=DEFAULT_COUNTRY, help="Pays ISO-2 de l'établissement.")
    setup.add_argument(
        "--psu-type",
        choices=["personal", "business"],
        default=DEFAULT_PSU_TYPE,
        help="Type d'utilisateur PSD2.",
    )
    setup.add_argument("--language", default=DEFAULT_LANGUAGE, help="Langue du parcours bancaire.")

    link = auth_sub.add_parser(
        "link", help="Démarre l'autorisation BNP dans le navigateur et crée la session."
    )
    link.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_CALLBACK_TIMEOUT,
        help="Délai d'attente du callback en secondes (défaut: 300).",
    )
    link.add_argument(
        "--no-wait",
        action="store_true",
        help="Affiche l'URL et rend la main sans attendre le callback.",
    )
    link.add_argument(
        "--no-open",
        action="store_true",
        help="N'ouvre pas le navigateur automatiquement.",
    )
    link.add_argument(
        "--force",
        action="store_true",
        help="Remplace une session encore valide.",
    )

    complete = auth_sub.add_parser(
        "complete", help="Échange une URL de callback contre une session."
    )
    complete_group = complete.add_mutually_exclusive_group(required=True)
    complete_group.add_argument("--callback-url", help="URL de callback complète.")
    complete_group.add_argument(
        "--callback-url-stdin",
        action="store_true",
        help="Lit l'URL de callback sur stdin (évite le code en argv).",
    )

    auth_sub.add_parser("status", help="Affiche l'état de la configuration et de la session.")

    logout = auth_sub.add_parser("logout", help="Révoque et supprime la session locale.")
    logout.add_argument(
        "--forget",
        action="store_true",
        help="Supprime aussi l'application ID, la clé privée et le certificat local.",
    )

    accounts = subparsers.add_parser("accounts", help="Liste les comptes et les soldes.")
    _add_account_selector(accounts)
    accounts.add_argument("--raw", action="store_true", help="Ajoute les objets bruts.")

    transactions = subparsers.add_parser("transactions", help="Liste les transactions.")
    _add_account_selector(transactions)
    _add_transaction_filters(transactions)

    export = subparsers.add_parser("export", help="Exporte comptes, soldes et transactions.")
    _add_account_selector(export)
    _add_transaction_filters(export)
    export.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="Écrit l'export dans un fichier privé 0600 au lieu de stdout.",
    )

    doctor = subparsers.add_parser("doctor", help="Diagnostique la configuration et la session.")
    doctor.add_argument(
        "--network",
        action="store_true",
        help="Vérifie aussi l'accès à l'API Enable Banking et la présence de BNP.",
    )
    return parser


# -- helpers --------------------------------------------------------------


def _validate_date(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    candidate = value.strip()
    try:
        date.fromisoformat(candidate)
    except ValueError as exc:
        raise UsageError(f"{label} invalide: {value!r} (format attendu YYYY-MM-DD).") from exc
    return candidate


def _validate_filters(args: argparse.Namespace) -> tuple[str | None, str | None, str | None]:
    date_from = _validate_date(args.date_from, "--from")
    date_to = _validate_date(args.date_to, "--to")
    if date_from and date_to and date_from > date_to:
        raise UsageError("--from doit être antérieur ou égal à --to.")
    if args.max_pages < 1 or args.max_pages > 500:
        raise UsageError("--max-pages doit être compris entre 1 et 500.")
    if args.limit is not None and args.limit < 1:
        raise UsageError("--limit doit être supérieur ou égal à 1.")
    status = "PDNG" if getattr(args, "pending", False) else getattr(args, "status", None)
    return date_from, date_to, status


def _mask_iban(iban: str | None) -> str | None:
    if not iban:
        return None
    compact = iban.replace(" ", "")
    if len(compact) <= 8:
        return "…"
    return f"{compact[:4]}…{compact[-4:]}"


def _read_pem(path: Path) -> str:
    return read_private_text(
        path.expanduser().resolve(),
        error_cls=ConfigError,
        label="Clé privée Enable Banking",
    )


def _read_pem_stdin(stdin: TextIO) -> str:
    content = stdin.read(MAX_PRIVATE_FILE_BYTES + 1)
    if len(content) > MAX_PRIVATE_FILE_BYTES:
        raise ConfigError("La clé privée fournie sur stdin est trop volumineuse.")
    if not content.strip():
        raise ConfigError("Aucune clé privée fournie sur stdin.")
    return content


def _session_summary(session: SessionRecord) -> JsonDict:
    return session.summary()


def _linked_payload(
    session: SessionRecord,
    paths: SidecarPaths,
    *,
    warnings: list[str] | None = None,
) -> JsonDict:
    return {
        "schema": "bnp-sidecar/auth/v1",
        "generatedAt": now_iso(),
        "ok": True,
        "status": "linked",
        "result": "linked",
        "aspsp": session.aspsp_name,
        "session": _session_summary(session),
        "accounts": [
            {
                "name": account.name,
                "product": account.product,
                "currency": account.currency,
                "ibanMasked": _mask_iban(account.iban),
            }
            for account in session.accounts
        ],
        "storage": {
            "sessionFile": str(paths.session_file),
            "mode": "600",
        },
        "warnings": warnings or [],
    }


def _pending_payload(
    pending: PendingLink,
    auth_url: str,
    *,
    waiting: bool,
) -> JsonDict:
    return {
        "schema": "bnp-sidecar/auth/v1",
        "generatedAt": now_iso(),
        "ok": True,
        "status": "pending",
        "result": "pending",
        "authUrl": auth_url,
        "aspsp": pending.aspsp_name,
        "redirectUri": pending.redirect_uri,
        "expiresAt": pending.expires_at,
        "consentValidUntil": pending.valid_until,
        "waiting": waiting,
        "instructions": (
            "Ouvrez l'URL, authentifiez-vous chez BNP, puis laissez le callback "
            "terminer la liaison. En mode --no-wait, relancez avec "
            "'bnp-sidecar auth complete --callback-url-stdin'."
        ),
    }


def _store_session(
    ctx: CommandContext,
    client: EnableBankingClient,
    pending: PendingLink,
    payload: JsonDict,
) -> tuple[SessionRecord, list[str]]:
    access = payload.get("access") if isinstance(payload.get("access"), dict) else {}
    aspsp = payload.get("aspsp") if isinstance(payload.get("aspsp"), dict) else {}
    valid_until = (
        access.get("valid_until")
        or pending.valid_until
        or isoformat(utc_now() + timedelta(days=180))
    )
    accounts = accounts_from_session_payload(payload)
    if not accounts:
        raise SessionError("Enable Banking n'a retourné aucun compte pour cette session.")
    now = now_iso()
    session = SessionRecord(
        session_id=str(payload["session_id"]),
        created_at=now,
        authorized_at=now,
        valid_until=str(valid_until),
        status=str(payload.get("status") or "AUTHORIZED"),
        aspsp_name=str(aspsp.get("name") or pending.aspsp_name),
        aspsp_country=str(aspsp.get("country") or pending.aspsp_country),
        psu_type=str(payload.get("psu_type") or pending.psu_type),
        redirect_uri=pending.redirect_uri,
        accounts=accounts,
    )
    previous = load_session(ctx.paths)
    save_session(ctx.paths, session)
    delete_pending_link(ctx.paths)
    ctx.redactor.add(session.session_id)
    warnings: list[str] = []
    if previous and previous.session_id != session.session_id:
        try:
            client.delete_session(previous.session_id)
        except SidecarError:
            warnings.append(
                "L'ancienne session n'a pas pu être révoquée côté Enable Banking; "
                "elle expirera d'elle-même."
            )
    return session, warnings


def _parse_callback_input(value: str) -> dict[str, str]:
    candidate = value.strip()
    if not candidate:
        raise UsageError("Aucune URL de callback fournie.")
    if len(candidate) > MAX_CALLBACK_INPUT:
        raise UsageError("L'URL de callback est trop longue.")
    if candidate.startswith("?"):
        query = candidate[1:]
    elif "://" in candidate:
        parts = urllib.parse.urlsplit(candidate)
        if parts.scheme not in {"http", "https"}:
            raise UsageError("L'URL de callback doit utiliser http ou https.")
        query = parts.query
    else:
        query = candidate
    if not query:
        raise UsageError("L'URL de callback ne contient aucun paramètre.")
    params = urllib.parse.parse_qs(query, keep_blank_values=True)
    return {key: values[0] for key, values in params.items() if values}


# -- commands -------------------------------------------------------------


def _cmd_auth_setup(ctx: CommandContext, args: argparse.Namespace) -> int:
    if args.private_key_stdin:
        private_key = _read_pem_stdin(ctx.stdin)
    else:
        assert args.private_key is not None
        private_key = _read_pem(Path(args.private_key))
    ctx.redactor.add(private_key)
    key = load_private_key(private_key)
    config = AppConfig(
        application_id=args.application_id,
        redirect_uri=args.redirect_uri,
        aspsp_name=args.aspsp,
        aspsp_country=args.country,
        psu_type=args.psu_type,
        language=args.language,
    ).validate()
    ctx.redactor.add(config.application_id)
    save_config(ctx.paths, config, private_key)
    ctx.write(
        {
            "schema": "bnp-sidecar/auth-setup/v1",
            "generatedAt": now_iso(),
            "ok": True,
            "result": "configured",
            "applicationIdMasked": mask_application_id(config.application_id),
            "keyFingerprint": public_key_fingerprint(key),
            "redirectUri": config.redirect_uri,
            "aspsp": config.aspsp_name,
            "country": config.aspsp_country,
            "psuType": config.psu_type,
            "storage": {
                "configFile": private_file_info(ctx.paths.config_file),
                "privateKeyFile": private_file_info(ctx.paths.private_key_file),
            },
            "next": "Lancez 'bnp-sidecar auth link' pour autoriser l'accès en lecture.",
        }
    )
    return 0


def _cmd_auth_status(ctx: CommandContext) -> int:
    warnings: list[str] = []
    config: AppConfig | None = None
    private_key: str | None = None

    if ctx.paths.config_file.exists() or ctx.paths.config_file.is_symlink():
        try:
            config, _ = load_config(ctx.paths, require_private_key=False)
        except SidecarError as exc:
            warnings.append(str(exc))
    if ctx.paths.private_key_file.exists() or ctx.paths.private_key_file.is_symlink():
        try:
            private_key = read_private_text(
                ctx.paths.private_key_file,
                error_cls=ConfigError,
                label="Clé privée Enable Banking",
            )
            load_private_key(private_key)
        except SidecarError as exc:
            warnings.append(str(exc))
            private_key = None

    if config is not None:
        ctx.redactor.add_many(config_secrets(config, private_key))

    session: SessionRecord | None = None
    try:
        session = load_session(ctx.paths)
    except SidecarError as exc:
        warnings.append(str(exc))
    if session is not None:
        ctx.redactor.add(session.session_id)
        if session.is_expired():
            warnings.append("La session enregistrée est expirée; relancez 'auth link'.")

    pending: PendingLink | None = None
    try:
        pending = load_pending_link(ctx.paths)
    except SidecarError as exc:
        warnings.append(str(exc))
    if pending is not None:
        ctx.redactor.add_many(pending_secrets(pending))
        if pending.is_expired():
            warnings.append("Une liaison en attente est expirée; elle peut être supprimée.")

    configured = config is not None and private_key is not None
    ready = bool(configured and session is not None and not session.is_expired())
    ctx.write(
        {
            "schema": "bnp-sidecar/auth-status/v1",
            "generatedAt": now_iso(),
            "ok": configured,
            "configured": configured,
            "ready": ready,
            "config": config_summary(ctx.paths, config, private_key) if config else None,
            "session": _session_summary(session) if session else None,
            "pendingLink": (
                {
                    "present": True,
                    "expiresAt": pending.expires_at,
                    "expired": pending.is_expired(),
                    "aspsp": pending.aspsp_name,
                }
                if pending
                else {"present": False}
            ),
            "storage": {
                "root": str(ctx.paths.root),
                "configFile": private_file_info(ctx.paths.config_file),
                "privateKeyFile": private_file_info(ctx.paths.private_key_file),
                "sessionFile": private_file_info(ctx.paths.session_file),
                "pendingLinkFile": private_file_info(ctx.paths.pending_link_file),
            },
            "warnings": warnings,
        }
    )
    return 0


def _cmd_auth_link(ctx: CommandContext, args: argparse.Namespace) -> int:
    config, private_key = ctx.load_config()
    client = ctx.client(config, private_key)
    if args.timeout <= 0 or args.timeout > 1800:
        raise UsageError("--timeout doit être compris entre 1 et 1800 secondes.")

    existing = load_session(ctx.paths)
    if existing is not None:
        ctx.redactor.add(existing.session_id)
        if not existing.is_expired() and not args.force:
            raise UsageError(
                "Une session BNP est déjà active. Utilisez --force pour la remplacer."
            )

    aspsp = client.find_aspsp()
    consent_seconds = client.maximum_consent_seconds(aspsp)
    now = utc_now()
    valid_until = now + timedelta(seconds=consent_seconds)
    state = new_state()
    pending = PendingLink(
        state=state,
        created_at=isoformat(now),
        expires_at=isoformat(now + timedelta(minutes=15)),
        aspsp_name=str(aspsp.get("name") or config.aspsp_name),
        aspsp_country=str(aspsp.get("country") or config.aspsp_country),
        psu_type=str(aspsp.get("psu_type") or config.psu_type),
        redirect_uri=config.redirect_uri,
        valid_until=isoformat(valid_until),
    )
    ctx.redactor.add_many([state])
    save_pending_link(ctx.paths, pending)

    payload = client.start_authorization(
        state=state,
        valid_until=valid_until,
        aspsp_name=pending.aspsp_name,
        country=pending.aspsp_country,
    )
    auth_url = str(payload["url"])
    authorization_id = payload.get("authorization_id")
    if authorization_id:
        pending.authorization_id = str(authorization_id)
        ctx.redactor.add(pending.authorization_id)
        save_pending_link(ctx.paths, pending)

    print(f"Autorisation BNP Paribas : {auth_url}", file=ctx.stderr, flush=True)

    can_receive = _is_loopback_redirect(pending.redirect_uri)
    if args.no_wait or not can_receive:
        opened = False if args.no_open else ctx.open_browser(auth_url)
        if not opened:
            print(
                "Ouvrez l'URL ci-dessus dans un navigateur, puis terminez avec "
                "'bnp-sidecar auth complete --callback-url-stdin'.",
                file=ctx.stderr,
                flush=True,
            )
        ctx.write(_pending_payload(pending, auth_url, waiting=False))
        return 0

    def ready() -> None:
        print(
            f"En attente du callback sur {pending.redirect_uri} "
            f"({int(args.timeout)} s).",
            file=ctx.stderr,
            flush=True,
        )
        if args.no_open:
            print("Ouvrez l'URL d'autorisation dans votre navigateur.", file=ctx.stderr, flush=True)
        else:
            ctx.open_browser(auth_url)

    callback = CallbackServer(pending.redirect_uri, state)
    result = callback.wait(timeout=args.timeout, paths=ctx.paths, on_ready=ready)
    if result.code:
        ctx.redactor.add(result.code)
    session, warnings = _store_session(
        ctx, client, pending, client.create_session(result.code or "")
    )
    ctx.write(_linked_payload(session, ctx.paths, warnings=warnings))
    return 0


def _cmd_auth_complete(ctx: CommandContext, args: argparse.Namespace) -> int:
    if args.callback_url_stdin:
        raw = ctx.stdin.read(MAX_CALLBACK_INPUT + 1)
        if len(raw) > MAX_CALLBACK_INPUT:
            raise UsageError("L'URL de callback lue sur stdin est trop longue.")
        callback_input = raw.strip()
    else:
        callback_input = str(args.callback_url).strip()
    params = _parse_callback_input(callback_input)
    if params.get("code"):
        ctx.redactor.add(params["code"])

    pending = load_pending_link(ctx.paths)
    if pending is None:
        raise SessionError(
            "Aucune liaison en attente. Lancez d'abord 'bnp-sidecar auth link'."
        )
    ctx.redactor.add_many(pending_secrets(pending))
    if pending.is_expired():
        delete_pending_link(ctx.paths)
        raise SessionError(
            "La liaison en attente a expiré. Relancez 'bnp-sidecar auth link'."
        )

    state = params.get("state", "")
    if not pending.matches_state(state):
        raise LinkStateError(
            "Le paramètre state du callback ne correspond pas à la liaison en cours."
        )
    if params.get("error"):
        description = params.get("error_description") or params["error"]
        delete_pending_link(ctx.paths)
        raise ConsentDenied(f"L'autorisation BNP a été refusée: {description}.")

    config, private_key = ctx.load_config()
    client = ctx.client(config, private_key)
    code = params.get("code")
    if not code:
        raise LinkStateError("Le callback ne contient pas de code d'autorisation.")
    payload = client.create_session(code)
    session, warnings = _store_session(ctx, client, pending, payload)
    ctx.write(_linked_payload(session, ctx.paths, warnings=warnings))
    return 0


def _cmd_auth_logout(ctx: CommandContext, args: argparse.Namespace) -> int:
    warnings: list[str] = []
    session: SessionRecord | None = None
    try:
        session = load_session(ctx.paths)
    except SidecarError as exc:
        warnings.append(str(exc))
    if session is not None:
        ctx.redactor.add(session.session_id)

    remote_revoked = False
    if session is not None:
        try:
            config, private_key = ctx.load_config()
            client = ctx.client(config, private_key)
            client.delete_session(session.session_id)
            remote_revoked = True
        except SidecarError as exc:
            warnings.append(f"Révocation distante impossible: {exc}")

    session_deleted = False
    try:
        session_deleted = delete_session_file(ctx.paths)
    except SidecarError as exc:
        warnings.append(str(exc))
    pending_deleted = delete_pending_link(ctx.paths)

    config_deleted: list[str] = []
    if args.forget:
        try:
            config_deleted = delete_config(ctx.paths)
        except SidecarError as exc:
            warnings.append(str(exc))
        for path in (
            ctx.paths.cache_dir / "callback-cert.pem",
            ctx.paths.cache_dir / "callback-key.pem",
        ):
            try:
                if delete_private_file(path):
                    config_deleted.append(path.name)
            except SidecarError as exc:
                warnings.append(str(exc))

    ctx.write(
        {
            "schema": "bnp-sidecar/auth-logout/v1",
            "generatedAt": now_iso(),
            "ok": True,
            "result": "logged_out",
            "sessionDeleted": session_deleted,
            "remoteSessionRevoked": remote_revoked,
            "pendingLinkDeleted": pending_deleted,
            "configDeleted": config_deleted,
            "forgot": bool(args.forget),
            "warnings": warnings,
        }
    )
    return 0


def _cmd_auth(ctx: CommandContext, args: argparse.Namespace) -> int:
    if args.auth_command == "setup":
        return _cmd_auth_setup(ctx, args)
    if args.auth_command == "status":
        return _cmd_auth_status(ctx)
    if args.auth_command == "link":
        return _cmd_auth_link(ctx, args)
    if args.auth_command == "complete":
        return _cmd_auth_complete(ctx, args)
    if args.auth_command == "logout":
        return _cmd_auth_logout(ctx, args)
    raise UsageError(f"Commande auth inconnue: {args.auth_command}")


def _auth_session(ctx: CommandContext) -> tuple[AppConfig, str, SessionRecord]:
    config, private_key = ctx.load_config()
    session = require_session(ctx.paths)
    ctx.redactor.add_many(session_secrets(session))
    return config, private_key, session


def _selected_accounts(session: SessionRecord, selectors: list[str] | None) -> list[SessionAccount]:
    if not selectors:
        return list(session.accounts)
    return select_accounts(session, selectors)


def _cmd_accounts(ctx: CommandContext, args: argparse.Namespace) -> int:
    config, private_key, session = _auth_session(ctx)
    client = ctx.client(config, private_key)
    selected = _selected_accounts(session, args.account)

    accounts: list[JsonDict] = []
    errors: list[JsonDict] = []
    for account in selected:
        try:
            details = client.get_account_details(account.uid)
            balances = client.get_account_balances(account.uid)
            accounts.append(
                serialize_account(account, details, balances, include_raw=args.raw)
            )
        except SidecarError as exc:
            errors.append(
                {
                    "account": mask_value(account.uid),
                    "step": "account",
                    "code": exc.code,
                    "message": ctx.redactor.text(str(exc)),
                }
            )
    if not accounts and errors:
        raise UpstreamError(
            "Aucun compte n'a pu être récupéré.",
            details={"errors": errors},
        )
    payload = accounts_payload(session, accounts)
    payload["status"] = "ok" if not errors else "partial"
    payload["errors"] = errors
    payload["warnings"] = []
    ctx.write(payload)
    return 0


def _account_transactions(
    ctx: CommandContext,
    client: EnableBankingClient,
    account: SessionAccount,
    args: argparse.Namespace,
    date_from: str | None,
    date_to: str | None,
    status: str | None,
) -> tuple[JsonDict | None, JsonDict | None, list[str]]:
    warnings: list[str] = []
    try:
        result = client.get_all_transactions(
            account.uid,
            date_from=date_from,
            date_to=date_to,
            transaction_status=status,
            strategy=args.strategy,
            max_pages=args.max_pages,
        )
    except SidecarError as exc:
        return (
            None,
            {
                "account": mask_value(account.uid),
                "step": "transactions",
                "code": exc.code,
                "message": ctx.redactor.text(str(exc)),
            },
            warnings,
        )

    serialized = [
        serialize_transaction(transaction, account_uid=account.uid, index=index, include_raw=args.raw)
        for index, transaction in enumerate(result.transactions)
    ]
    serialized = sort_transactions(serialized)
    limited = False
    if args.limit is not None and len(serialized) > args.limit:
        serialized = serialized[: args.limit]
        limited = True
        warnings.append(f"Limite de {args.limit} transactions appliquée.")
    warnings.extend(result.warnings)
    payload = {
        "uid": account.uid,
        "name": account.name,
        "product": account.product,
        "iban": account.iban,
        "currency": account.currency,
        "transactions": serialized,
        "pages": result.pages,
        "truncated": result.truncated,
        "limited": limited,
        "warnings": warnings,
    }
    return payload, None, warnings


def _transactions_base(
    session: SessionRecord,
    args: argparse.Namespace,
    date_from: str | None,
    date_to: str | None,
    status: str | None,
) -> JsonDict:
    return {
        "schema": "bnp-sidecar/transactions/v1",
        "generatedAt": now_iso(),
        "aspsp": session.aspsp_name,
        "session": _session_summary(session),
        "dateFrom": date_from,
        "dateTo": date_to,
        "transactionStatus": status,
        "strategy": args.strategy,
    }


def _cmd_transactions(ctx: CommandContext, args: argparse.Namespace) -> int:
    date_from, date_to, status = _validate_filters(args)
    config, private_key, session = _auth_session(ctx)
    client = ctx.client(config, private_key)
    selected = _selected_accounts(session, args.account)

    account_payloads: list[JsonDict] = []
    errors: list[JsonDict] = []
    warnings: list[str] = []
    total = 0
    for account in selected:
        account_payload, error, account_warnings = _account_transactions(
            ctx, client, account, args, date_from, date_to, status
        )
        warnings.extend(account_warnings)
        if error:
            errors.append(error)
            continue
        if account_payload is not None:
            total += len(account_payload["transactions"])
            account_payloads.append(account_payload)

    if not account_payloads and errors:
        raise UpstreamError(
            "Aucune transaction n'a pu être récupérée.",
            details={"errors": errors},
        )
    payload = _transactions_base(session, args, date_from, date_to, status)
    payload.update(
        {
            "status": "ok" if not errors else "partial",
            "accounts": account_payloads,
            "summary": {"accounts": len(account_payloads), "transactions": total},
            "errors": errors,
            "warnings": warnings,
        }
    )
    ctx.write(payload)
    return 0


def _cmd_export(ctx: CommandContext, args: argparse.Namespace) -> int:
    date_from, date_to, status = _validate_filters(args)
    config, private_key, session = _auth_session(ctx)
    client = ctx.client(config, private_key)
    selected = _selected_accounts(session, args.account)

    accounts: list[JsonDict] = []
    errors: list[JsonDict] = []
    warnings: list[str] = []
    total_transactions = 0
    for account in selected:
        try:
            details = client.get_account_details(account.uid)
            balances = client.get_account_balances(account.uid)
            account_payload = serialize_account(
                account, details, balances, include_raw=args.raw
            )
        except SidecarError as exc:
            errors.append(
                {
                    "account": mask_value(account.uid),
                    "step": "account",
                    "code": exc.code,
                    "message": ctx.redactor.text(str(exc)),
                }
            )
            placeholder = serialize_account(account, {}, [], include_raw=False)
            placeholder["transactions"] = []
            placeholder["transactionPages"] = 0
            placeholder["transactionsTruncated"] = True
            accounts.append(placeholder)
            continue

        transaction_payload, error, account_warnings = _account_transactions(
            ctx, client, account, args, date_from, date_to, status
        )
        warnings.extend(account_warnings)
        if error:
            errors.append(error)
            account_payload["transactions"] = []
            account_payload["transactionPages"] = 0
            account_payload["transactionsTruncated"] = True
        else:
            assert transaction_payload is not None
            account_payload["transactions"] = transaction_payload["transactions"]
            account_payload["transactionPages"] = transaction_payload["pages"]
            account_payload["transactionsTruncated"] = transaction_payload["truncated"]
            account_payload["transactionsLimited"] = transaction_payload["limited"]
            total_transactions += len(transaction_payload["transactions"])
        accounts.append(account_payload)

    if not accounts and errors:
        raise SidecarError(
            "Aucun compte n'a pu être exporté.",
            details={"errors": errors},
        )
    payload = {
        "schema": "bnp-sidecar/export/v1",
        "generatedAt": now_iso(),
        "status": "ok" if not errors else "partial",
        "aspsp": session.aspsp_name,
        "country": session.aspsp_country,
        "session": _session_summary(session),
        "dateFrom": date_from,
        "dateTo": date_to,
        "transactionStatus": status,
        "strategy": args.strategy,
        "accounts": accounts,
        "totals": {
            "balances": totals_by_currency(accounts),
            "accounts": len(accounts),
            "transactions": total_transactions,
        },
        "errors": errors,
        "warnings": warnings,
    }
    if args.output is None:
        ctx.write(payload)
        return 0

    output_path = Path(args.output).expanduser().resolve()
    write_private_json(output_path, payload)
    ctx.write(
        {
            "schema": "bnp-sidecar/export-file/v1",
            "generatedAt": payload["generatedAt"],
            "ok": True,
            "status": payload["status"],
            "path": str(output_path),
            "mode": "600",
            "accounts": len(accounts),
            "transactions": total_transactions,
            "warnings": warnings,
        }
    )
    return 0


def _check(name: str, ok: bool, *, critical: bool, detail: str) -> JsonDict:
    return {"name": name, "ok": ok, "critical": critical, "detail": detail}


def _cmd_doctor(ctx: CommandContext, args: argparse.Namespace) -> int:
    checks: list[JsonDict] = []
    warnings: list[str] = []

    checks.append(
        _check(
            "python",
            sys.version_info >= (3, 11),
            critical=True,
            detail=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        )
    )
    root_mode = None
    try:
        root_mode = ctx.paths.root.stat().st_mode & 0o777
        if ctx.paths.root.is_symlink():
            raise OSError("lien symbolique")
    except OSError as exc:
        checks.append(
            _check("storage", False, critical=True, detail=f"{ctx.paths.root}: {exc}")
        )
    else:
        secure = (root_mode & 0o077) == 0
        checks.append(
            _check(
                "storage",
                secure,
                critical=False,
                detail=f"{ctx.paths.root} (mode {root_mode:o})",
            )
        )
        if not secure:
            warnings.append(
                f"Le répertoire {ctx.paths.root} est accessible au groupe ou aux autres "
                f"(mode {root_mode:o}); 'chmod 700' est recommandé."
            )

    config: AppConfig | None = None
    private_key: str | None = None
    try:
        config, _ = load_config(ctx.paths, require_private_key=False)
        checks.append(
            _check(
                "config",
                True,
                critical=True,
                detail=f"application {mask_application_id(config.application_id)}, "
                f"redirect {config.redirect_uri}",
            )
        )
    except SidecarError as exc:
        checks.append(_check("config", False, critical=True, detail=str(exc)))

    if config is not None:
        try:
            private_key = read_private_text(
                ctx.paths.private_key_file,
                error_cls=ConfigError,
                label="Clé privée Enable Banking",
            )
            key = load_private_key(private_key)
            checks.append(
                _check(
                    "private-key",
                    True,
                    critical=True,
                    detail=f"RSA {key.key_size} bits, empreinte {public_key_fingerprint(key)}",
                )
            )
            ctx.redactor.add_many(config_secrets(config, private_key))
        except SidecarError as exc:
            checks.append(_check("private-key", False, critical=True, detail=str(exc)))

    session: SessionRecord | None = None
    try:
        session = load_session(ctx.paths)
    except SidecarError as exc:
        checks.append(_check("session", False, critical=True, detail=str(exc)))
    else:
        if session is None:
            checks.append(
                _check(
                    "session",
                    False,
                    critical=True,
                    detail="aucune session; lancez 'auth link'",
                )
            )
        else:
            ctx.redactor.add(session.session_id)
            expired = session.is_expired()
            checks.append(
                _check(
                    "session",
                    not expired,
                    critical=True,
                    detail=(
                        f"{session.aspsp_name}, {len(session.accounts)} compte(s), "
                        f"expire le {session.valid_until or 'inconnu'}"
                    ),
                )
            )
            if expired:
                warnings.append("La session est expirée; relancez 'auth link'.")

    try:
        pending = load_pending_link(ctx.paths)
    except SidecarError as exc:
        checks.append(_check("pending-link", False, critical=False, detail=str(exc)))
    else:
        if pending is None:
            checks.append(_check("pending-link", True, critical=False, detail="aucune liaison en attente"))
        else:
            ctx.redactor.add_many(pending_secrets(pending))
            checks.append(
                _check(
                    "pending-link",
                    not pending.is_expired(),
                    critical=False,
                    detail=f"expire le {pending.expires_at}",
                )
            )
            if pending.is_expired():
                warnings.append("Une liaison en attente est expirée; 'auth logout' la supprime.")

    if args.network:
        if config is None or private_key is None:
            checks.append(
                _check("network", False, critical=False, detail="configuration incomplète")
            )
        else:
            try:
                client = ctx.client(config, private_key)
                application = client.get_application()
                checks.append(
                    _check(
                        "network",
                        True,
                        critical=False,
                        detail=f"API Enable Banking joignable ({len(application.get('countries') or [])} pays)",
                    )
                )
                aspsp = client.find_aspsp()
                days = client.maximum_consent_seconds(aspsp) / 86400
                checks.append(
                    _check(
                        "aspsp",
                        True,
                        critical=False,
                        detail=f"{aspsp.get('name')} disponible, consentement ~{days:.0f} jours",
                    )
                )
            except SidecarError as exc:
                checks.append(_check("network", False, critical=False, detail=str(exc)))

    critical_ok = all(check["ok"] for check in checks if check["critical"])
    configured = config is not None and private_key is not None
    ready = bool(configured and session is not None and not session.is_expired())
    ctx.write(
        {
            "schema": "bnp-sidecar/doctor/v1",
            "generatedAt": now_iso(),
            "ok": critical_ok,
            "configured": configured,
            "ready": ready,
            "checks": checks,
            "warnings": warnings,
            "session": _session_summary(session) if session else None,
        }
    )
    return 0 if critical_ok else 1


def _is_loopback_redirect(redirect_uri: str) -> bool:
    try:
        hostname = urllib.parse.urlsplit(redirect_uri).hostname
    except ValueError:
        return False
    return hostname in {"localhost", "127.0.0.1", "::1"}


# -- entry point ----------------------------------------------------------


def main(
    argv: list[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    stdin: TextIO | None = None,
    client_factory: ClientFactory | None = None,
    browser_opener: BrowserOpener | None = None,
) -> int:
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    stdin = sys.stdin if stdin is None else stdin
    redactor = Redactor()
    debug = False
    previous_env: dict[str, str | None] | None = None

    try:
        args = build_parser().parse_args(argv)
        debug = bool(getattr(args, "debug", False))
        data_dir = getattr(args, "data_dir", None)
        paths = SidecarPaths.from_root(data_dir) if data_dir else SidecarPaths.default()
        paths.ensure()
        previous_env = paths.apply_sandbox_env()
        ctx = CommandContext(
            paths=paths,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            redactor=redactor,
            client_factory=client_factory,
            browser_opener=browser_opener,
        )
        if args.command == "auth":
            return _cmd_auth(ctx, args)
        if args.command == "accounts":
            return _cmd_accounts(ctx, args)
        if args.command == "transactions":
            return _cmd_transactions(ctx, args)
        if args.command == "export":
            return _cmd_export(ctx, args)
        if args.command == "doctor":
            return _cmd_doctor(ctx, args)
        raise UsageError(f"Commande inconnue: {args.command}")
    except SidecarError as exc:
        code, payload = _error_payload(exc, redactor, debug)
        try:
            _write_json(stderr, payload)
        except BrokenPipeError:
            pass
        return code
    except KeyboardInterrupt:
        code, payload = _error_payload(
            UsageError("Interrompu par l'utilisateur."), redactor, debug
        )
        try:
            _write_json(stderr, payload)
        except BrokenPipeError:
            pass
        return code
    except BrokenPipeError:
        return 0
    except Exception as exc:  # noqa: BLE001 - filet de sécurité: toute erreur devient un JSON
        code, payload = _error_payload(exc, redactor, debug)
        try:
            _write_json(stderr, payload)
        except BrokenPipeError:
            pass
        return code
    finally:
        if previous_env is not None:
            SidecarPaths.restore_env(previous_env)
