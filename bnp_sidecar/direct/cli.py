"""CLI expérimentale d'accès direct à BNP Paribas.

Le code secret est demandé dans le terminal et n'est jamais écrit sur disque.
Les sorties JSON peuvent contenir des données bancaires : utilisez ``--output``
pour les écrire dans un fichier privé (0600).
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import json
import os
import re
import stat
import sys
import time
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..errors import SidecarError, UsageError
from ..paths import SidecarPaths
from ..private_files import read_private_json, write_private_json
from ..redact import Redactor
from .client import BnpDirectClient, MfaDecision, MfaHandler
from .login import MfaChallenge

_CUSTOMER_ID_RE = re.compile(r"[0-9]{7,10}")
_PASSWORD_RE = re.compile(r"[0-9]{6}")
_CODE_RE = re.compile(r"[0-9]{4,10}")


class _ArgumentParser(argparse.ArgumentParser):
    """Transforme les erreurs argparse en erreurs JSON."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise UsageError(message)


def _add_mfa_options(parser: argparse.ArgumentParser) -> None:
    """Ajoute l'échange MFA par fichiers privés (intégration dashboard)."""
    parser.add_argument(
        "--mfa-dir",
        help=(
            "Répertoire privé 0700 où le CLI dépose la demande de validation "
            "forte et attend une réponse JSON (intégration non interactive)."
        ),
    )
    parser.add_argument(
        "--mfa-timeout",
        type=float,
        default=180.0,
        help="Délai maximal d'attente d'une réponse MFA, en secondes (défaut: 180).",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="bnp-direct",
        description=(
            "Accès direct à BNP Paribas en lecture seule (expérimental). "
            "Le code secret est demandé au terminal et n'est pas stocké."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "probe",
        help="Vérifie l'accès à la page de connexion BNP, sans identifiant.",
    )

    accounts = subparsers.add_parser(
        "accounts",
        help="Liste les comptes et les soldes.",
    )
    accounts.add_argument(
        "--output",
        help="Écrit le JSON dans un fichier privé 0600 au lieu de stdout.",
    )
    accounts.add_argument(
        "--customer-id",
        dest="customer_id",
        help="Numéro client BNP (7 à 10 chiffres). Peut aussi être passé via BNP_CUSTOMER_ID.",
    )
    accounts.add_argument(
        "--password-stdin",
        action="store_true",
        help="Lit le code secret sur stdin (ou via la variable BNP_PASSWORD).",
    )
    accounts.add_argument(
        "--raw",
        action="store_true",
        help="Ajoute les objets BNP bruts (données sensibles).",
    )
    _add_mfa_options(accounts)

    export = subparsers.add_parser(
        "export",
        help="Exporte les comptes, soldes et transactions.",
    )
    export.add_argument(
        "--output",
        help="Écrit le JSON dans un fichier privé 0600 au lieu de stdout.",
    )
    export.add_argument(
        "--customer-id",
        dest="customer_id",
        help="Numéro client BNP (7 à 10 chiffres). Peut aussi être passé via BNP_CUSTOMER_ID.",
    )
    export.add_argument(
        "--password-stdin",
        action="store_true",
        help="Lit le code secret sur stdin (ou via la variable BNP_PASSWORD).",
    )
    export.add_argument(
        "--since",
        help="Début de l'historique au format YYYY-MM-DD (défaut: il y a 1 an).",
    )
    export.add_argument(
        "--until",
        help="Fin de l'historique au format YYYY-MM-DD (défaut: aujourd'hui).",
    )
    export.add_argument(
        "--account",
        action="append",
        default=[],
        dest="accounts",
        help="Filtre un compte par identifiant, nom, produit ou IBAN (répétable).",
    )
    export.add_argument(
        "--no-transactions",
        action="store_true",
        help="Exporte uniquement les comptes et les soldes.",
    )
    export.add_argument(
        "--raw",
        action="store_true",
        help="Ajoute les objets BNP bruts (données sensibles).",
    )
    _add_mfa_options(export)
    return parser


def _prompt_credentials(args: argparse.Namespace | None = None) -> tuple[str, str]:
    customer_id = (
        getattr(args, "customer_id", None)
        or os.environ.get("BNP_CUSTOMER_ID")
    )
    if not customer_id:
        try:
            customer_id = input("Numéro client BNP (7 à 10 chiffres) : ").strip()
        except EOFError as exc:
            raise UsageError("Numéro client BNP manquant.") from exc
    else:
        customer_id = customer_id.strip()

    if not _CUSTOMER_ID_RE.fullmatch(customer_id):
        raise UsageError("Le numéro client BNP doit contenir 7 à 10 chiffres.")

    password: str | None = None
    if getattr(args, "password_stdin", False):
        try:
            line = sys.stdin.readline()
            if line:
                password = line.rstrip("\r\n")
        except Exception as exc:
            raise UsageError("Code secret BNP manquant sur stdin.") from exc
    if not password:
        password = os.environ.get("BNP_PASSWORD")
    if not password:
        try:
            password = getpass.getpass("Code secret BNP (6 chiffres) : ")
        except EOFError as exc:
            raise UsageError("Code secret BNP manquant.") from exc
    else:
        password = password.strip()

    if not _PASSWORD_RE.fullmatch(password):
        raise UsageError("Le code secret BNP doit contenir exactement 6 chiffres.")
    return customer_id, password


def _mfa_actions(challenge: MfaChallenge) -> list[tuple[str, MfaDecision]]:
    actions: list[tuple[str, MfaDecision]] = []
    for form in challenge.forms:
        for button_index, button in enumerate(form.buttons):
            if button.type not in ("submit", ""):
                continue
            actions.append(
                (
                    f"{button.label} (formulaire {form.index + 1})",
                    {"type": "form", "form": form.index, "button": button_index},
                )
            )
        if not form.buttons:
            actions.append(
                (
                    f"Envoyer le formulaire {form.index + 1}",
                    {"type": "form", "form": form.index, "button": None},
                )
            )
    ignored = ("annul", "retour", "oubli", "aide", "contact", "déconnex")
    useful = (
        "code",
        "sms",
        "valider",
        "validation",
        "vérif",
        "verif",
        "recevoir",
        "envoyer",
        "authentif",
        "application",
        "clé",
        "cle ",
        "digitale",
        "continuer",
        "suivant",
        "autre moyen",
        "confirmer",
        "approuver",
    )
    for link in challenge.links:
        label = link.label or link.href
        lowered = label.casefold()
        if not link.href.startswith(("/", "http")):
            continue
        if any(word in lowered for word in ignored):
            continue
        if not any(word in lowered for word in useful):
            continue
        actions.append((f"Lien : {label}", {"type": "link", "href": link.href}))
    return actions


def _prompt_mfa_choice(actions: list[tuple[str, MfaDecision]]) -> MfaDecision | None:
    for index, (label, _) in enumerate(actions[:10], start=1):
        print(f"  {index}. {label}", file=sys.stderr)
    try:
        raw = input(f"Choix (1-{min(len(actions), 10)}, Entrée = 1) : ").strip()
    except EOFError:
        return None
    if not raw:
        return actions[0][1]
    if raw.isdigit() and 1 <= int(raw) <= min(len(actions), 10):
        return actions[int(raw) - 1][1]
    raise UsageError("Choix de validation BNP invalide.")


def _save_mfa_structure(challenge: MfaChallenge) -> None:
    paths = SidecarPaths.default()
    structure_path = paths.data_dir / "mfa-structure.json"
    with contextlib.suppress(SidecarError):
        paths.ensure()
        write_private_json(structure_path, challenge.structure)
        print(
            f"Structure de la validation écrite dans {structure_path} (0600).",
            file=sys.stderr,
        )


def _mfa_handler(challenge: MfaChallenge) -> MfaDecision | None:
    """Gère la validation forte dans le terminal, sans journaliser de secret."""
    _save_mfa_structure(challenge)
    page = challenge.structure.get("page", {})
    host = page.get("host") or "inconnu"
    path = page.get("path") or "/"
    print(f"Validation forte BNP demandée ({challenge.kind}).", file=sys.stderr)
    print(f"Page : {host}{path}", file=sys.stderr)
    print(
        f"Formulaires : {len(challenge.forms)}, "
        f"liens : {len(challenge.links)}.",
        file=sys.stderr,
    )
    if challenge.kind == "sms" and challenge.code_fields:
        try:
            code = getpass.getpass("Code de validation reçu par SMS : ").strip()
        except EOFError:
            return None
        if not _CODE_RE.fullmatch(code):
            raise UsageError(
                "Le code de validation BNP doit contenir 4 à 10 chiffres."
            )
        return {"type": "code", "code": code}
    if challenge.kind == "approval":
        actions = _mfa_actions(challenge)
        prompt = "Validez dans l'application BNP, puis appuyez sur Entrée"
        if actions:
            prompt += " (ou 'a' pour choisir une action)"
        try:
            raw = input(prompt + " : ").strip().casefold()
        except EOFError:
            return None
        if raw == "a" and actions:
            return _prompt_mfa_choice(actions)
        return {"type": "continue"}
    actions = _mfa_actions(challenge)
    if not actions:
        print("Aucune action de validation reconnue.", file=sys.stderr)
        return None
    return _prompt_mfa_choice(actions)


def _private_mfa_dir(path: str | Path) -> Path:
    """Valide un répertoire d'échange MFA privé (0700, sans lien symbolique)."""
    directory = Path(path).expanduser()
    if directory.is_symlink():
        raise UsageError(
            f"Le répertoire MFA {directory} est un lien symbolique; refus d'utilisation."
        )
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise UsageError(f"Le chemin MFA {directory} n'est pas un répertoire.")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise UsageError(
            f"Le répertoire MFA {directory} est accessible au groupe ou aux autres "
            f"(mode {stat.S_IMODE(info.st_mode):o}). Corrigez avec: chmod 700 {directory}"
        )
    return directory


def _broker_mfa_decision(
    challenge: MfaChallenge,
    mfa_dir: Path,
    timeout: float,
) -> MfaDecision | None:
    """Échange la validation forte via des fichiers privés (dashboard).

    Le CLI écrit ``mfa-request.json`` (sans valeur de champ ni jeton) puis
    attend ``mfa-response.json``. Le dashboard lit la demande, la présente à
    l'utilisateur et écrit la réponse. Aucun secret ne passe par argv ou les
    journaux.
    """
    if timeout <= 0:
        raise UsageError("Le délai de validation BNP doit être positif.")
    directory = _private_mfa_dir(mfa_dir)
    actions = _mfa_actions(challenge)
    if challenge.kind == "approval":
        actions.insert(
            0,
            ("J'ai validé dans l'application BNP", {"type": "continue"}),
        )
    code_required = challenge.kind == "sms" and bool(challenge.code_fields)
    if code_required:
        # La page SMS attend uniquement le code : ne pas proposer d'action
        # alternative qui soumettrait le formulaire sans code.
        actions = []
    if not code_required and not actions:
        raise UsageError("Aucune action de validation BNP reconnue.")

    request_id = uuid.uuid4().hex
    request_path = directory / "mfa-request.json"
    response_path = directory / "mfa-response.json"
    write_private_json(
        request_path,
        {
            "schema": "bnp-sidecar/mfa-request/v1",
            "id": request_id,
            "kind": challenge.kind,
            "page": challenge.structure.get("page", {}),
            "codeRequired": code_required,
            "actions": [
                {"index": index, "label": label, "kind": decision["type"]}
                for index, (label, decision) in enumerate(actions)
            ],
        },
    )

    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if not response_path.exists():
                time.sleep(0.2)
                continue
            response = read_private_json(
                response_path,
                error_cls=UsageError,
                label="La réponse de validation BNP",
            )
            response_path.unlink(missing_ok=True)
            if response.get("id") != request_id:
                # Réponse périmée (nouvelle demande entre-temps) : on ignore.
                continue
            if response.get("cancel"):
                return None
            code = response.get("code")
            if code is not None:
                candidate = str(code).strip()
                if not _CODE_RE.fullmatch(candidate):
                    raise UsageError(
                        "Le code de validation BNP doit contenir 4 à 10 chiffres."
                    )
                return {"type": "code", "code": candidate}
            action = response.get("action")
            if isinstance(action, int) and not isinstance(action, bool):
                if 0 <= action < len(actions):
                    return actions[action][1]
                raise UsageError("Action de validation BNP introuvable.")
            if response.get("continue") and challenge.kind == "approval":
                return {"type": "continue"}
            raise UsageError("Réponse de validation BNP invalide.")
        return None
    finally:
        request_path.unlink(missing_ok=True)


def _mfa_handler_for_args(
    args: argparse.Namespace,
) -> MfaHandler:
    """Retourne le gestionnaire terminal ou le broker de fichiers privés."""
    mfa_dir = getattr(args, "mfa_dir", None)
    if not mfa_dir:
        return _mfa_handler
    directory = _private_mfa_dir(mfa_dir)
    timeout = float(getattr(args, "mfa_timeout", 180.0))
    return lambda challenge: _broker_mfa_decision(challenge, directory, timeout)


def _emit(payload: dict[str, Any], output: str | None) -> None:
    if output:
        path = Path(output).expanduser()
        write_private_json(path, payload)
        print(f"Écrit dans {path} (mode 0600).", file=sys.stderr)
        return
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, default=str)
    sys.stdout.write("\n")


def _print_error(exc: BaseException, redactor: Redactor) -> int:
    if isinstance(exc, SidecarError):
        code = exc.code
        message = str(exc)
        details = exc.details
        exit_code = exc.exit_code
    else:
        code = "INTERNAL_ERROR"
        message = f"Erreur interne: {exc}"
        details = {}
        exit_code = 1
    payload = {
        "schema": "bnp-sidecar/error/v1",
        "ok": False,
        "error": {
            "code": code,
            "message": redactor.text(message),
            "details": redactor.value(details),
        },
    }
    json.dump(payload, sys.stderr, ensure_ascii=False, indent=2, default=str)
    sys.stderr.write("\n")
    return exit_code


def _run_probe() -> int:
    client = BnpDirectClient()
    try:
        form = client.probe_login_page()
        host = urlparse(form.page_url).hostname or "inconnu"
        print("Page de connexion BNP accessible.", file=sys.stderr)
        print(f"Hôte : {host}", file=sys.stderr)
        print("Formulaire PingFederate détecté.", file=sys.stderr)
        print(f"Clavier : {len(form.grid)} touches.", file=sys.stderr)
        print("Jeton de sécurité : présent.", file=sys.stderr)
        return 0
    finally:
        client.close()


def _run_accounts(args: argparse.Namespace, redactor: Redactor) -> int:
    client = BnpDirectClient(
        include_raw=args.raw,
        mfa_handler=_mfa_handler_for_args(args),
    )
    try:
        print("Ouverture de la page de connexion BNP…", file=sys.stderr)
        customer_id, password = _prompt_credentials(args)
        redactor.add_many((customer_id, password))
        print("Connexion à BNP…", file=sys.stderr)
        client.login(customer_id, password)
        del password
        print("Connexion réussie. Lecture des comptes…", file=sys.stderr)
        payload = client.accounts_payload()
        _emit(payload, args.output)
        count = len(payload.get("accounts", []))
        print(f"{count} compte(s) trouvé(s).", file=sys.stderr)
        return 0
    finally:
        client.close()


def _run_export(args: argparse.Namespace, redactor: Redactor) -> int:
    client = BnpDirectClient(
        include_raw=args.raw,
        mfa_handler=_mfa_handler_for_args(args),
    )
    try:
        print("Ouverture de la page de connexion BNP…", file=sys.stderr)
        customer_id, password = _prompt_credentials(args)
        redactor.add_many((customer_id, password))
        print("Connexion à BNP…", file=sys.stderr)
        client.login(customer_id, password)
        del password
        print("Connexion réussie. Lecture des comptes et opérations…", file=sys.stderr)
        payload = client.export(
            since=args.since,
            until=args.until,
            account_selectors=args.accounts,
            include_transactions=not args.no_transactions,
        )
        _emit(payload, args.output)
        totals = payload.get("totals", {})
        print(
            "Export terminé: "
            f"{totals.get('accounts', 0)} compte(s), "
            f"{totals.get('transactions', 0)} transaction(s).",
            file=sys.stderr,
        )
        return 0
    finally:
        client.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    redactor = Redactor()
    try:
        if args.command == "probe":
            return _run_probe()
        if args.command == "accounts":
            return _run_accounts(args, redactor)
        if args.command == "export":
            return _run_export(args, redactor)
        raise UsageError(f"Commande inconnue: {args.command}")
    except SidecarError as exc:
        return _print_error(exc, redactor)
    except KeyboardInterrupt:
        print("Interrompu.", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - dernière barrière JSON
        return _print_error(exc, redactor)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
