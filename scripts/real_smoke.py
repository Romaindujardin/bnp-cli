#!/usr/bin/env python3
"""Smoke test réel BNP Paribas via Enable Banking.

Ce script est réservé aux essais manuels avec un vrai compte. Il utilise une
session déjà créée par ``bnp-sidecar auth link`` et ne demande, ne lit et
n'affiche jamais de mot de passe BNP : l'authentification et la validation
forte ont lieu dans le navigateur, sur les pages de BNP Paribas.

Il enchaîne :

1. la configuration et la session locale ;
2. ``GET /application`` (preuve de connectivité et de JWT) ;
3. la présence de BNP Paribas et la durée de consentement ;
4. les détails et soldes des comptes ;
5. un historique de transactions ciblé ;
6. éventuellement l'export complet via la CLI (``--export``).

Par défaut, le rapport ne contient ni soldes, ni IBAN, ni montants : seulement
des compteurs, des types, des dates et les erreurs. ``--show-data`` inclut un
petit échantillon des données sérialisées et doit être utilisé avec prudence.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections import Counter
from datetime import date
from io import StringIO
from pathlib import Path
from typing import Any, TextIO

from bnp_sidecar import __version__
from bnp_sidecar.cli import SidecarArgumentParser
from bnp_sidecar.cli import main as cli_main
from bnp_sidecar.client import EnableBankingClient
from bnp_sidecar.config import (
    config_secrets,
    load_config,
    mask_application_id,
)
from bnp_sidecar.errors import SidecarError, UsageError
from bnp_sidecar.jwt import load_private_key, public_key_fingerprint
from bnp_sidecar.paths import SidecarPaths
from bnp_sidecar.redact import Redactor
from bnp_sidecar.serialize import (
    now_iso,
    serialize_account,
    serialize_transaction,
    sort_transactions,
)
from bnp_sidecar.session import (
    SessionAccount,
    mask_value,
    require_session,
    select_accounts,
    session_secrets,
)

DEFAULT_TARGETED_LIMIT = 5
MAX_TRANSACTION_PAGES = 500


def build_parser() -> SidecarArgumentParser:
    parser = SidecarArgumentParser(
        prog="real_smoke.py",
        description=(
            "Smoke test réel du sidecar BNP Paribas (session Enable Banking existante, "
            "lecture seule, aucun mot de passe BNP)."
        ),
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Répertoire de données du sidecar (défaut: ~/.local/share/bnp-sidecar).",
    )
    parser.add_argument(
        "--account",
        action="append",
        default=None,
        metavar="UID|IBAN|NOM",
        help="Limite le test à un compte (répétable).",
    )
    parser.add_argument("--from", dest="date_from", metavar="YYYY-MM-DD", help="Date de début.")
    parser.add_argument("--to", dest="date_to", metavar="YYYY-MM-DD", help="Date de fin.")
    parser.add_argument(
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
        help=(
            "Transactions conservées pour le test ciblé "
            f"(défaut: {DEFAULT_TARGETED_LIMIT}). L'export n'est limité que si "
            "cette option est fournie."
        ),
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Exécute aussi l'export complet via la CLI après les tests ciblés.",
    )
    parser.add_argument(
        "--show-data",
        action="store_true",
        help="Inclut un échantillon des données sérialisées (données personnelles).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Ajoute une trace masquée aux erreurs internes.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def write_json(stream: TextIO, payload: Any) -> None:
    stream.write(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    stream.write("\n")
    stream.flush()


def _validate_date(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    candidate = value.strip()
    try:
        date.fromisoformat(candidate)
    except ValueError as exc:
        raise UsageError(f"{label} invalide: {value!r} (format attendu YYYY-MM-DD).") from exc
    return candidate


def _validate_args(args: argparse.Namespace) -> tuple[str | None, str | None]:
    date_from = _validate_date(args.date_from, "--from")
    date_to = _validate_date(args.date_to, "--to")
    if date_from and date_to and date_from > date_to:
        raise UsageError("--from doit être antérieur ou égal à --to.")
    if not 1 <= args.max_pages <= MAX_TRANSACTION_PAGES:
        raise UsageError(
            f"--max-pages doit être compris entre 1 et {MAX_TRANSACTION_PAGES}."
        )
    if args.limit is not None and args.limit < 1:
        raise UsageError("--limit doit être supérieur ou égal à 1.")
    return date_from, date_to


def _account_summary(account: SessionAccount, serialized: dict[str, Any]) -> dict[str, Any]:
    return {
        "uidMasked": mask_value(account.uid),
        "type": serialized.get("type"),
        "kind": serialized.get("kind"),
        "currency": serialized.get("currency"),
        "hasIban": bool(serialized.get("iban")),
        "balancePresent": serialized.get("balance") is not None,
        "balanceType": serialized.get("balanceType"),
        "availableBalancePresent": serialized.get("availableBalance") is not None,
        "availableBalanceType": serialized.get("availableBalanceType"),
        "balances": len(serialized.get("balances") or []),
    }


def _pick_transaction_target(
    accounts: list[tuple[SessionAccount, dict[str, Any]]],
) -> tuple[SessionAccount, dict[str, Any]] | None:
    for account, serialized in accounts:
        if serialized.get("type") == "checking":
            return account, serialized
    return accounts[0] if accounts else None


def _transaction_detail(
    account: SessionAccount,
    payload: dict[str, Any],
    *,
    limit: int | None,
) -> dict[str, Any]:
    transactions = payload.get("transactions") or []
    if limit is not None and len(transactions) > limit:
        transactions = transactions[:limit]
    dates = [
        item.get("bookingDate") or item.get("valueDate") or item.get("transactionDate")
        for item in transactions
    ]
    dates = [value for value in dates if value]
    statuses = Counter(str(item.get("status")) for item in transactions if item.get("status"))
    currencies = sorted({str(item.get("currency")) for item in transactions if item.get("currency")})
    return {
        "account": mask_value(account.uid),
        "count": len(transactions),
        "pages": payload.get("pages"),
        "truncated": payload.get("truncated"),
        "limited": limit is not None and len(payload.get("transactions") or []) > limit,
        "statuses": dict(sorted(statuses.items())),
        "currencies": currencies,
        "firstDate": min(dates) if dates else None,
        "lastDate": max(dates) if dates else None,
        "warnings": payload.get("warnings") or [],
    }


def run(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    date_from, date_to = _validate_args(args)
    paths = SidecarPaths.from_root(args.data_dir) if args.data_dir else SidecarPaths.default()
    paths.ensure()
    previous_env = paths.apply_sandbox_env()

    redactor = Redactor()
    report: dict[str, Any] | None = None

    try:
        config, private_key = load_config(paths)
        session = require_session(paths)
        key = load_private_key(private_key)
        redactor.add_many(config_secrets(config, private_key))
        redactor.add_many(session_secrets(session))

        report = {
            "schema": "bnp-sidecar/real-smoke/v1",
            "generatedAt": now_iso(),
            "status": "ok",
            "version": __version__,
            "aspsp": config.aspsp_name,
            "config": {
                "applicationIdMasked": mask_application_id(config.application_id),
                "redirectUri": config.redirect_uri,
                "baseUrl": config.base_url,
                "aspsp": config.aspsp_name,
                "country": config.aspsp_country,
                "psuType": config.psu_type,
                "language": config.language,
                "keyBits": key.key_size,
                "keyFingerprint": public_key_fingerprint(key),
            },
            "session": session.summary(),
            "steps": [],
            "accounts": [],
            "targeted": {},
            "export": None,
            "errors": [],
            "warnings": [],
            "sampleMayContainPersonalData": bool(args.show_data),
        }
        if args.show_data:
            report["warnings"].append(
                "--show-data est actif : l'échantillon contient des données "
                "personnelles (IBAN, montants, libellés)."
            )

        def add_step(
            name: str,
            ok: bool | None,
            detail: Any = None,
            error: str | None = None,
        ) -> None:
            step: dict[str, Any] = {"name": name, "ok": ok}
            if detail is not None:
                step["detail"] = detail
            if error:
                step["error"] = error
            report["steps"].append(step)

        def add_error(step: str, exc: BaseException) -> None:
            code = exc.code if isinstance(exc, SidecarError) else "INTERNAL_ERROR"
            message = redactor.text(str(exc))
            report["errors"].append({"step": step, "code": code, "message": message})

        client = EnableBankingClient(config, private_key)

        # 1. Connectivité et JWT : premier appel authentifié.
        try:
            application = client.get_application()
            countries = application.get("countries")
            add_step(
                "application",
                True,
                {"countries": len(countries) if isinstance(countries, list) else None},
            )
        except SidecarError as exc:
            add_step("application", False, error=redactor.text(str(exc)))
            add_error("application", exc)
            report["status"] = "failed"
            write_json(stdout, report)
            return 1

        # 2. Présence de BNP et durée de consentement.
        try:
            aspsp = client.find_aspsp()
            consent_days = client.maximum_consent_seconds(aspsp) / 86400
            add_step(
                "aspsp",
                True,
                {
                    "name": aspsp.get("name"),
                    "country": aspsp.get("country"),
                    "consentDays": round(consent_days, 2),
                },
            )
        except SidecarError as exc:
            add_step("aspsp", False, error=redactor.text(str(exc)))
            add_error("aspsp", exc)
            report["status"] = "partial"

        # 3. Détails et soldes des comptes.
        selected = select_accounts(session, args.account or [])
        account_results: list[tuple[SessionAccount, dict[str, Any]]] = []
        account_errors: list[dict[str, Any]] = []
        for account in selected:
            try:
                details = client.get_account_details(account.uid)
                balances = client.get_account_balances(account.uid)
                serialized = serialize_account(account, details, balances, include_raw=False)
            except SidecarError as exc:
                account_errors.append(
                    {
                        "account": mask_value(account.uid),
                        "code": exc.code,
                        "message": redactor.text(str(exc)),
                    }
                )
                continue
            account_results.append((account, serialized))
            report["accounts"].append(_account_summary(account, serialized))
        report["errors"].extend({"step": "account", **item} for item in account_errors)
        if account_results:
            add_step(
                "accounts",
                not account_errors,
                {
                    "count": len(account_results),
                    "errors": len(account_errors),
                    "types": dict(
                        sorted(
                            Counter(
                                str(item.get("type")) for _, item in account_results
                            ).items()
                        )
                    ),
                },
            )
        else:
            add_step("accounts", False, error="aucun compte récupéré")
            report["status"] = "failed"
            if args.show_data:
                report["sample"] = None
            write_json(stdout, report)
            return 1

        if account_errors and report["status"] == "ok":
            report["status"] = "partial"

        # 4. Transactions ciblées.
        target = _pick_transaction_target(account_results)
        if target is None:
            add_step("transactions", None, {"skipped": True, "reason": "aucun compte"})
        else:
            account, _ = target
            try:
                result = client.get_all_transactions(
                    account.uid,
                    date_from=date_from,
                    date_to=date_to,
                    transaction_status=args.status,
                    strategy=args.strategy,
                    max_pages=args.max_pages,
                )
                serialized_transactions = [
                    serialize_transaction(
                        transaction, account_uid=account.uid, index=index, include_raw=False
                    )
                    for index, transaction in enumerate(result.transactions)
                ]
                serialized_transactions = sort_transactions(serialized_transactions)
                effective_limit = (
                    DEFAULT_TARGETED_LIMIT if args.limit is None else args.limit
                )
                payload = {
                    "transactions": serialized_transactions,
                    "pages": result.pages,
                    "truncated": result.truncated,
                    "limited": len(serialized_transactions) > effective_limit,
                    "warnings": result.warnings,
                }
                detail = _transaction_detail(account, payload, limit=effective_limit)
                add_step("transactions", True, detail)
                report["targeted"]["transactions"] = detail
                report["warnings"].extend(result.warnings)
                if args.show_data:
                    report.setdefault("sample", {})
                    report["sample"]["account"] = account_results[0][1]
                    report["sample"]["transactions"] = serialized_transactions[:2]
            except SidecarError as exc:
                add_step("transactions", False, error=redactor.text(str(exc)))
                add_error("transactions", exc)
                report["status"] = "partial"

        # 5. Export complet optionnel, via la CLI publique.
        if args.export:
            export_argv = ["--data-dir", str(paths.root), "export"]
            for selector in args.account or []:
                export_argv.extend(["--account", selector])
            if date_from:
                export_argv.extend(["--from", date_from])
            if date_to:
                export_argv.extend(["--to", date_to])
            if args.status:
                export_argv.extend(["--status", args.status])
            if args.strategy:
                export_argv.extend(["--strategy", args.strategy])
            export_argv.extend(["--max-pages", str(args.max_pages)])
            if args.limit is not None:
                export_argv.extend(["--limit", str(args.limit)])

            export_stdout = StringIO()
            export_stderr = StringIO()
            code = cli_main(
                export_argv,
                stdout=export_stdout,
                stderr=export_stderr,
                stdin=StringIO(),
            )
            if code != 0:
                message = export_stderr.getvalue().strip()
                error_code = "UPSTREAM_ERROR"
                try:
                    parsed_error = json.loads(message)
                    error_code = parsed_error["error"]["code"]
                    message = parsed_error["error"]["message"]
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass
                add_step("export", False, error=redactor.text(message or "export échoué"))
                report["errors"].append(
                    {
                        "step": "export",
                        "code": error_code,
                        "message": redactor.text(message or "export échoué"),
                    }
                )
                report["status"] = "partial"
            else:
                export_payload = json.loads(export_stdout.getvalue())
                export_status = export_payload.get("status")
                export_counts = {
                    "status": export_status,
                    "accounts": export_payload.get("totals", {}).get("accounts"),
                    "transactions": export_payload.get("totals", {}).get("transactions"),
                    "errors": len(export_payload.get("errors") or []),
                }
                add_step("export", export_status == "ok", export_counts)
                report["export"] = export_counts
                report["warnings"].extend(export_payload.get("warnings") or [])
                if export_status != "ok":
                    report["status"] = "partial"

        if report["status"] == "ok" and any(
            step["ok"] is False for step in report["steps"]
        ):
            report["status"] = "partial"

        write_json(stdout, report)
        return 0 if report["status"] == "ok" else 1
    finally:
        paths.restore_env(previous_env)


def _emit_error(
    stderr: TextIO,
    exc: BaseException,
    *,
    debug: bool,
    redactor: Redactor | None = None,
) -> int:
    redactor = redactor or Redactor()
    if isinstance(exc, SidecarError):
        exit_code = exc.exit_code
        payload = {
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
    write_json(stderr, payload)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except UsageError as exc:
        return _emit_error(sys.stderr, exc, debug=False)
    try:
        return run(args, sys.stdout, sys.stderr)
    except SidecarError as exc:
        return _emit_error(sys.stderr, exc, debug=args.debug)
    except KeyboardInterrupt:
        return _emit_error(
            sys.stderr,
            UsageError("Interrompu par l'utilisateur."),
            debug=False,
        )
    except Exception as exc:  # noqa: BLE001 - dernier filet: toujours du JSON
        return _emit_error(sys.stderr, exc, debug=args.debug)


if __name__ == "__main__":
    raise SystemExit(main())
