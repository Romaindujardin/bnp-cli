"""Sérialisation JSON stable des données Enable Banking.

Les montants arrivent sous forme de chaînes décimales dans l'API. Ils sont
convertis avec ``Decimal`` pour éviter les erreurs d'arrondi, puis exposés en
nombres JSON. Les transactions ``DBIT`` sont négatives, les ``CRDT``
positives.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from .session import SessionAccount, SessionRecord

ACCOUNT_TYPES: dict[str, tuple[str, str, str]] = {
    "CHECKING": ("checking", "Compte courant", "banking"),
    "SAVINGS": ("savings", "Épargne", "savings"),
    "PEA": ("pea", "PEA", "trading"),
    "SECURITIES": ("securities", "Compte-titres", "trading"),
    "EMPLOYEE_SAVINGS": ("employee_savings", "Épargne salariale", "trading"),
    "LIFE_INSURANCE": ("life_insurance", "Assurance-vie", "insurance"),
    "LOAN": ("loan", "Crédit", "loan"),
    "CARD": ("card", "Carte", "banking"),
    "DEPOSIT": ("deposit", "Dépôt", "deposit"),
    "UNKNOWN": ("unknown", "Compte", "unknown"),
}

BOOKED_BALANCE_TYPES = ("CLBD", "ITBD", "PRCD", "XPCD", "FWAV", "expected", "closingBooked")
AVAILABLE_BALANCE_TYPES = ("CLAV", "ITAV", "OPAV", "XPCD", "FWAV", "expected")

_SPACE_RE = re.compile(r"[\s\u00a0\u202f]+")


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def parse_decimal(value: Any) -> Decimal | None:
    """Convertit un montant Enable Banking en ``Decimal`` sûr."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, dict):
        value = value.get("amount")
    if isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, str):
        text = _SPACE_RE.sub("", value).replace(",", ".")
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
    return parsed


def money(value: Any) -> float | None:
    parsed = parse_decimal(value)
    if parsed is None:
        return None
    return float(parsed)


def money_or_zero(value: Any) -> float:
    parsed = parse_decimal(value)
    return float(parsed) if parsed is not None else 0.0


def text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    cleaned = value.strip()
    return cleaned or None


def iso_date(value: Any) -> str | None:
    if not value or not isinstance(value, str):
        return None
    candidate = value.strip()
    if len(candidate) < 10:
        return None
    head = candidate[:10]
    try:
        date.fromisoformat(head)
    except ValueError:
        return None
    return head


def currency_of(value: Any, default: str = "EUR") -> str:
    if isinstance(value, dict):
        currency = text(value.get("currency"))
        if currency:
            return currency.upper()
    return default


def normalize_balance(item: dict[str, Any]) -> dict[str, Any] | None:
    amount = parse_decimal(item.get("balance_amount"))
    if amount is None:
        return None
    return {
        "type": text(item.get("balance_type")),
        "name": text(item.get("name")),
        "amount": float(amount),
        "currency": currency_of(item.get("balance_amount")),
        "referenceDate": iso_date(item.get("reference_date")),
        "lastChangeDateTime": text(item.get("last_change_date_time")),
    }


def _pick_by_type(
    balances: list[dict[str, Any]], preferred: Iterable[str]
) -> dict[str, Any] | None:
    by_type = {
        str(item.get("type")): item for item in balances if item.get("type")
    }
    for balance_type in preferred:
        if balance_type in by_type:
            return by_type[balance_type]
    return None


def select_balances(
    raw_balances: Iterable[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None, dict[str, Any] | None]:
    """Normalise les soldes et choisit le solde comptable et disponible."""
    balances = [
        normalized
        for item in raw_balances
        if isinstance(item, dict)
        for normalized in [normalize_balance(item)]
        if normalized is not None
    ]
    booked = _pick_by_type(balances, BOOKED_BALANCE_TYPES)
    available = _pick_by_type(balances, AVAILABLE_BALANCE_TYPES)
    if booked is None and balances:
        booked = balances[0]
    if available is None and booked is not None:
        available = booked
    return balances, booked, available


def detect_account_type(details: dict[str, Any], fallback_name: str | None = None) -> tuple[str, str, str]:
    haystack = " ".join(
        value
        for value in (
            text(details.get("name")),
            text(details.get("product")),
            text(details.get("details")),
            text(fallback_name),
            text(details.get("cash_account_type")),
        )
        if value
    ).casefold()
    cash_type = (text(details.get("cash_account_type")) or "").upper()

    if any(term in haystack for term in ("épargne salariale", "epargne salariale", "pee", "perco", "intéressement", "interessement", "participation")):
        return ACCOUNT_TYPES["EMPLOYEE_SAVINGS"]
    if re.search(r"\bpea\b|plan d'épargne en actions|plan d'epargne en actions", haystack):
        return ACCOUNT_TYPES["PEA"]
    if any(term in haystack for term in ("compte-titres", "compte titres", "compte titre", "portefeuille", "securities", "cto")):
        return ACCOUNT_TYPES["SECURITIES"]
    if any(term in haystack for term in ("assurance vie", "assurance-vie", "multisupport")):
        return ACCOUNT_TYPES["LIFE_INSURANCE"]
    if any(term in haystack for term in ("prêt", "pret", "crédit", "credit", "loan", "immobilier")):
        return ACCOUNT_TYPES["LOAN"]
    if any(term in haystack for term in ("livret", "ldds", "lep", "pel", "cel", "épargne", "epargne")):
        return ACCOUNT_TYPES["SAVINGS"]
    if any(term in haystack for term in ("carte", "card")):
        return ACCOUNT_TYPES["CARD"]
    if cash_type in {"SVGS", "TRAN"}:
        return ACCOUNT_TYPES["SAVINGS"]
    if cash_type in {"LOAN", "LOANACCOUNT"}:
        return ACCOUNT_TYPES["LOAN"]
    if cash_type in {"CACC", "CARD", "CASH", "OTHR"}:
        return ACCOUNT_TYPES["CHECKING"]
    return ACCOUNT_TYPES["UNKNOWN"] if not haystack else ACCOUNT_TYPES["CHECKING"]


def account_external_id(details: dict[str, Any], account: SessionAccount) -> str:
    if account.identification_hash:
        return account.identification_hash
    hashed = text(details.get("identification_hash"))
    if hashed:
        return hashed
    if account.iban:
        digest = hashlib.sha256(account.iban.encode("utf-8")).hexdigest()[:24]
        return f"iban:{digest}"
    return f"uid:{account.uid}"


def serialize_account(
    account: SessionAccount,
    details: dict[str, Any],
    raw_balances: Iterable[dict[str, Any]],
    *,
    include_raw: bool = False,
) -> dict[str, Any]:
    balances, booked, available = select_balances(raw_balances)
    account_id = details.get("account_id") if isinstance(details.get("account_id"), dict) else {}
    iban = text(account_id.get("iban")) or text(details.get("iban")) or account.iban
    name = (
        text(details.get("name"))
        or text(details.get("product"))
        or text(details.get("details"))
        or account.name
        or "Compte bancaire"
    )
    product = text(details.get("product")) or account.product
    currency = (
        text(details.get("currency"))
        or account.currency
        or (booked or {}).get("currency")
        or "EUR"
    )
    type_key, type_label, kind = detect_account_type(details, name)

    payload: dict[str, Any] = {
        "uid": account.uid,
        "externalId": account_external_id(details, account),
        "identificationHash": account.identification_hash or text(details.get("identification_hash")),
        "name": name,
        "product": product,
        "iban": iban,
        "currency": currency,
        "type": type_key,
        "typeLabel": type_label,
        "kind": kind,
        "cashAccountType": text(details.get("cash_account_type")) or account.cash_account_type,
        "usage": text(details.get("usage")),
        "balance": booked["amount"] if booked else None,
        "balanceType": booked["type"] if booked else None,
        "balanceDate": booked["referenceDate"] if booked else None,
        "availableBalance": available["amount"] if available else None,
        "availableBalanceType": available["type"] if available else None,
        "creditLimit": money(details.get("credit_limit")),
        "balances": balances,
    }
    if include_raw:
        payload["raw"] = {"details": details, "balances": list(raw_balances)}
    return payload


def _description(transaction: dict[str, Any]) -> tuple[str, list[str]]:
    remittance = transaction.get("remittance_information")
    lines: list[str] = []
    if isinstance(remittance, list):
        lines = [item.strip() for item in remittance if isinstance(item, str) and item.strip()]
    elif isinstance(remittance, str) and remittance.strip():
        lines = [remittance.strip()]
    bank_code = transaction.get("bank_transaction_code")
    bank_description = None
    if isinstance(bank_code, dict):
        bank_description = text(bank_code.get("description"))
    note = text(transaction.get("note"))
    counterparty = _counterparty(transaction)
    fallback = bank_description or note or (counterparty or {}).get("name") or "Transaction"
    if not lines:
        lines = [fallback]
    return " ".join(lines), lines


def _counterparty(transaction: dict[str, Any]) -> dict[str, Any] | None:
    direction = (text(transaction.get("credit_debit_indicator")) or "").upper()
    party_key = "creditor" if direction == "DBIT" else "debtor"
    account_key = "creditor_account" if direction == "DBIT" else "debtor_account"
    party = transaction.get(party_key)
    party_account = transaction.get(account_key)
    name = text(party.get("name")) if isinstance(party, dict) else None
    iban = None
    if isinstance(party_account, dict):
        iban = text(party_account.get("iban"))
    if not name and not iban:
        # Certaines banques ne remplissent qu'un seul côté.
        for alt_party, alt_account in (
            ("debtor", "debtor_account"),
            ("creditor", "creditor_account"),
        ):
            alt = transaction.get(alt_party)
            alt_acc = transaction.get(alt_account)
            if isinstance(alt, dict) and text(alt.get("name")):
                name = text(alt.get("name"))
                if isinstance(alt_acc, dict):
                    iban = text(alt_acc.get("iban"))
                break
    if not name and not iban:
        return None
    return {"name": name, "iban": iban}


def _transaction_id(
    transaction: dict[str, Any], account_uid: str, index: int
) -> str:
    for key in ("entry_reference", "transaction_id", "reference_number"):
        value = text(transaction.get(key))
        if value:
            return value
    amount = parse_decimal(transaction.get("transaction_amount"))
    seed = "|".join(
        (
            account_uid,
            text(transaction.get("booking_date")) or "",
            text(transaction.get("value_date")) or "",
            str(amount if amount is not None else ""),
            text(transaction.get("credit_debit_indicator")) or "",
            _description(transaction)[0],
            str(index),
        )
    )
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def serialize_transaction(
    transaction: dict[str, Any],
    *,
    account_uid: str,
    index: int = 0,
    include_raw: bool = False,
) -> dict[str, Any]:
    amount = parse_decimal(transaction.get("transaction_amount")) or Decimal(0)
    direction = (text(transaction.get("credit_debit_indicator")) or "").upper() or None
    signed = -abs(amount) if direction == "DBIT" else abs(amount)
    description, lines = _description(transaction)
    transaction_id = _transaction_id(transaction, account_uid, index)
    balance_after = parse_decimal(transaction.get("balance_after_transaction"))
    bank_code = transaction.get("bank_transaction_code")

    payload: dict[str, Any] = {
        "id": transaction_id,
        "dedupKey": f"bnp:{account_uid}:{transaction_id}",
        "entryReference": text(transaction.get("entry_reference")),
        "transactionId": text(transaction.get("transaction_id")),
        "bookingDate": iso_date(transaction.get("booking_date")),
        "valueDate": iso_date(transaction.get("value_date")),
        "transactionDate": iso_date(transaction.get("transaction_date")),
        "status": text(transaction.get("status")),
        "direction": direction,
        "amount": float(signed),
        "currency": currency_of(transaction.get("transaction_amount")),
        "description": description,
        "descriptionLines": lines,
        "counterparty": _counterparty(transaction),
        "merchantCategoryCode": text(transaction.get("merchant_category_code")),
        "referenceNumber": text(transaction.get("reference_number")),
        "bankTransactionCode": text(bank_code.get("code")) if isinstance(bank_code, dict) else None,
        "bankTransactionLabel": text(bank_code.get("description")) if isinstance(bank_code, dict) else None,
        "balanceAfter": float(balance_after) if balance_after is not None else None,
        "note": text(transaction.get("note")),
    }
    if include_raw:
        payload["raw"] = transaction
    return payload


def sort_transactions(transactions: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Trie du plus récent au plus ancien, en conservant l'ordre d'origine à date égale."""
    ordered = list(transactions)

    def stamp(transaction: dict[str, Any]) -> str:
        return (
            transaction.get("bookingDate")
            or transaction.get("valueDate")
            or transaction.get("transactionDate")
            or ""
        )

    ordered.sort(key=stamp, reverse=True)
    return ordered


def totals_by_currency(accounts: Iterable[dict[str, Any]]) -> dict[str, float]:
    totals: dict[str, Decimal] = {}
    for account in accounts:
        balance = parse_decimal(account.get("balance"))
        if balance is None:
            continue
        currency = str(account.get("currency") or "EUR").upper()
        totals[currency] = totals.get(currency, Decimal(0)) + balance
    return {currency: float(value) for currency, value in sorted(totals.items())}


def accounts_payload(
    session: SessionRecord,
    accounts: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    account_list = list(accounts)
    return {
        "schema": "bnp-sidecar/accounts/v1",
        "generatedAt": generated_at or now_iso(),
        "aspsp": session.aspsp_name,
        "country": session.aspsp_country,
        "session": session.summary(),
        "accounts": account_list,
        "totals": {"balances": totals_by_currency(account_list)},
    }
