"""Tests de sérialisation des comptes, soldes et transactions."""

from __future__ import annotations

from decimal import Decimal

from bnp_sidecar.serialize import (
    detect_account_type,
    normalize_balance,
    parse_decimal,
    select_balances,
    serialize_account,
    serialize_transaction,
    sort_transactions,
    totals_by_currency,
)
from bnp_sidecar.session import SessionAccount


def test_parse_decimal_handles_french_and_blank_spaces() -> None:
    assert parse_decimal("1 234,56") == Decimal("1234.56")
    assert parse_decimal({"amount": "12.30", "currency": "EUR"}) == Decimal("12.30")
    assert parse_decimal("NaN") is None
    assert parse_decimal("Infinity") is None
    assert parse_decimal(None) is None
    assert parse_decimal(True) is None


def test_select_balances_prefers_clbd_and_clav() -> None:
    balances, booked, available = select_balances(
        [
            {"balance_type": "CLAV", "balance_amount": {"amount": "90", "currency": "EUR"}},
            {"balance_type": "CLBD", "balance_amount": {"amount": "100", "currency": "EUR"}},
            {"balance_type": "ITAV", "balance_amount": {"amount": "80", "currency": "EUR"}},
        ]
    )
    assert booked["type"] == "CLBD" and booked["amount"] == 100.0
    assert available["type"] == "CLAV" and available["amount"] == 90.0
    assert len(balances) == 3


def test_select_balances_falls_back_to_first() -> None:
    _, booked, available = select_balances(
        [{"balance_type": "OTHR", "balance_amount": {"amount": "5", "currency": "EUR"}}]
    )
    assert booked["type"] == "OTHR"
    assert available["type"] == "OTHR"


def test_normalize_balance_ignores_invalid_amount() -> None:
    assert normalize_balance({"balance_type": "CLBD", "balance_amount": {"amount": "x"}}) is None


def test_detect_account_types() -> None:
    assert detect_account_type({"name": "Compte de dépôt", "cash_account_type": "CACC"})[0] == "checking"
    assert detect_account_type({"name": "Livret A", "cash_account_type": "SVGS"})[0] == "savings"
    assert detect_account_type({"name": "PEA"})[0] == "pea"
    assert detect_account_type({"name": "Compte titres"})[0] == "securities"
    assert detect_account_type({"name": "Épargne salariale PEE"})[0] == "employee_savings"
    assert detect_account_type({"name": "Prêt immobilier"})[0] == "loan"
    assert detect_account_type({})[0] == "unknown"


def test_serialize_account() -> None:
    account = SessionAccount(
        uid="uid-1",
        name="Compte de dépôt",
        iban="FR7630006000011234567890189",
        identification_hash="hash-1",
    )
    details = {
        "name": "Compte de dépôt",
        "product": "Compte de dépôt",
        "currency": "EUR",
        "cash_account_type": "CACC",
        "account_id": {"iban": "FR7630006000011234567890189"},
    }
    payload = serialize_account(
        account,
        details,
        [
            {"balance_type": "CLBD", "balance_amount": {"amount": "1000.50", "currency": "EUR"}},
            {"balance_type": "CLAV", "balance_amount": {"amount": "900.25", "currency": "EUR"}},
        ],
    )
    assert payload["uid"] == "uid-1"
    assert payload["iban"].startswith("FR76")
    assert payload["balance"] == 1000.5
    assert payload["balanceType"] == "CLBD"
    assert payload["availableBalance"] == 900.25
    assert payload["type"] == "checking"
    assert payload["externalId"] == "hash-1"
    assert len(payload["balances"]) == 2


def test_serialize_transaction_debit_is_negative() -> None:
    transaction = {
        "entry_reference": "TX-1",
        "transaction_amount": {"amount": "12.34", "currency": "EUR"},
        "credit_debit_indicator": "DBIT",
        "booking_date": "2026-11-18",
        "value_date": "2026-11-17",
        "remittance_information": ["CARREFOUR"],
        "creditor": {"name": "CARREFOUR"},
        "merchant_category_code": "5411",
        "balance_after_transaction": {"amount": "1000.50", "currency": "EUR"},
    }
    payload = serialize_transaction(transaction, account_uid="uid-1")
    assert payload["amount"] == -12.34
    assert payload["direction"] == "DBIT"
    assert payload["description"] == "CARREFOUR"
    assert payload["counterparty"] == {"name": "CARREFOUR", "iban": None}
    assert payload["balanceAfter"] == 1000.5
    assert payload["dedupKey"] == "bnp:uid-1:TX-1"


def test_serialize_transaction_credit_is_positive() -> None:
    payload = serialize_transaction(
        {
            "transaction_amount": {"amount": "2000", "currency": "EUR"},
            "credit_debit_indicator": "CRDT",
            "booking_date": "2026-11-15",
            "remittance_information": ["SALAIRE"],
            "debtor": {"name": "EMPLOYEUR"},
        },
        account_uid="uid-1",
    )
    assert payload["amount"] == 2000.0
    assert payload["counterparty"]["name"] == "EMPLOYEUR"


def test_serialize_transaction_generates_stable_id() -> None:
    transaction = {
        "transaction_amount": {"amount": "1.00", "currency": "EUR"},
        "credit_debit_indicator": "DBIT",
        "booking_date": "2026-01-01",
        "remittance_information": ["SANS REFERENCE"],
    }
    first = serialize_transaction(transaction, account_uid="uid-1", index=0)
    second = serialize_transaction(transaction, account_uid="uid-1", index=0)
    other = serialize_transaction(transaction, account_uid="uid-1", index=1)
    assert first["id"] == second["id"]
    assert first["id"] != other["id"]


def test_sort_transactions_keeps_order_for_same_date() -> None:
    transactions = [
        {"id": "old", "bookingDate": "2026-01-01"},
        {"id": "new", "bookingDate": "2026-02-01"},
        {"id": "same-a", "bookingDate": "2026-02-01"},
    ]
    assert [item["id"] for item in sort_transactions(transactions)] == [
        "new",
        "same-a",
        "old",
    ]


def test_totals_by_currency() -> None:
    totals = totals_by_currency(
        [
            {"balance": 10.5, "currency": "EUR"},
            {"balance": 2.0, "currency": "EUR"},
            {"balance": 5, "currency": "USD"},
            {"balance": None, "currency": "EUR"},
        ]
    )
    assert totals == {"EUR": 12.5, "USD": 5.0}
