"""Fixtures partagées : clé RSA, chemins privés et faux client Enable Banking."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from bnp_sidecar.client import TransactionsResult
from bnp_sidecar.config import AppConfig, save_config
from bnp_sidecar.errors import UpstreamError
from bnp_sidecar.paths import SidecarPaths

APPLICATION_ID = "cf589be3-3755-465b-a8df-a90a16a31403"


@pytest.fixture(scope="session")
def private_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


@pytest.fixture()
def paths(tmp_path: Path) -> SidecarPaths:
    return SidecarPaths.from_root(tmp_path / "runtime").ensure()


@pytest.fixture()
def app_config() -> AppConfig:
    return AppConfig(application_id=APPLICATION_ID)


@pytest.fixture()
def configured(paths: SidecarPaths, app_config: AppConfig, private_key_pem: str) -> tuple[AppConfig, str]:
    save_config(paths, app_config, private_key_pem)
    return app_config, private_key_pem


def session_payload(now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    return {
        "session_id": "11111111-2222-3333-4444-555555555555",
        "status": "AUTHORIZED",
        "aspsp": {"name": "BNP Paribas", "country": "FR"},
        "psu_type": "personal",
        "access": {"valid_until": (now + timedelta(days=170)).isoformat()},
        "accounts": [
            {
                "uid": "uid-account-1",
                "name": "Compte de dépôt",
                "product": "Compte de dépôt",
                "currency": "EUR",
                "cash_account_type": "CACC",
                "account_id": {"iban": "FR7630006000011234567890189"},
                "identification_hash": "hash-account-1",
            },
            {
                "uid": "uid-account-2",
                "name": "Livret A",
                "product": "Livret A",
                "currency": "EUR",
                "cash_account_type": "SVGS",
                "account_id": {"iban": "FR7630006000019876543210198"},
                "identification_hash": "hash-account-2",
            },
        ],
    }


def account_details(uid: str) -> dict[str, Any]:
    if uid == "uid-account-1":
        return {
            "uid": uid,
            "name": "Compte de dépôt",
            "product": "Compte de dépôt",
            "currency": "EUR",
            "cash_account_type": "CACC",
            "account_id": {"iban": "FR7630006000011234567890189"},
            "identification_hash": "hash-account-1",
        }
    return {
        "uid": uid,
        "name": "Livret A",
        "product": "Livret A",
        "currency": "EUR",
        "cash_account_type": "SVGS",
        "account_id": {"iban": "FR7630006000019876543210198"},
        "identification_hash": "hash-account-2",
    }


def account_balances(uid: str) -> list[dict[str, Any]]:
    if uid == "uid-account-1":
        return [
            {
                "name": "Solde comptable",
                "balance_type": "CLBD",
                "balance_amount": {"amount": "1000.50", "currency": "EUR"},
                "reference_date": "2026-11-18",
            },
            {
                "name": "Solde disponible",
                "balance_type": "CLAV",
                "balance_amount": {"amount": "900.25", "currency": "EUR"},
                "reference_date": "2026-11-18",
            },
        ]
    return [
        {
            "name": "Solde comptable",
            "balance_type": "CLBD",
            "balance_amount": {"amount": "5000.00", "currency": "EUR"},
            "reference_date": "2026-11-18",
        }
    ]


def transactions(uid: str) -> list[dict[str, Any]]:
    if uid != "uid-account-1":
        return [
            {
                "entry_reference": "SAV-1",
                "transaction_amount": {"amount": "25.00", "currency": "EUR"},
                "credit_debit_indicator": "CRDT",
                "status": "BOOK",
                "booking_date": "2026-11-01",
                "remittance_information": ["Intérêts"],
            }
        ]
    return [
        {
            "entry_reference": "TX-1",
            "transaction_id": "transaction-1",
            "transaction_amount": {"amount": "12.34", "currency": "EUR"},
            "credit_debit_indicator": "DBIT",
            "status": "BOOK",
            "booking_date": "2026-11-18",
            "value_date": "2026-11-17",
            "remittance_information": ["CARREFOUR MARKET"],
            "creditor": {"name": "CARREFOUR MARKET"},
            "merchant_category_code": "5411",
            "balance_after_transaction": {"amount": "1000.50", "currency": "EUR"},
        },
        {
            "entry_reference": "TX-2",
            "transaction_amount": {"amount": "2000.00", "currency": "EUR"},
            "credit_debit_indicator": "CRDT",
            "status": "BOOK",
            "booking_date": "2026-11-15",
            "remittance_information": ["VIREMENT SALAIRE"],
            "debtor": {"name": "EMPLOYEUR"},
        },
    ]


class FakeEnableBankingClient:
    """Client de test : aucun réseau, données déterministes."""

    def __init__(self, config: AppConfig | None = None, private_key: str | None = None) -> None:
        self.config = config
        self.private_key = private_key
        self.deleted_sessions: list[str] = []
        self.auth_calls: list[dict[str, Any]] = []
        self.created_codes: list[str] = []
        self.transaction_calls: list[dict[str, Any]] = []
        self.fail_accounts: set[str] = set()
        self.aspsp = {
            "name": "BNP Paribas",
            "country": "FR",
            "psu_types": ["personal"],
            "maximum_consent_validity": 15552000,
        }
        self.session_payload = session_payload()

    def find_aspsp(self, name: str | None = None, country: str | None = None) -> dict[str, Any]:
        return dict(self.aspsp)

    def maximum_consent_seconds(self, aspsp: dict[str, Any]) -> int:
        return int(aspsp.get("maximum_consent_validity", 15552000)) - 60

    def start_authorization(self, state: str, valid_until: datetime, **kwargs: Any) -> dict[str, Any]:
        self.auth_calls.append({"state": state, "valid_until": valid_until, **kwargs})
        return {
            "url": "https://auth.enablebanking.com/ais/start?sessionid=fake-session",
            "authorization_id": "fake-authorization-id",
        }

    def create_session(self, code: str) -> dict[str, Any]:
        self.created_codes.append(code)
        return dict(self.session_payload)

    def get_account_details(self, uid: str) -> dict[str, Any]:
        if uid in self.fail_accounts:
            raise UpstreamError("details failed")
        return account_details(uid)

    def get_account_balances(self, uid: str) -> list[dict[str, Any]]:
        return account_balances(uid)

    def get_all_transactions(self, uid: str, **kwargs: Any) -> TransactionsResult:
        self.transaction_calls.append({"uid": uid, **kwargs})
        return TransactionsResult(transactions=transactions(uid), pages=1)

    def delete_session(self, session_id: str) -> None:
        self.deleted_sessions.append(session_id)

    def get_application(self) -> dict[str, Any]:
        return {"countries": ["FR", "DE"]}


@pytest.fixture()
def fake_client() -> FakeEnableBankingClient:
    return FakeEnableBankingClient()
