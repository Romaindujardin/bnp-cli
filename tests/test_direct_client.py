from __future__ import annotations

from datetime import date, timedelta

import pytest

from bnp_sidecar.direct.client import (
    BnpDirectClient,
    DirectAccount,
    DirectMFARequired,
    DirectTransaction,
    _merge_transactions,
    account_type,
    normalize_iban,
    parse_accounts_payload,
    parse_amount,
    parse_bnp_date,
    parse_transactions_payload,
    rib_to_iban,
)
from bnp_sidecar.direct.login import LoginForm
from bnp_sidecar.errors import UpstreamError, UsageError

VALID_IBAN = "FR1420041010050500013M02606"


def test_parse_amount_handles_french_and_nested_values() -> None:
    assert parse_amount("1 234,56") == 1234.56
    assert parse_amount("-12,5") == -12.5
    assert parse_amount({"montant": "-12,50"}) == -12.5
    assert parse_amount({"montant": {"montant": 42}}) == 42.0
    assert parse_amount(None) is None
    assert parse_amount("") is None


def test_parse_bnp_date_normalizes_known_formats() -> None:
    assert parse_bnp_date("31-01-2026") == "2026-01-31"
    assert parse_bnp_date("31/01/2026") == "2026-01-31"
    assert parse_bnp_date("2026-01-31") == "2026-01-31"
    assert parse_bnp_date("20260131") is None
    assert parse_bnp_date(None) is None


def test_normalize_iban_accepts_only_valid_ibans() -> None:
    assert normalize_iban(VALID_IBAN) == VALID_IBAN
    assert normalize_iban(VALID_IBAN.lower()) == VALID_IBAN
    assert normalize_iban("123456789012345678901") is None
    assert normalize_iban("FR1420041010050500013M02607") is None
    assert normalize_iban(None) is None


def test_rib_to_iban_converts_french_rib() -> None:
    expected = "FR7630006000011234567890189"
    assert rib_to_iban("300060000112345678901") == expected
    assert rib_to_iban("30006000011234567890189") == expected
    assert rib_to_iban("3 0006 00001 12345678901") == expected
    assert rib_to_iban("30006000011234567890100") is None
    assert rib_to_iban("30006000011234567890") is None
    assert rib_to_iban("FR7630006000011234567890189") is None
    assert rib_to_iban(None) is None


def test_ibans_accepts_single_info_compte_object(monkeypatch) -> None:
    """BNP renvoie ``infoCompte`` comme objet, pas comme liste."""
    payload = {
        "data": {
            "listeRib": [
                {
                    "infoCompte": {
                        "ibanCrypte": "ABC",
                        "iban": "300060000112345678901",
                    }
                }
            ]
        }
    }
    client = BnpDirectClient(session=object())
    client._base_url = "https://mabanque.bnpparibas"
    monkeypatch.setattr(client, "_get_json", lambda *args, **kwargs: payload)
    assert client._ibans() == {"ABC": "FR7630006000011234567890189"}


def test_ibans_accepts_single_liste_rib_object(monkeypatch) -> None:
    payload = {
        "data": {
            "listeRib": {
                "infoCompte": {
                    "ibanCrypte": "ABC",
                    "iban": VALID_IBAN,
                }
            }
        }
    }
    client = BnpDirectClient(session=object())
    client._base_url = "https://mabanque.bnpparibas"
    monkeypatch.setattr(client, "_get_json", lambda *args, **kwargs: payload)
    assert client._ibans() == {"ABC": VALID_IBAN}


def test_ibans_accepts_list_of_info_compte_objects(monkeypatch) -> None:
    payload = {
        "data": {
            "listeRib": [
                {
                    "infoCompte": [
                        {"ibanCrypte": "ABC", "iban": VALID_IBAN},
                        {"ibanCrypte": "DEF", "iban": "300060000112345678901"},
                    ]
                }
            ]
        }
    }
    client = BnpDirectClient(session=object())
    client._base_url = "https://mabanque.bnpparibas"
    monkeypatch.setattr(client, "_get_json", lambda *args, **kwargs: payload)
    assert client._ibans() == {
        "ABC": VALID_IBAN,
        "DEF": "FR7630006000011234567890189",
    }


def test_account_type_maps_bnp_families_and_labels() -> None:
    assert account_type(1, "Compte courant")[0] == "checking"
    assert account_type(2, "Livret A")[0] == "savings"
    assert account_type(2, "LDDS")[0] == "savings"
    assert account_type(4, "PEA")[0] == "pea"
    assert account_type(4, "Compte-titres")[0] == "securities"
    assert account_type(5, "Assurance-vie")[0] == "life_insurance"
    assert account_type(8, "Crédit immobilier")[0] == "loan"
    assert account_type(99, "Produit inconnu")[0] == "unknown"


def test_parse_accounts_payload_extracts_savings_and_checking() -> None:
    payload = {
        "data": {
            "infoUdc": {
                "familleCompte": [
                    {
                        "idFamilleCompte": 1,
                        "compte": [
                            {
                                "key": "ABC",
                                "libelleProduit": "Compte courant",
                                "devise": "EUR",
                                "soldeDispo": "1 234,56",
                                "value": "****1234",
                            }
                        ],
                    },
                    {
                        "idFamilleCompte": 2,
                        "compte": [
                            {
                                "key": "DEF",
                                "libelleProduit": "Livret A",
                                "devise": "EUR",
                                "soldeDispo": "5000",
                                "soldeAVenir": "5100",
                            }
                        ],
                    },
                ]
            }
        }
    }
    accounts, warnings = parse_accounts_payload(payload, {"ABC": VALID_IBAN})
    assert warnings == []
    assert len(accounts) == 2
    assert accounts[0].type_key == "checking"
    assert accounts[0].balance == 1234.56
    assert accounts[0].iban == VALID_IBAN
    assert accounts[1].type_key == "savings"
    assert accounts[1].name == "Livret A"
    assert accounts[1].balance == 5000.0
    assert accounts[1].coming_balance == 5100.0
    assert accounts[1].iban is None


def test_parse_accounts_payload_prefers_booked_balance() -> None:
    payload = {
        "data": {
            "infoUdc": {
                "familleCompte": [
                    {
                        "idFamilleCompte": 1,
                        "compte": [
                            {
                                "key": "ABC",
                                "libelleProduit": "Compte courant",
                                "soldeComptable": "1 000,00",
                                "soldeDispo": "900,00",
                            }
                        ],
                    }
                ]
            }
        }
    }
    accounts, warnings = parse_accounts_payload(payload)
    assert warnings == []
    assert accounts[0].balance == 1000.0
    assert accounts[0].available_balance == 900.0
    assert accounts[0].to_payload()["type"] == "checking"


def test_parse_accounts_payload_reports_empty_payload() -> None:
    accounts, warnings = parse_accounts_payload({})
    assert accounts == []
    assert warnings


def test_parse_transactions_payload_extracts_operations() -> None:
    payload = {
        "data": {
            "listerOperations": {
                "compte": {
                    "operationPassee": [
                        {
                            "idOperation": "op-1",
                            "libelleOperation": "CARTE 31/01",
                            "dateOperation": "31-01-2026",
                            "montant": {
                                "montant": "-12,50",
                                "valueDate": "30-01-2026",
                            },
                            "operationType": {"codeFamille": 7},
                            "categorie": "Alimentation",
                        },
                        {
                            "idOperation": "op-2",
                            "libelleOperation": "VIREMENT RECU",
                            "dateOperation": "01-02-2026",
                            "montant": {"montant": "100,00"},
                            "operationType": {"codeFamille": 4},
                        },
                    ]
                }
            }
        }
    }
    transactions = parse_transactions_payload(payload, account_key="ABC")
    assert len(transactions) == 2
    assert transactions[0].amount == -12.5
    assert transactions[0].booking_date == "2026-01-31"
    assert transactions[0].value_date == "2026-01-30"
    assert transactions[0].kind == "card"
    assert transactions[1].amount == 100.0
    assert transactions[1].kind == "transfer"


def test_parse_transactions_payload_ignores_operations_without_amount() -> None:
    payload = {
        "data": {
            "listerOperations": {
                "compte": {
                    "operationPassee": [
                        {
                            "idOperation": "op-1",
                            "libelleOperation": "SANS MONTANT",
                            "dateOperation": "31-01-2026",
                        }
                    ]
                }
            }
        }
    }
    assert parse_transactions_payload(payload, account_key="ABC") == []


def _account_for_history() -> DirectAccount:
    return DirectAccount(
        key="ABC",
        family_id=1,
        name="Compte de chèques",
        product="Compte de chèques",
        currency="EUR",
        balance=1000.0,
        available_balance=1000.0,
        coming_balance=None,
        masked_number=None,
        iban=None,
        type_key="checking",
        type_label="Compte courant",
        kind="banking",
    )


def _history_payload(*operations: dict) -> dict:
    return {
        "data": {
            "listerOperations": {
                "compte": {"operationPassee": list(operations)}
            }
        }
    }


def test_transactions_extends_history_with_old_endpoint(monkeypatch) -> None:
    account = _account_for_history()
    since = date.today() - timedelta(days=800)
    until = date.today()
    recent_date = (date.today() - timedelta(days=10)).strftime("%d-%m-%Y")
    recent = {
        "idOperation": "recent",
        "libelleOperation": "RECENT",
        "dateOperation": recent_date,
        "montant": {"montant": "-10,00"},
        "operationType": {"codeFamille": 7},
    }
    old = {
        "idOperation": "old",
        "libelleOperation": "ANCIEN",
        "dateOperation": "02-05-2024",
        "montant": {"montant": "50,00"},
        "operationType": {"codeFamille": 4},
    }
    calls: list[str] = []

    def fake_post(path: str, body: dict) -> dict:
        calls.append(path)
        if path == "/rop2-wspl/rest/releveOp":
            return _history_payload(recent)
        if path == "/rop-wspl/rest/releveOp":
            # Le recouvrement avec le nouvel endpoint doit être dédupliqué.
            return _history_payload(recent, old)
        raise AssertionError(f"Endpoint inattendu: {path}")

    client = BnpDirectClient(session=object())
    client._base_url = "https://mabanque.bnpparibas"
    monkeypatch.setattr(client, "_post_json", fake_post)

    transactions = client.transactions(account, since=since, until=until)

    assert {item.id for item in transactions} == {"recent", "old"}
    assert calls == [
        "/rop2-wspl/rest/releveOp",
        "/rop-wspl/rest/releveOp",
    ]
    assert client.warnings == []


def test_transactions_keeps_new_history_if_old_endpoint_fails(monkeypatch) -> None:
    account = _account_for_history()
    recent = {
        "idOperation": "recent",
        "libelleOperation": "RECENT",
        "dateOperation": (date.today() - timedelta(days=10)).strftime("%d-%m-%Y"),
        "montant": {"montant": "-10,00"},
        "operationType": {"codeFamille": 7},
    }

    def fake_post(path: str, body: dict) -> dict:
        if path == "/rop2-wspl/rest/releveOp":
            return _history_payload(recent)
        raise UpstreamError("ancien endpoint indisponible")

    client = BnpDirectClient(session=object())
    client._base_url = "https://mabanque.bnpparibas"
    monkeypatch.setattr(client, "_post_json", fake_post)

    transactions = client.transactions(
        account,
        since=date.today() - timedelta(days=800),
        until=date.today(),
    )

    assert [item.id for item in transactions] == ["recent"]
    assert any("plus d'un an" in warning for warning in client.warnings)


def test_transactions_does_not_use_old_endpoint_for_recent_range(monkeypatch) -> None:
    account = _account_for_history()
    calls: list[str] = []

    def fake_post(path: str, body: dict) -> dict:
        calls.append(path)
        return _history_payload()

    client = BnpDirectClient(session=object())
    client._base_url = "https://mabanque.bnpparibas"
    monkeypatch.setattr(client, "_post_json", fake_post)

    client.transactions(
        account,
        since=date.today() - timedelta(days=30),
        until=date.today(),
    )

    assert calls == ["/rop2-wspl/rest/releveOp"]


def test_merge_transactions_deduplicates_only_by_id() -> None:
    def transaction(identifier: str) -> DirectTransaction:
        return DirectTransaction(
            id=identifier,
            booking_date="2026-01-01",
            value_date=None,
            label="IDENTIQUE",
            amount=-10.0,
            category=None,
            kind="card",
        )

    merged = _merge_transactions(
        [transaction("a"), transaction("b")],
        [transaction("a"), transaction("c")],
    )

    assert {item.id for item in merged} == {"a", "b", "c"}


def test_read_only_allowlist_rejects_write_endpoints() -> None:
    assert BnpDirectClient._endpoint_allowed("GET", "/udc-wspl/rest/getlstcpt")
    assert BnpDirectClient._endpoint_allowed("GET", "/rib-wspl/rpc/comptes")
    assert BnpDirectClient._endpoint_allowed("POST", "/rop2-wspl/rest/releveOp")
    assert BnpDirectClient._endpoint_allowed("POST", "/rop-wspl/rest/releveOp")
    assert not BnpDirectClient._endpoint_allowed(
        "POST", "/virement-wspl/rest/validationVirementIP"
    )
    assert not BnpDirectClient._endpoint_allowed(
        "POST", "/virement-wspl/rest/ajouterBeneficiaire"
    )
    assert not BnpDirectClient._endpoint_allowed("DELETE", "/udc-wspl/rest/getlstcpt")
    assert not BnpDirectClient._endpoint_allowed("GET", "/compte-titres/order")


def test_export_selects_accounts_and_keeps_empty_transactions(monkeypatch) -> None:
    account = DirectAccount(
        key="DEF",
        family_id=2,
        name="Livret A",
        product="Livret A",
        currency="EUR",
        balance=5000.0,
        available_balance=5000.0,
        coming_balance=None,
        masked_number=None,
        iban=None,
        type_key="savings",
        type_label="Épargne",
        kind="savings",
    )
    client = BnpDirectClient()
    client._base_url = "https://mabanque.bnpparibas"
    monkeypatch.setattr(client, "accounts", lambda: [account])
    monkeypatch.setattr(client, "transactions", lambda *args, **kwargs: [])

    payload = client.export(
        since="2026-01-01",
        until="2026-01-31",
        account_selectors=["livret"],
    )
    assert payload["status"] == "ok"
    assert payload["totals"]["accounts"] == 1
    assert payload["accounts"][0]["name"] == "Livret A"
    assert payload["accounts"][0]["transactions"] == []
    assert payload["accounts"][0]["transactionsTruncated"] is False


def test_export_rejects_unknown_selector(monkeypatch) -> None:
    account = DirectAccount(
        key="ABC",
        family_id=1,
        name="Compte courant",
        product="Compte courant",
        currency="EUR",
        balance=10.0,
        available_balance=10.0,
        coming_balance=None,
        masked_number=None,
        iban=None,
        type_key="checking",
        type_label="Compte courant",
        kind="banking",
    )
    client = BnpDirectClient()
    client._base_url = "https://mabanque.bnpparibas"
    monkeypatch.setattr(client, "accounts", lambda: [account])
    with pytest.raises(UsageError, match="sélecteur"):
        client.export(
            since="2026-01-01",
            until="2026-01-31",
            account_selectors=["inexistant"],
            include_transactions=False,
        )


def test_export_default_start_handles_leap_day(monkeypatch) -> None:
    client = BnpDirectClient()
    monkeypatch.setattr(client, "accounts", list)
    payload = client.export(until="2028-02-29", include_transactions=False)
    assert payload["dateFrom"] == "2027-02-28"
    assert payload["dateTo"] == "2028-02-29"


def test_read_request_follows_only_allowed_redirects(monkeypatch) -> None:
    calls: list[tuple[str, str, bool]] = []

    def fake_send(method: str, url: str, **kwargs):
        calls.append((method, url, bool(kwargs.get("allow_redirects"))))
        if len(calls) == 1:
            return FakeResponse(
                "https://mabanque.bnpparibas/udc-wspl/rest/getlstcpt",
                status_code=302,
                headers={"location": "/fr/secure/comptes-et-contrats"},
            )
        return FakeResponse(
            "https://mabanque.bnpparibas/fr/secure/comptes-et-contrats",
            payload={"data": {}},
        )

    client = BnpDirectClient(session=object())
    client._base_url = "https://mabanque.bnpparibas"
    monkeypatch.setattr(client, "_send", fake_send)

    assert client._get_json("/udc-wspl/rest/getlstcpt") == {"data": {}}
    assert calls == [
        (
            "GET",
            "https://mabanque.bnpparibas/udc-wspl/rest/getlstcpt",
            False,
        ),
        (
            "GET",
            "https://mabanque.bnpparibas/fr/secure/comptes-et-contrats",
            False,
        ),
    ]


def test_read_request_rejects_external_redirect(monkeypatch) -> None:
    def fake_send(method: str, url: str, **kwargs):
        return FakeResponse(
            "https://mabanque.bnpparibas/udc-wspl/rest/getlstcpt",
            status_code=302,
            headers={"location": "https://example.invalid/collect"},
        )

    client = BnpDirectClient(session=object())
    client._base_url = "https://mabanque.bnpparibas"
    monkeypatch.setattr(client, "_send", fake_send)

    with pytest.raises(UpstreamError, match="hôte inattendu"):
        client._get_json("/udc-wspl/rest/getlstcpt")


def test_read_request_rejects_unexpected_final_host(monkeypatch) -> None:
    def fake_send(method: str, url: str, **kwargs):
        return FakeResponse("https://example.invalid/response", payload={"data": {}})

    client = BnpDirectClient(session=object())
    client._base_url = "https://mabanque.bnpparibas"
    monkeypatch.setattr(client, "_send", fake_send)

    with pytest.raises(UpstreamError, match="hôte inattendu"):
        client._get_json("/udc-wspl/rest/getlstcpt")


class FakeResponse:
    def __init__(
        self,
        url: str,
        *,
        status_code: int = 200,
        text: str = "",
        headers: dict[str, str] | None = None,
        payload: dict | None = None,
    ) -> None:
        self.url = url
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self._payload = payload

    def json(self) -> dict:
        if self._payload is None:
            raise ValueError("pas de JSON")
        return self._payload


MFA_SMS_HTML = """
<html><head><title>Validation</title></head><body>
<p>Un code a été envoyé.</p>
<form method="post" action="/fr/secure/valider-code">
  <input type="hidden" name="csrf" value="jeton-interne">
  <input type="text" name="code" id="code" inputmode="numeric" maxlength="8">
  <button type="submit">Valider</button>
</form>
</body></html>
"""


def test_login_handles_sms_mfa_without_leaking_code(monkeypatch) -> None:
    login_form = LoginForm(
        page_url="https://connexion.mabanque.bnpparibas/as/x",
        action="https://connexion.mabanque.bnpparibas/as/abc/resume/as/authorization.ping",
        grid="1805246379",
        id_tmx="tmx-123",
    )
    challenges = []
    sent: list[tuple[str, str, dict[str, str] | None]] = []

    def fake_send(method: str, url: str, **kwargs):
        data = kwargs.get("data")
        sent.append((method, url, dict(data) if data else None))
        if url == login_form.action:
            return FakeResponse(
                "https://mabanque.bnpparibas/fr/espace-prive/authentification-forte-anr",
                text=MFA_SMS_HTML,
            )
        if url == "https://mabanque.bnpparibas/fr/secure/valider-code":
            assert data is not None
            assert data["code"] == "123456"
            assert data["csrf"] == "jeton-interne"
            return FakeResponse(
                url,
                status_code=302,
                headers={
                    "location": "https://mabanque.bnpparibas/fr/secure/comptes-et-contrats"
                },
            )
        if url == "https://mabanque.bnpparibas/fr/secure/comptes-et-contrats":
            return FakeResponse(url, text="<html>Bienvenue</html>")
        raise AssertionError(f"URL inattendue: {method} {url}")

    def handler(challenge):
        challenges.append(challenge)
        return {"type": "code", "code": "123456"}

    client = BnpDirectClient(session=object(), mfa_handler=handler)
    monkeypatch.setattr(client, "probe_login_page", lambda: login_form)
    monkeypatch.setattr(client, "_send", fake_send)
    monkeypatch.setattr(client, "_verify_session", lambda: None)

    assert client.login("1234567", "123456") == "https://mabanque.bnpparibas"
    assert len(challenges) == 1
    assert challenges[0].kind == "sms"
    assert challenges[0].code_fields == ["code"]
    code_posts = [data for method, url, data in sent if url.endswith("/valider-code")]
    assert code_posts and code_posts[0]["code"] == "123456"


def test_login_reports_mfa_structure_without_handler(monkeypatch) -> None:
    login_form = LoginForm(
        page_url="https://connexion.mabanque.bnpparibas/as/x",
        action="https://connexion.mabanque.bnpparibas/as/abc/resume/as/authorization.ping",
        grid="1805246379",
        id_tmx="tmx-123",
    )

    def fake_send(method: str, url: str, **kwargs):
        return FakeResponse(
            "https://mabanque.bnpparibas/fr/espace-prive/authentification-forte-anr",
            text=MFA_SMS_HTML,
        )

    client = BnpDirectClient(session=object())
    monkeypatch.setattr(client, "probe_login_page", lambda: login_form)
    monkeypatch.setattr(client, "_send", fake_send)

    with pytest.raises(DirectMFARequired) as excinfo:
        client.login("1234567", "123456")
    details = excinfo.value.details
    assert details["kind"] == "sms"
    assert details["structure"]["forms"][0]["fields"][0]["name"] == "csrf"
    assert "jeton-interne" not in str(details)
