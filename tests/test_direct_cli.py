from __future__ import annotations

import bnp_sidecar.direct.cli as direct_cli
from bnp_sidecar.direct.cli import main
from bnp_sidecar.direct.client import BnpDirectClient
from bnp_sidecar.direct.login import LoginForm, parse_mfa_page


def test_probe_command_does_not_require_credentials(monkeypatch, capsys) -> None:
    def fake_probe(self: BnpDirectClient) -> LoginForm:
        return LoginForm(
            page_url="https://connexion.mabanque.bnpparibas/as/authorization.oauth2?state=x",
            action="https://connexion.mabanque.bnpparibas/as/abc/resume/as/authorization.ping",
            grid="1805246379",
            id_tmx="tmx-123",
        )

    monkeypatch.setattr(BnpDirectClient, "probe_login_page", fake_probe)
    assert main(["probe"]) == 0
    captured = capsys.readouterr()
    assert "Page de connexion BNP accessible" in captured.err
    assert "Clavier : 10 touches" in captured.err
    assert "tmx-123" not in captured.err


MFA_SMS_HTML = """
<html><body>
<form method="post" action="/valider">
  <input type="hidden" name="csrf" value="jeton">
  <input type="text" name="code" inputmode="numeric">
  <button type="submit">Valider</button>
</form>
</body></html>
"""

MFA_UNKNOWN_HTML = """
<html><body>
<form method="post" action="/envoyer">
  <input type="hidden" name="csrf" value="jeton">
  <button type="submit">Recevoir un code par SMS</button>
</form>
</body></html>
"""


def test_mfa_handler_reads_sms_code_without_echo(monkeypatch, capsys) -> None:
    challenge = parse_mfa_page(MFA_SMS_HTML, "https://mabanque.bnpparibas/valider")
    monkeypatch.setattr(direct_cli, "_save_mfa_structure", lambda challenge: None)
    monkeypatch.setattr(
        direct_cli.getpass, "getpass", lambda prompt="": "654321"
    )
    decision = direct_cli._mfa_handler(challenge)
    assert decision == {"type": "code", "code": "654321"}
    assert "654321" not in capsys.readouterr().err


def test_mfa_handler_offers_actions_for_unknown_page(monkeypatch, capsys) -> None:
    challenge = parse_mfa_page(
        MFA_UNKNOWN_HTML, "https://mabanque.bnpparibas/choix"
    )
    monkeypatch.setattr(direct_cli, "_save_mfa_structure", lambda challenge: None)
    monkeypatch.setattr("builtins.input", lambda prompt="": "1")
    decision = direct_cli._mfa_handler(challenge)
    assert decision == {"type": "form", "form": 0, "button": 0}
    assert "Recevoir un code par SMS" in capsys.readouterr().err


def test_mfa_actions_ignore_dashboard_navigation_links() -> None:
    challenge = parse_mfa_page(
        """
        <html><body>
        <a href="/fr/secure/assistance">Assistance</a>
        <a href="/fr/secure/mes-outils/profil">Paramètres</a>
        <a href="/fr/secure/sms">Recevoir un code par SMS</a>
        </body></html>
        """,
        "https://mabanque.bnpparibas/fr/secure/choix",
    )
    actions = direct_cli._mfa_actions(challenge)
    assert [label for label, _ in actions] == ["Lien : Recevoir un code par SMS"]


def test_print_error_redacts_registered_secrets(capsys) -> None:
    from bnp_sidecar.errors import UpstreamError
    from bnp_sidecar.redact import Redactor

    redactor = Redactor(["1234567", "123456"])
    error = UpstreamError(
        "Échec pour 1234567 avec le code 123456.",
        details={"customer": "1234567", "password": "123456"},
    )
    assert direct_cli._print_error(error, redactor) == error.exit_code
    output = capsys.readouterr().err
    assert "1234567" not in output
    assert "123456" not in output
    assert "[REDACTED]" in output


def test_prompt_credentials_from_env(monkeypatch) -> None:
    monkeypatch.setenv("BNP_CUSTOMER_ID", "12345678")
    monkeypatch.setenv("BNP_PASSWORD", "654321")
    customer_id, password = direct_cli._prompt_credentials()
    assert customer_id == "12345678"
    assert password == "654321"


def test_prompt_credentials_from_args_and_stdin(monkeypatch) -> None:
    import argparse
    import io

    args = argparse.Namespace(customer_id="98765432", password_stdin=True)
    monkeypatch.setattr("sys.stdin", io.StringIO("112233\n"))
    customer_id, password = direct_cli._prompt_credentials(args)
    assert customer_id == "98765432"
    assert password == "112233"


def test_prompt_credentials_validation(monkeypatch) -> None:
    import pytest
    from bnp_sidecar.errors import UsageError

    monkeypatch.setenv("BNP_CUSTOMER_ID", "bad")
    with pytest.raises(UsageError, match="numéro client BNP"):
        direct_cli._prompt_credentials()

    monkeypatch.setenv("BNP_CUSTOMER_ID", "12345678")
    monkeypatch.setenv("BNP_PASSWORD", "bad")
    with pytest.raises(UsageError, match="code secret BNP"):
        direct_cli._prompt_credentials()

