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



# ---------------------------------------------------------------------------
# Broker MFA par fichiers privés (intégration dashboard)
# ---------------------------------------------------------------------------

MFA_APPROVAL_HTML = """
<html><body>
<p>Merci de valider la connexion dans l'application BNP.</p>
</body></html>
"""


def _wait_for_request(tmp_path, timeout=5.0):
    import json
    import time

    request_path = tmp_path / "mfa-request.json"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if request_path.exists():
            return json.loads(request_path.read_text(encoding="utf-8"))
        time.sleep(0.02)
    raise AssertionError("mfa-request.json n'a pas été écrit")


def test_broker_mfa_writes_private_request_and_reads_sms_code(tmp_path) -> None:
    import json
    import os
    import stat
    import threading

    from bnp_sidecar.private_files import write_private_json

    os.chmod(tmp_path, 0o700)
    challenge = parse_mfa_page(MFA_SMS_HTML, "https://mabanque.bnpparibas/valider")

    def responder() -> None:
        request = _wait_for_request(tmp_path)
        assert request["schema"] == "bnp-sidecar/mfa-request/v1"
        assert request["kind"] == "sms"
        assert request["codeRequired"] is True
        assert request["actions"] == []
        content = (tmp_path / "mfa-request.json").read_text(encoding="utf-8")
        assert "jeton" not in content
        assert "csrf" not in content  # aucun détail de formulaire/token
        mode = stat.S_IMODE((tmp_path / "mfa-request.json").stat().st_mode)
        assert mode == 0o600
        write_private_json(
            tmp_path / "mfa-response.json",
            {
                "schema": "bnp-sidecar/mfa-response/v1",
                "id": request["id"],
                "code": "654321",
            },
        )

    thread = threading.Thread(target=responder)
    thread.start()
    decision = direct_cli._broker_mfa_decision(challenge, tmp_path, 5.0)
    thread.join(timeout=5)
    assert decision == {"type": "code", "code": "654321"}
    assert not (tmp_path / "mfa-request.json").exists()
    assert not (tmp_path / "mfa-response.json").exists()


def test_broker_mfa_maps_action_index(tmp_path) -> None:
    import os
    import threading

    from bnp_sidecar.private_files import write_private_json

    os.chmod(tmp_path, 0o700)
    challenge = parse_mfa_page(
        MFA_UNKNOWN_HTML, "https://mabanque.bnpparibas/choix"
    )

    def responder() -> None:
        request = _wait_for_request(tmp_path)
        assert request["codeRequired"] is False
        assert [action["kind"] for action in request["actions"]] == ["form"]
        assert "Recevoir un code par SMS" in request["actions"][0]["label"]
        write_private_json(
            tmp_path / "mfa-response.json",
            {"id": request["id"], "action": 0},
        )

    thread = threading.Thread(target=responder)
    thread.start()
    decision = direct_cli._broker_mfa_decision(challenge, tmp_path, 5.0)
    thread.join(timeout=5)
    assert decision == {"type": "form", "form": 0, "button": 0}


def test_broker_mfa_offers_continue_for_approval(tmp_path) -> None:
    import os
    import threading

    from bnp_sidecar.private_files import write_private_json

    os.chmod(tmp_path, 0o700)
    challenge = parse_mfa_page(
        MFA_APPROVAL_HTML, "https://mabanque.bnpparibas/approbation"
    )

    def responder() -> None:
        request = _wait_for_request(tmp_path)
        assert request["kind"] == "approval"
        assert request["actions"][0]["kind"] == "continue"
        assert "application BNP" in request["actions"][0]["label"]
        write_private_json(
            tmp_path / "mfa-response.json",
            {"id": request["id"], "action": 0},
        )

    thread = threading.Thread(target=responder)
    thread.start()
    decision = direct_cli._broker_mfa_decision(challenge, tmp_path, 5.0)
    thread.join(timeout=5)
    assert decision == {"type": "continue"}


def test_broker_mfa_times_out_and_removes_request(tmp_path) -> None:
    import os

    os.chmod(tmp_path, 0o700)
    challenge = parse_mfa_page(MFA_SMS_HTML, "https://mabanque.bnpparibas/valider")
    assert direct_cli._broker_mfa_decision(challenge, tmp_path, 0.3) is None
    assert not (tmp_path / "mfa-request.json").exists()


def test_broker_mfa_refuses_shared_directory(tmp_path) -> None:
    import os

    import pytest
    from bnp_sidecar.errors import UsageError

    os.chmod(tmp_path, 0o755)
    challenge = parse_mfa_page(MFA_SMS_HTML, "https://mabanque.bnpparibas/valider")
    with pytest.raises(UsageError, match="accessible au groupe"):
        direct_cli._broker_mfa_decision(challenge, tmp_path, 1.0)
