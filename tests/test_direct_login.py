from __future__ import annotations

import pytest

from bnp_sidecar.direct.login import (
    LoginForm,
    build_login_form_data,
    is_mfa_page,
    parse_login_page,
    parse_mfa_page,
    positions_for_password,
)
from bnp_sidecar.errors import UpstreamError, UsageError

LOGIN_HTML = """
<html><body>
<form method="post" id="identForm" action="/as/abc123/resume/as/authorization.ping">
  <input type="text" id="username" name="pf.username">
  <input type="hidden" id="encryptedUsername" name="pf.encryptedUsername">
  <input type="hidden" name="pf.pass.positions" id="password" value="">
  <input type="hidden" name="pf.idTMX" id="idTMX" value="tmx-123">
</form>
<script nonce="x">
const gridPositions = "1805246379";
</script>
</body></html>
"""


def test_parse_login_page_extracts_form_and_grid() -> None:
    url = "https://connexion.mabanque.bnpparibas/as/authorization.oauth2?state=x"
    form = parse_login_page(LOGIN_HTML, url)
    assert form.page_url == url
    assert (
        form.action
        == "https://connexion.mabanque.bnpparibas/as/abc123/resume/as/authorization.ping"
    )
    assert form.grid == "1805246379"
    assert form.id_tmx == "tmx-123"


def test_parse_login_page_rejects_missing_security_token() -> None:
    html = LOGIN_HTML.replace('id="idTMX" value="tmx-123"', 'id="idTMX" value=""')
    with pytest.raises(UpstreamError, match="Jeton de sécurité"):
        parse_login_page(html, "https://connexion.mabanque.bnpparibas/as/x")


def test_parse_login_page_rejects_missing_grid() -> None:
    html = LOGIN_HTML.replace('const gridPositions = "1805246379";', "")
    with pytest.raises(UpstreamError, match="Grille"):
        parse_login_page(html, "https://connexion.mabanque.bnpparibas/as/x")


def test_parse_login_page_rejects_unexpected_action_host() -> None:
    html = LOGIN_HTML.replace(
        'action="/as/abc123/resume/as/authorization.ping"',
        'action="https://evil.example/as/abc123/resume/as/authorization.ping"',
    )
    with pytest.raises(UpstreamError, match="hôte inattendu"):
        parse_login_page(html, "https://connexion.mabanque.bnpparibas/as/x")


def test_positions_for_password_maps_digits_to_dom_positions() -> None:
    assert positions_for_password("0123456789", "123456") == "123456"
    assert positions_for_password("1805246379", "123456") == "047536"
    assert positions_for_password("9876543210", "123456") == "876543"


def test_positions_for_password_rejects_bad_length() -> None:
    with pytest.raises(UsageError, match="6 chiffres"):
        positions_for_password("0123456789", "12345")


def test_positions_for_password_rejects_invalid_grid() -> None:
    with pytest.raises(UpstreamError, match="Grille"):
        positions_for_password("0011223344", "123456")


def test_build_login_form_data_contains_positions_not_password() -> None:
    form = LoginForm(
        page_url="https://connexion.mabanque.bnpparibas/as/x",
        action="https://connexion.mabanque.bnpparibas/as/abc/resume/as/authorization.ping",
        grid="1805246379",
        id_tmx="tmx-123",
    )
    data = build_login_form_data(form, "1234567", "123456")
    assert data["pf.username"] == "1234567"
    assert data["pf.pass.positions"] == "047536"
    assert data["pf.idTMX"] == "tmx-123"
    assert data["pf.encryptedUsername"] == ""
    assert "saveUserId" not in data
    assert "123456" not in data.values()


def test_build_login_form_data_rejects_bad_customer_id() -> None:
    form = LoginForm(
        page_url="https://connexion.mabanque.bnpparibas/as/x",
        action="https://connexion.mabanque.bnpparibas/as/abc/resume/as/authorization.ping",
        grid="1805246379",
        id_tmx="tmx-123",
    )
    with pytest.raises(UsageError, match="7 à 10 chiffres"):
        build_login_form_data(form, "123", "123456")


MFA_SMS_HTML = """
<html><head><title>Validation</title></head><body>
<p>Un code vous a été envoyé au 06 12 34 56 78.</p>
<form method="post" action="/fr/secure/valider-code">
  <input type="hidden" name="csrf" value="secret-token-123">
  <input type="text" name="code" id="code" inputmode="numeric" maxlength="8">
  <button type="submit" name="action" value="validate">Valider le code</button>
</form>
</body></html>
"""

MFA_SPLIT_HTML = """
<html><body>
<form method="post" action="/valider">
  <input type="hidden" name="token" value="abc">
  <input type="text" name="c1" maxlength="1">
  <input type="text" name="c2" maxlength="1">
  <input type="text" name="c3" maxlength="1">
  <input type="text" name="c4" maxlength="1">
  <input type="text" name="c5" maxlength="1">
  <input type="text" name="c6" maxlength="1">
  <button type="submit">Continuer</button>
</form>
</body></html>
"""

MFA_APPROVAL_HTML = """
<html><body>
<p>Validez la connexion avec votre Clé Digitale dans l'application BNP Paribas.</p>
<p>Une notification a été envoyée sur votre téléphone.</p>
</body></html>
"""


def test_is_mfa_page_matches_url_and_body() -> None:
    assert is_mfa_page(
        "<html></html>",
        "https://mabanque.bnpparibas/fr/espace-prive/authentification-forte-anr",
    )
    assert is_mfa_page(MFA_APPROVAL_HTML, "https://mabanque.bnpparibas/fr/secure/x")
    assert not is_mfa_page("<html>Bonjour</html>", "https://mabanque.bnpparibas/fr/secure/x")


def test_is_mfa_page_ignores_connected_dashboard() -> None:
    """Le menu connecté contient « Clé Digitale » mais ce n'est pas une 2FA."""
    dashboard = """
    <html><body>
    <a href="/fr/secure/mes-outils/profil">Paramètres : Clé Digitale, code secret</a>
    <a href="/fr/secure/deconnexion">Se d&eacute;connecter</a>
    <a href="/fr/secure/comptes-et-contrats">Mes comptes</a>
    </body></html>
    """
    assert not is_mfa_page(
        dashboard, "https://mabanque.bnpparibas/fr/secure/123456"
    )


def test_parse_mfa_page_sms_single_field() -> None:
    challenge = parse_mfa_page(
        MFA_SMS_HTML, "https://mabanque.bnpparibas/fr/secure/authentification"
    )
    assert challenge.kind == "sms"
    assert challenge.code_fields == ["code"]
    assert len(challenge.forms) == 1
    form = challenge.forms[0]
    assert form.action == "https://mabanque.bnpparibas/fr/secure/valider-code"
    assert [button.label for button in form.buttons] == ["Valider le code"]
    assert "secret-token-123" not in str(challenge.structure)
    assert "<N>" in challenge.structure["bodyExcerpt"]


def test_parse_mfa_page_sms_split_fields() -> None:
    challenge = parse_mfa_page(MFA_SPLIT_HTML, "https://mabanque.bnpparibas/valider")
    assert challenge.kind == "sms"
    assert challenge.code_fields == ["c1", "c2", "c3", "c4", "c5", "c6"]


def test_parse_mfa_page_approval() -> None:
    challenge = parse_mfa_page(
        MFA_APPROVAL_HTML, "https://mabanque.bnpparibas/fr/secure/attente"
    )
    assert challenge.kind == "approval"
    assert challenge.code_fields == []
    assert challenge.forms == []


def test_parse_mfa_page_unknown_keeps_actions_without_values() -> None:
    html = """
    <html><body>
    <p>Choisissez un moyen de validation.</p>
    <form method="post" action="/envoyer-sms">
      <input type="hidden" name="jeton" value="top-secret">
      <button type="submit">Recevoir un code par SMS</button>
    </form>
    </body></html>
    """
    challenge = parse_mfa_page(html, "https://mabanque.bnpparibas/fr/secure/choix")
    assert challenge.kind == "unknown"
    assert challenge.forms[0].buttons[0].label == "Recevoir un code par SMS"
    assert "top-secret" not in str(challenge.structure)
