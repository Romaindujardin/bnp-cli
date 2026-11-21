"""Lecture de la page de connexion BNP et calcul des positions du clavier.

Le mot de passe n'est jamais stocké ni journalisé. Il est converti en une
suite de positions (les index DOM des touches du clavier virtuel), puis la
référence au mot de passe est abandonnée par l'appelant.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html import unescape
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

from ..errors import UpstreamError, UsageError

LOGIN_ENTRY = "https://mabanque.bnpparibas/fr/connexion"

_LOGIN_ACTION_HOSTS = {
    "connexion.mabanque.bnpparibas",
    "connexion.hellobank.fr",
}

_GRID_RE = re.compile(r'const\s+gridPositions\s*=\s*"([0-9]{10})"')
_CUSTOMER_ID_RE = re.compile(r"[0-9]{7,10}")
_PASSWORD_RE = re.compile(r"[0-9]{6}")


@dataclass(frozen=True)
class LoginForm:
    """Champs non secrets du formulaire de connexion BNP."""

    page_url: str
    action: str
    grid: str
    id_tmx: str


@dataclass(frozen=True)
class MfaField:
    """Champ d'un formulaire de validation forte."""

    name: str
    type: str
    element_id: str | None = None
    inputmode: str | None = None
    autocomplete: str | None = None
    maxlength: int | None = None
    value: str = ""
    checked: bool = False


@dataclass(frozen=True)
class MfaButton:
    """Bouton d'un formulaire de validation forte."""

    label: str
    type: str
    name: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class MfaForm:
    """Formulaire HTML rencontré sur une page de validation forte."""

    index: int
    action: str
    method: str
    element_id: str | None
    fields: tuple[MfaField, ...]
    buttons: tuple[MfaButton, ...]


@dataclass(frozen=True)
class MfaLink:
    """Lien utile d'une page de validation forte (SMS, aide, etc.)."""

    label: str
    href: str


@dataclass
class MfaChallenge:
    """Page de validation forte, avec une vue structurelle sans secret."""

    page_url: str
    kind: str
    forms: list[MfaForm] = field(default_factory=list)
    links: list[MfaLink] = field(default_factory=list)
    code_fields: list[str] = field(default_factory=list)
    structure: dict[str, Any] = field(default_factory=dict)


_MFA_BODY_MARKERS = (
    "authentification-forte",
    "authentification forte",
    "authentforte",
    "clé digitale",
    "cle digitale",
)
_MFA_URL_MARKERS = ("authentification-forte", "authentforte")
# Un espace déjà authentifié contient toujours un lien de déconnexion. Le mot
# « Clé Digitale » y figure aussi dans les menus, donc il ne suffit pas à
# reconnaître une validation forte.
_AUTHENTICATED_BODY_MARKERS = (
    "se déconnecter",
    "se deconnecter",
    "déconnexion",
    "deconnexion",
)
_CODE_HINTS = ("code", "otp", "sms", "token", "validation", "auth", "secret")


def _mask_digits(text: str) -> str:
    return re.sub(r"\d+", "<N>", text)


def _mask_path(path: str, *, mask_ids: bool = True) -> str:
    segments: list[str] = []
    for segment in (path or "/").split("/"):
        if not segment:
            segments.append("")
        elif segment.isdigit():
            segments.append("<N>")
        elif mask_ids and len(segment) >= 12 and re.fullmatch(r"[A-Za-z0-9_-]+", segment):
            segments.append("<ID>")
        else:
            segments.append(segment)
    return "/".join(segments)


def _safe_url_parts(url: str, *, mask_ids: bool = True) -> dict[str, Any]:
    parsed = urlparse(url)
    return {
        "host": (parsed.hostname or "").lower(),
        "path": _mask_path(parsed.path, mask_ids=mask_ids),
        "queryKeys": sorted(parse_qs(parsed.query).keys()),
    }


class _MfaPageParser(HTMLParser):
    """Extrait les formulaires, boutons et liens d'une page de 2FA.

    Les valeurs des champs ne sont jamais incluses dans la structure publique ;
    elles restent uniquement en mémoire pour rejouer le formulaire.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.body_parts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.links: list[dict[str, Any]] = []
        self.scripts: list[str] = []
        self.iframes: list[str] = []
        self._current_form: dict[str, Any] | None = None
        self._current_button: dict[str, Any] | None = None
        self._current_link: dict[str, Any] | None = None
        self._in_title = False
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key: value or "" for key, value in attrs}
        if tag in ("script", "style"):
            if tag == "script" and attributes.get("src"):
                self.scripts.append(attributes["src"])
            self._skip_depth += 1
            return
        if tag == "iframe":
            if attributes.get("src"):
                self.iframes.append(attributes["src"])
            return
        if tag == "title":
            self._in_title = True
            return
        if tag == "form":
            form: dict[str, Any] = {
                "id": attributes.get("id") or None,
                "action": attributes.get("action") or "",
                "method": (attributes.get("method") or "post").lower(),
                "fields": [],
                "buttons": [],
            }
            self.forms.append(form)
            self._current_form = form
            return
        if tag == "input":
            name = attributes.get("name") or ""
            if not name:
                return
            try:
                maxlength = int(attributes["maxlength"])
            except (KeyError, ValueError):
                maxlength = None
            mfa_field = MfaField(
                name=name,
                type=(attributes.get("type") or "text").lower(),
                element_id=attributes.get("id") or None,
                inputmode=attributes.get("inputmode") or None,
                autocomplete=attributes.get("autocomplete") or None,
                maxlength=maxlength,
                value=attributes.get("value") or "",
                checked="checked" in attributes,
            )
            if self._current_form is not None:
                self._current_form["fields"].append(mfa_field)
            return
        if tag == "button":
            button: dict[str, Any] = {
                "type": (attributes.get("type") or "submit").lower(),
                "name": attributes.get("name") or None,
                "value": attributes.get("value") or None,
                "text": [],
            }
            self._current_button = button
            if self._current_form is not None:
                self._current_form["buttons"].append(button)
            return
        if tag == "a":
            link: dict[str, Any] = {
                "href": attributes.get("href") or "",
                "text": [],
            }
            self.links.append(link)
            self._current_link = link
            return
        if tag == "br" and self._current_link is None and self._current_button is None:
            self.body_parts.append(" ")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._in_title:
            self.title_parts.append(data)
            return
        if self._current_button is not None:
            self._current_button["text"].append(data)
            return
        if self._current_link is not None:
            self._current_link["text"].append(data)
            return
        self.body_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            if self._skip_depth:
                self._skip_depth -= 1
        elif tag == "title":
            self._in_title = False
        elif tag == "form":
            self._current_form = None
        elif tag == "button":
            self._current_button = None
        elif tag == "a":
            self._current_link = None


def _field_is_code_candidate(field: MfaField) -> bool:
    return bool(field.name) and field.type in ("text", "tel", "number", "password")


def _code_field_score(field: MfaField) -> int:
    haystack = " ".join(
        value.casefold()
        for value in (field.name, field.element_id, field.autocomplete)
        if value
    )
    score = 2 if any(hint in haystack for hint in _CODE_HINTS) else 0
    if field.type in ("tel", "number", "password"):
        score += 1
    if (field.inputmode or "").casefold() in ("numeric", "tel"):
        score += 1
    return score


def _detect_code_fields(fields: list[MfaField]) -> list[str]:
    candidates = [field for field in fields if _field_is_code_candidate(field)]
    if not candidates:
        return []
    single_digit = [field for field in candidates if field.maxlength == 1]
    if len(single_digit) >= 4:
        return [field.name for field in single_digit]
    best = max(candidates, key=_code_field_score)
    if _code_field_score(best) > 0 or len(candidates) == 1:
        return [best.name]
    return []


def parse_mfa_page(html: str, page_url: str) -> MfaChallenge:
    """Lit une page de validation forte sans exposer de valeur sensible.

    Le type est déduit du formulaire : un champ de code donne ``sms``, la
    mention de la Clé Digitale ou d'une application donne ``approval``. Les
    pages inconnues restent ``unknown`` et sont décrites par leur structure.
    """
    parser = _MfaPageParser()
    parser.feed(html)

    forms: list[MfaForm] = []
    visible_fields: list[MfaField] = []
    for index, raw_form in enumerate(parser.forms):
        raw_fields = list(raw_form["fields"])
        visible_fields.extend(raw_fields)
        buttons = tuple(
            MfaButton(
                label=" ".join(button["text"]).strip() or "Envoyer",
                type=button["type"],
                name=button["name"],
                value=button["value"],
            )
            for button in raw_form["buttons"]
        )
        forms.append(
            MfaForm(
                index=index,
                action=urljoin(page_url, raw_form["action"]),
                method=raw_form["method"] or "post",
                element_id=raw_form["id"],
                fields=tuple(raw_fields),
                buttons=buttons,
            )
        )

    links = tuple(
        MfaLink(label=" ".join(link["text"]).strip(), href=link["href"])
        for link in parser.links
        if link["href"]
    )
    code_fields = _detect_code_fields(visible_fields)
    body_text = re.sub(r"\s+", " ", "".join(parser.body_parts)).strip()
    lowered = (
        body_text.casefold()
        .replace("\u00a0", " ")
        .replace("\u202f", " ")
    )
    if code_fields:
        kind = "sms"
    elif (
        "cle digitale" in lowered
        or "clé digitale" in lowered
        or ("application" in lowered and any(
            word in lowered for word in ("notification", "valider", "approuver", "confirmer")
        ))
    ):
        kind = "approval"
    else:
        kind = "unknown"

    structured_forms: list[dict[str, Any]] = []
    for form in forms:
        action_parts = _safe_url_parts(form.action)
        structured_forms.append(
            {
                "id": form.element_id,
                "actionHost": action_parts["host"],
                "actionPath": action_parts["path"],
                "actionQueryKeys": action_parts["queryKeys"],
                "method": form.method,
                "fields": [
                    {
                        "name": field.name,
                        "type": field.type,
                        "id": field.element_id,
                        "inputmode": field.inputmode,
                        "autocomplete": field.autocomplete,
                        "maxlength": field.maxlength,
                    }
                    for field in form.fields
                ],
                "buttons": [
                    {
                        "label": _mask_digits(button.label),
                        "type": button.type,
                        "name": button.name,
                    }
                    for button in form.buttons
                ],
            }
        )

    structure = {
        "kind": kind,
        "page": _safe_url_parts(page_url),
        "titleLength": len("".join(parser.title_parts).strip()),
        "forms": structured_forms,
        "links": [
            {
                "label": _mask_digits(link.label),
                **_safe_url_parts(urljoin(page_url, link.href)),
            }
            for link in links
        ],
        "scripts": [
            _safe_url_parts(urljoin(page_url, src), mask_ids=False)
            for src in parser.scripts
        ],
        "iframes": [
            _safe_url_parts(urljoin(page_url, src), mask_ids=False)
            for src in parser.iframes
        ],
        "bodyExcerpt": _mask_digits(body_text[:600]),
    }

    return MfaChallenge(
        page_url=page_url,
        kind=kind,
        forms=forms,
        links=list(links),
        code_fields=code_fields,
        structure=structure,
    )


def is_mfa_page(html: str, page_url: str) -> bool:
    """Détecte une page d'authentification forte à partir de l'URL ou du corps."""
    lowered_url = page_url.casefold()
    if any(marker in lowered_url for marker in _MFA_URL_MARKERS):
        return True
    lowered_body = (
        unescape(html)
        .casefold()
        .replace("\u00a0", " ")
        .replace("\u202f", " ")
    )
    if any(marker in lowered_body for marker in _AUTHENTICATED_BODY_MARKERS):
        return False
    return any(marker in lowered_body for marker in _MFA_BODY_MARKERS)


class _LoginPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.form_action: str | None = None
        self.inputs: dict[str, dict[str, str]] = {}
        self.ids: dict[str, dict[str, str]] = {}
        self.scripts: list[str] = []
        self._in_script = False
        self._script_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key: value or "" for key, value in attrs}
        if tag == "form" and attributes.get("id") == "identForm":
            self.form_action = attributes.get("action") or None
        elif tag == "input":
            name = attributes.get("name")
            if name:
                self.inputs[name] = attributes
            element_id = attributes.get("id")
            if element_id:
                self.ids[element_id] = attributes
        elif tag == "script":
            self._in_script = True
            self._script_parts = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            self.scripts.append("".join(self._script_parts))
            self._script_parts = []
            self._in_script = False


def parse_login_page(html: str, page_url: str) -> LoginForm:
    """Extrait l'action du formulaire, la grille et le jeton ThreatMetrix.

    La page peut changer : toute structure inattendue lève ``UpstreamError``
    plutôt que de tenter une connexion avec des champs incomplets.
    """
    parser = _LoginPageParser()
    try:
        parser.feed(html)
    except Exception as exc:  # pragma: no cover - HTMLParser est robuste
        raise UpstreamError("La page de connexion BNP est illisible.") from exc

    if not parser.form_action:
        raise UpstreamError(
            "Formulaire de connexion BNP introuvable (page de login inattendue)."
        )

    tmx = parser.ids.get("idTMX") or parser.inputs.get("pf.idTMX")
    id_tmx = (tmx or {}).get("value", "").strip()
    if not id_tmx:
        raise UpstreamError(
            "Jeton de sécurité BNP introuvable dans le formulaire de connexion."
        )

    grid_match = _GRID_RE.search("\n".join(parser.scripts))
    if not grid_match:
        raise UpstreamError(
            "Grille du clavier BNP introuvable (page de login inattendue)."
        )
    grid = grid_match.group(1)
    if set(grid) != set("0123456789"):
        raise UpstreamError("Grille du clavier BNP invalide.")

    action = urljoin(page_url, parser.form_action)
    host = (urlparse(action).hostname or "").lower()
    if host not in _LOGIN_ACTION_HOSTS:
        raise UpstreamError(
            "Le formulaire de connexion BNP pointe vers un hôte inattendu."
        )

    return LoginForm(
        page_url=page_url,
        action=action,
        grid=grid,
        id_tmx=id_tmx,
    )


def positions_for_password(grid: str, password: str) -> str:
    """Convertit un code à 6 chiffres en positions DOM du clavier BNP.

    La banque mélange les touches à chaque chargement. Le champ
    ``pf.pass.positions`` attend l'index de la touche cliquée (0 à 9), pas le
    chiffre lui-même. Une grille valide est une permutation de 0 à 9.
    """
    if set(grid) != set("0123456789") or len(grid) != 10:
        raise UpstreamError("Grille du clavier BNP invalide.")
    if not _PASSWORD_RE.fullmatch(password):
        raise UsageError("Le code secret BNP doit contenir exactement 6 chiffres.")
    return "".join(str(grid.index(digit)) for digit in password)


def build_login_form_data(
    form: LoginForm, customer_id: str, password: str
) -> dict[str, str]:
    """Construit les champs du POST de connexion, sans conserver le mot de passe.

    Le champ ``pf.encryptedUsername`` n'est renseigné par la banque que lorsque
    la case « Mémoriser mon numéro client » est cochée. On ne la coche jamais :
    le numéro client part en clair, comme dans le navigateur sans mémorisation.
    """
    if not _CUSTOMER_ID_RE.fullmatch(customer_id):
        raise UsageError("Le numéro client BNP doit contenir 7 à 10 chiffres.")

    positions = positions_for_password(form.grid, password)
    return {
        "pf.username": customer_id,
        "pf.encryptedUsername": "",
        "pf.pass.positions": positions,
        "pf.idTMX": form.id_tmx,
    }
