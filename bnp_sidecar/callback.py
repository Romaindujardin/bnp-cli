"""Serveur de callback local pour le flux d'autorisation Enable Banking.

Le serveur écoute uniquement sur la boucle locale, sur le chemin exact de la
redirect URI. Il valide le paramètre ``state`` avant d'accepter un code, ne
journalise jamais la requête (le code est un secret à usage unique) et renvoie
une page HTML minimale sans ressource externe.

En HTTPS, un certificat auto-signé local est généré dans le cache du sidecar
(``0600``) ; le navigateur affiche un avertissement à accepter une fois.
"""

from __future__ import annotations

import html
import ipaddress
import queue
import secrets
import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .errors import (
    AuthenticationError,
    ConfigError,
    ConsentDenied,
    LinkStateError,
    UsageError,
)
from .paths import SidecarPaths
from .private_files import write_private_text

CERTIFICATE_DAYS = 30
CERTIFICATE_RENEW_BEFORE = timedelta(days=3)


@dataclass(frozen=True)
class CallbackResult:
    code: str | None
    state: str | None
    error: str | None
    error_description: str | None

    @property
    def denied(self) -> bool:
        return bool(self.error)


def _loopback_bind_host(hostname: str) -> str:
    if hostname == "::1":
        return "::1"
    return "127.0.0.1"


def _certificate_is_usable(cert_path: Path) -> bool:
    if not cert_path.exists():
        return False
    try:
        certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (ValueError, OSError):
        return False
    not_after = certificate.not_valid_after_utc
    return not_after - CERTIFICATE_RENEW_BEFORE > datetime.now(UTC)


def ensure_localhost_certificate(paths: SidecarPaths) -> tuple[Path, Path]:
    """Retourne (certificat, clé) TLS locaux, en les générant si nécessaire."""
    cert_path = paths.cache_dir / "callback-cert.pem"
    key_path = paths.cache_dir / "callback-key.pem"
    paths.ensure()
    if cert_path.is_symlink() or key_path.is_symlink():
        raise AuthenticationError(
            "Le certificat de callback local est un lien symbolique; refusez de continuer."
        )
    if _certificate_is_usable(cert_path) and key_path.exists():
        return cert_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "bnp-sidecar local callback"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "bnp-sidecar"),
        ]
    )
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=CERTIFICATE_DAYS))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    write_private_text(key_path, key_pem)
    write_private_text(cert_path, cert_pem)
    return cert_path, key_path


def _page(title: str, message: str, *, ok: bool) -> bytes:
    color = "#0a7d32" if ok else "#b00020"
    document = f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{html.escape(title)}</title>
<style>
body {{ font-family: -apple-system, system-ui, sans-serif; margin: 3rem auto; max-width: 36rem; padding: 0 1rem; color: #1c1c1e; }}
h1 {{ color: {color}; font-size: 1.4rem; }}
p {{ line-height: 1.5; }}
code {{ background: #f2f2f7; padding: .1rem .3rem; border-radius: .25rem; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<p>{html.escape(message)}</p>
</body>
</html>
"""
    return document.encode("utf-8")


class _CallbackHandler(BaseHTTPRequestHandler):
    server_version = "bnp-sidecar-callback"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        # Ne jamais journaliser l'URL : elle contient le code d'autorisation.
        return

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path != self.server.callback_path:  # type: ignore[attr-defined]
            self._send(404, _page("Page introuvable", "Ce chemin n'est pas le callback attendu.", ok=False))
            return

        params = parse_qs(parsed.query, keep_blank_values=True)
        state = (params.get("state") or [None])[0]
        code = (params.get("code") or [None])[0]
        error = (params.get("error") or [None])[0]
        description = (params.get("error_description") or [None])[0]

        if not state or not secrets.compare_digest(state, self.server.expected_state):  # type: ignore[attr-defined]
            self._send(
                400,
                _page(
                    "État de sécurité invalide",
                    "Cette réponse ne correspond pas à la demande d'autorisation en cours. "
                    "Relancez 'bnp-sidecar auth link'.",
                    ok=False,
                ),
            )
            return

        if error:
            self._send(
                400,
                _page(
                    "Autorisation refusée",
                    "La banque ou l'utilisateur a refusé l'accès. Vous pouvez fermer cet onglet.",
                    ok=False,
                ),
            )
        else:
            self._send(
                200,
                _page(
                    "Autorisation reçue",
                    "La session bancaire est en cours de création. Vous pouvez fermer cet onglet "
                    "et revenir au terminal.",
                    ok=True,
                ),
            )

        self.server.results.put(  # type: ignore[attr-defined]
            CallbackResult(code=code, state=state, error=error, error_description=description)
        )


class CallbackServer:
    def __init__(self, redirect_uri: str, expected_state: str) -> None:
        parts = urlsplit(redirect_uri)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ConfigError("URL de redirection invalide pour le callback local.")
        if parts.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise UsageError(
                "Le serveur de callback ne peut écouter que sur localhost. "
                "Utilisez 'auth complete --callback-url-stdin' pour une redirection distante."
            )
        if not parts.path:
            raise ConfigError("URL de redirection invalide: chemin absent.")
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError as exc:
            raise ConfigError("URL de redirection invalide: port incorrect.") from exc
        self.redirect_uri = redirect_uri
        self.expected_state = expected_state
        self.host = _loopback_bind_host(parts.hostname)
        self.port = port
        self.path = parts.path
        self.scheme = parts.scheme

    def wait(
        self,
        *,
        timeout: float = 300.0,
        paths: SidecarPaths | None = None,
        on_ready: Callable[[], None] | None = None,
    ) -> CallbackResult:
        if timeout <= 0 or timeout > 1800:
            raise UsageError("Le délai d'attente du callback doit être compris entre 1 et 1800 secondes.")
        results: queue.Queue[CallbackResult] = queue.Queue()

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        try:
            server = Server((self.host, self.port), _CallbackHandler)
        except OSError as exc:
            raise AuthenticationError(
                f"Impossible d'écouter sur {self.host}:{self.port} pour le callback: {exc}. "
                "Vérifiez qu'aucun autre processus n'utilise ce port."
            ) from exc

        server.callback_path = self.path  # type: ignore[attr-defined]
        server.expected_state = self.expected_state  # type: ignore[attr-defined]
        server.results = results  # type: ignore[attr-defined]

        if self.scheme == "https":
            if paths is None:
                raise ConfigError("Cache du sidecar requis pour le certificat TLS local.")
            cert_path, key_path = ensure_localhost_certificate(paths)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            try:
                context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
            except (OSError, ssl.SSLError) as exc:
                server.server_close()
                raise AuthenticationError(
                    f"Certificat TLS local inutilisable: {exc}. Supprimez "
                    f"{cert_path} et {key_path}, puis réessayez."
                ) from exc
            server.socket = context.wrap_socket(server.socket, server_side=True)

        thread = threading.Thread(target=server.serve_forever, name="bnp-callback", daemon=True)
        thread.start()
        try:
            if on_ready is not None:
                on_ready()
            try:
                result = results.get(timeout=timeout)
            except queue.Empty as exc:
                raise AuthenticationError(
                    "Aucun callback d'autorisation reçu avant la fin du délai. "
                    "Relancez 'bnp-sidecar auth link' ou utilisez "
                    "'auth complete --callback-url-stdin'."
                ) from exc
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        if result.denied:
            description = result.error_description or result.error or "autorisation refusée"
            raise ConsentDenied(
                f"L'autorisation BNP a été refusée: {description}.",
                details={"error": result.error},
            )
        if not result.code:
            raise LinkStateError("Le callback ne contient pas de code d'autorisation.")
        return result
