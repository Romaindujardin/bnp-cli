"""Tests du serveur de callback local."""

from __future__ import annotations

import socket
import threading
import urllib.error
import urllib.request

import pytest
from cryptography import x509

from bnp_sidecar.callback import CallbackServer, ensure_localhost_certificate
from bnp_sidecar.errors import AuthenticationError, ConsentDenied, UsageError

STATE = "state-" + "x" * 40


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run(server: CallbackServer, timeout: float = 5.0):
    ready = threading.Event()
    holder: dict[str, object] = {}

    def target() -> None:
        try:
            holder["result"] = server.wait(timeout=timeout, on_ready=ready.set)
        except BaseException as exc:  # noqa: BLE001 - transmis au test
            holder["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    assert ready.wait(3), "le serveur de callback n'a pas démarré"
    return thread, holder


def test_callback_success() -> None:
    port = _free_port()
    redirect = f"http://127.0.0.1:{port}/callback"
    thread, holder = _run(CallbackServer(redirect, STATE))
    with urllib.request.urlopen(f"{redirect}?code=one-time-code&state={STATE}", timeout=5) as response:
        body = response.read().decode("utf-8")
        assert response.status == 200
        assert "Autorisation reçue" in body
        assert "one-time-code" not in body
    thread.join(5)
    result = holder["result"]
    assert result.code == "one-time-code"
    assert result.state == STATE


def test_callback_rejects_wrong_state_then_accepts_correct_one() -> None:
    port = _free_port()
    redirect = f"http://127.0.0.1:{port}/callback"
    thread, holder = _run(CallbackServer(redirect, STATE))
    try:
        urllib.request.urlopen(f"{redirect}?code=bad&state=wrong", timeout=5)
    except urllib.error.HTTPError as exc:
        assert exc.code == 400
        assert "État de sécurité invalide".encode() in exc.read()
    with urllib.request.urlopen(f"{redirect}?code=good&state={STATE}", timeout=5) as response:
        assert response.status == 200
    thread.join(5)
    assert holder["result"].code == "good"


def test_callback_denied() -> None:
    port = _free_port()
    redirect = f"http://127.0.0.1:{port}/callback"
    thread, holder = _run(CallbackServer(redirect, STATE))
    try:
        urllib.request.urlopen(
            f"{redirect}?error=access_denied&error_description=refus&state={STATE}",
            timeout=5,
        )
    except urllib.error.HTTPError as exc:
        assert exc.code == 400
    thread.join(5)
    assert isinstance(holder.get("error"), ConsentDenied)


def test_callback_unknown_path_is_404() -> None:
    port = _free_port()
    redirect = f"http://127.0.0.1:{port}/callback"
    thread, holder = _run(CallbackServer(redirect, STATE))
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/other", timeout=5)
    except urllib.error.HTTPError as exc:
        assert exc.code == 404
    with urllib.request.urlopen(f"{redirect}?code=ok&state={STATE}", timeout=5):
        pass
    thread.join(5)
    assert holder["result"].code == "ok"


def test_callback_timeout() -> None:
    port = _free_port()
    server = CallbackServer(f"http://127.0.0.1:{port}/callback", STATE)
    with pytest.raises(AuthenticationError, match="Aucun callback"):
        server.wait(timeout=0.2)


def test_callback_refuses_non_loopback() -> None:
    with pytest.raises(UsageError, match="localhost"):
        CallbackServer("https://example.com/callback", STATE)


def test_localhost_certificate_is_private_and_valid(paths) -> None:
    cert_path, key_path = ensure_localhost_certificate(paths)
    assert cert_path.exists() and key_path.exists()
    assert oct(cert_path.stat().st_mode & 0o777) == "0o600"
    assert oct(key_path.stat().st_mode & 0o777) == "0o600"
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in names.get_values_for_type(x509.DNSName)
    before = cert_path.read_bytes()
    second = ensure_localhost_certificate(paths)
    assert second == (cert_path, key_path)
    assert cert_path.read_bytes() == before
