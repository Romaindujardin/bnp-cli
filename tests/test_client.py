"""Tests du client Enable Banking contre un faux serveur HTTP local."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from bnp_sidecar.client import EnableBankingClient, _validate_base_url
from bnp_sidecar.config import AppConfig
from bnp_sidecar.errors import (
    AuthenticationError,
    ConfigError,
    NotFoundError,
    SessionExpired,
    UpstreamError,
)
from bnp_sidecar.jwt import b64url_decode

APPLICATION_ID = "cf589be3-3755-465b-a8df-a90a16a31403"
Responder = Callable[[str, str, dict[str, list[str]], dict[str, Any]], tuple[int, Any, dict[str, str]]]


class _Handler(BaseHTTPRequestHandler):
    server_version = "fake-enable-banking"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except json.JSONDecodeError:
            body = {}
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        self.server.requests.append(  # type: ignore[attr-defined]
            {
                "method": self.command,
                "path": parsed.path,
                "query": query,
                "headers": dict(self.headers),
                "body": body,
            }
        )
        responder: Responder = self.server.responder  # type: ignore[attr-defined]
        status, payload, headers = responder(self.command, parsed.path, query, body)
        if isinstance(payload, bytes):
            raw = payload
        elif payload is None:
            raw = b""
        else:
            raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    do_GET = _handle
    do_POST = _handle
    do_DELETE = _handle


@pytest.fixture()
def api():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.requests = []  # type: ignore[attr-defined]
    server.responder = lambda method, path, query, body: (404, {"message": "not found"}, {})  # type: ignore[attr-defined]

    def run() -> None:
        server.serve_forever()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def client(api, private_key_pem: str) -> EnableBankingClient:
    base_url = f"http://127.0.0.1:{api.server_address[1]}"
    return EnableBankingClient(
        AppConfig(application_id=APPLICATION_ID),
        private_key_pem,
        base_url=base_url,
        timeout=5,
    )


def _json(status: int, payload: Any, headers: dict[str, str] | None = None):
    return status, payload, headers or {}


def test_get_application_sends_valid_jwt(client: EnableBankingClient, api) -> None:
    api.responder = lambda method, path, query, body: _json(200, {"countries": ["FR"]})
    assert client.get_application() == {"countries": ["FR"]}
    request = api.requests[0]
    assert request["method"] == "GET"
    assert request["path"] == "/application"
    auth = request["headers"]["Authorization"]
    assert auth.startswith("Bearer ")
    header = json.loads(b64url_decode(auth.split(" ")[1].split(".")[0]))
    assert header["kid"] == APPLICATION_ID


def test_find_aspsp_and_consent(client: EnableBankingClient, api) -> None:
    api.responder = lambda method, path, query, body: _json(
        200,
        {
            "aspsps": [
                {"name": "BNP Paribas", "country": "FR", "maximum_consent_validity": 15552000},
                {"name": "BNP Paribas Business", "country": "FR"},
            ]
        },
    )
    aspsp = client.find_aspsp()
    assert aspsp["name"] == "BNP Paribas"
    assert client.maximum_consent_seconds(aspsp) == 15551940
    assert client.maximum_consent_seconds({"maximum_consent_validity": 999999999}) == 15551940
    assert client.maximum_consent_seconds({}) == 15551940


def test_find_aspsp_not_found_and_ambiguous(client: EnableBankingClient, api) -> None:
    api.responder = lambda method, path, query, body: _json(200, {"aspsps": []})
    with pytest.raises(NotFoundError):
        client.find_aspsp()

    api.responder = lambda method, path, query, body: _json(
        200,
        {
            "aspsps": [
                {"name": "BNP Paribas", "country": "FR"},
                {"name": "BNP Paribas", "country": "FR"},
            ]
        },
    )
    with pytest.raises(UpstreamError, match="Plusieurs"):
        client.find_aspsp()


def test_start_authorization_payload(client: EnableBankingClient, api) -> None:
    api.responder = lambda method, path, query, body: _json(
        200,
        {"url": "https://auth.enablebanking.com/ais/start?sessionid=abc", "authorization_id": "abc"},
    )
    valid_until = datetime.now(UTC)
    payload = client.start_authorization("state-value", valid_until)
    assert payload["authorization_id"] == "abc"
    request = api.requests[0]
    assert request["method"] == "POST"
    assert request["path"] == "/auth"
    body = request["body"]
    assert body["state"] == "state-value"
    assert body["aspsp"] == {"name": "BNP Paribas", "country": "FR"}
    assert body["redirect_url"] == "https://localhost:8787/callback"
    assert body["psu_type"] == "personal"
    assert body["language"] == "fr"
    assert body["access"]["valid_until"].endswith("+00:00")


def test_start_authorization_rejects_unsafe_url(client: EnableBankingClient, api) -> None:
    api.responder = lambda method, path, query, body: _json(200, {"url": "javascript:alert(1)"})
    now = datetime.now(UTC)
    with pytest.raises(UpstreamError, match="pas sûre"):
        client.start_authorization("state", now)


def test_create_get_and_delete_session(client: EnableBankingClient, api) -> None:
    api.responder = lambda method, path, query, body: (
        _json(200, {"session_id": "sid-1", "accounts": []})
        if method == "POST" and path == "/sessions"
        else _json(200, {"session_id": "sid-1", "accounts": []})
        if method == "GET" and path == "/sessions/sid-1"
        else _json(200, {"message": "OK"})
        if method == "DELETE" and path == "/sessions/sid-1"
        else _json(404, {"message": "not found"})
    )
    assert client.create_session("code-1")["session_id"] == "sid-1"
    assert client.get_session("sid-1")["session_id"] == "sid-1"
    client.delete_session("sid-1")
    assert [request["method"] for request in api.requests] == ["POST", "GET", "DELETE"]
    assert api.requests[0]["body"] == {"code": "code-1"}


def test_transactions_pagination(client: EnableBankingClient, api) -> None:
    def responder(method, path, query, body):
        if path != "/accounts/uid-1/transactions":
            return _json(404, {"message": "not found"})
        if query.get("continuation_key") == ["page-2"]:
            return _json(200, {"transactions": [{"entry_reference": "TX-2"}]})
        return _json(
            200,
            {
                "transactions": [{"entry_reference": "TX-1"}],
                "continuation_key": "page-2",
            },
        )

    api.responder = responder
    result = client.get_all_transactions("uid-1", date_from="2026-01-01", strategy="longest")
    assert [item["entry_reference"] for item in result.transactions] == ["TX-1", "TX-2"]
    assert result.pages == 2
    assert result.truncated is False
    first_query = api.requests[0]["query"]
    assert first_query["date_from"] == ["2026-01-01"]
    assert first_query["strategy"] == ["longest"]
    assert api.requests[1]["query"]["continuation_key"] == ["page-2"]


def test_transactions_repeated_continuation_key(client: EnableBankingClient, api) -> None:
    api.responder = lambda method, path, query, body: _json(
        200, {"transactions": [], "continuation_key": "same-key"}
    )
    result = client.get_all_transactions("uid-1")
    assert result.truncated is True
    assert result.pages == 2
    assert result.warnings


def test_transactions_max_pages(client: EnableBankingClient, api) -> None:
    counter = {"value": 0}

    def responder(method, path, query, body):
        counter["value"] += 1
        return _json(200, {"transactions": [], "continuation_key": f"key-{counter['value']}"})

    api.responder = responder
    result = client.get_all_transactions("uid-1", max_pages=2)
    assert result.truncated is True
    assert result.pages == 2
    assert result.continuation_key == "key-2"


def test_authentication_error(client: EnableBankingClient, api) -> None:
    api.responder = lambda method, path, query, body: _json(401, {"message": "bad token"})
    with pytest.raises(AuthenticationError):
        client.get_application()


def test_expired_session_error(client: EnableBankingClient, api) -> None:
    api.responder = lambda method, path, query, body: _json(
        401, {"code": "EXPIRED_SESSION", "message": "expired"}
    )
    with pytest.raises(SessionExpired):
        client.get_session("sid-1")


def test_account_not_found(client: EnableBankingClient, api) -> None:
    api.responder = lambda method, path, query, body: _json(404, {"message": "missing"})
    with pytest.raises(NotFoundError):
        client.get_account_details("uid-1")


def test_session_not_found_is_expired(client: EnableBankingClient, api) -> None:
    api.responder = lambda method, path, query, body: _json(404, {"message": "missing"})
    with pytest.raises(SessionExpired):
        client.get_session("sid-1")


def test_server_error(client: EnableBankingClient, api) -> None:
    api.responder = lambda method, path, query, body: _json(500, {"message": "boom"})
    with pytest.raises(UpstreamError, match="erreur"):
        client.get_application()


def test_redirect_is_refused(client: EnableBankingClient, api) -> None:
    api.responder = lambda method, path, query, body: _json(
        302, None, {"Location": "https://evil.example/"}
    )
    with pytest.raises(UpstreamError, match="redirection"):
        client.get_application()


def test_invalid_json_response(client: EnableBankingClient, api) -> None:
    api.responder = lambda method, path, query, body: (200, b"not-json", {})
    with pytest.raises(UpstreamError, match="JSON invalide"):
        client.get_application()


def test_bad_credentials_are_rejected_locally(private_key_pem: str) -> None:
    with pytest.raises(ConfigError):
        EnableBankingClient(AppConfig(application_id=""), private_key_pem)


def test_base_url_validation() -> None:
    assert _validate_base_url("https://api.enablebanking.com") == "https://api.enablebanking.com"
    assert _validate_base_url("http://127.0.0.1:1234") == "http://127.0.0.1:1234"
    with pytest.raises(ConfigError):
        _validate_base_url("http://example.com")
    with pytest.raises(ConfigError):
        _validate_base_url("https://example.com/path")
    with pytest.raises(ConfigError):
        _validate_base_url("https://user:pass@example.com")
