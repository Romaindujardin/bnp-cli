"""Tests de bout en bout de la CLI, sans réseau externe."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from datetime import timedelta
from io import StringIO

from bnp_sidecar.cli import main
from bnp_sidecar.config import AppConfig, save_config
from bnp_sidecar.errors import UpstreamError
from bnp_sidecar.paths import SidecarPaths
from bnp_sidecar.session import (
    PendingLink,
    SessionRecord,
    accounts_from_session_payload,
    isoformat,
    load_pending_link,
    load_session,
    save_pending_link,
    save_session,
    utc_now,
)
from tests.conftest import APPLICATION_ID, FakeEnableBankingClient, session_payload


def run_cli(
    paths: SidecarPaths,
    args: list[str],
    *,
    stdin: str = "",
    client_factory=None,
    browser_opener=None,
) -> tuple[int, dict, str]:
    stdout = StringIO()
    stderr = StringIO()
    code = main(
        ["--data-dir", str(paths.root), *args],
        stdout=stdout,
        stderr=stderr,
        stdin=StringIO(stdin),
        client_factory=client_factory,
        browser_opener=browser_opener,
    )
    output = stdout.getvalue()
    payload = json.loads(output) if output.strip() else {}
    return code, payload, stderr.getvalue()


def _configure(paths: SidecarPaths, private_key_pem: str, **overrides) -> AppConfig:
    config = AppConfig(application_id=APPLICATION_ID, **overrides)
    save_config(paths, config, private_key_pem)
    return config


def _save_linked_session(paths: SidecarPaths, payload: dict | None = None) -> None:
    payload = payload or session_payload()
    now = isoformat(utc_now())
    save_session(
        paths,
        SessionRecord(
            session_id=payload["session_id"],
            created_at=now,
            authorized_at=now,
            valid_until=payload["access"]["valid_until"],
            aspsp_name="BNP Paribas",
            aspsp_country="FR",
            psu_type="personal",
            redirect_uri="https://localhost:8787/callback",
            accounts=accounts_from_session_payload(payload),
            status="AUTHORIZED",
        ),
    )


def _pending(state: str = "state-" + "x" * 40) -> PendingLink:
    now = utc_now()
    return PendingLink(
        state=state,
        created_at=isoformat(now),
        expires_at=isoformat(now + timedelta(minutes=10)),
        aspsp_name="BNP Paribas",
        aspsp_country="FR",
        psu_type="personal",
        redirect_uri="https://localhost:8787/callback",
        valid_until=isoformat(now + timedelta(days=170)),
    )


def test_auth_setup_and_status(paths, tmp_path, private_key_pem) -> None:
    key_path = tmp_path / "key.pem"
    key_path.write_text(private_key_pem)
    key_path.chmod(0o600)
    code, payload, stderr = run_cli(
        paths,
        [
            "auth",
            "setup",
            "--application-id",
            APPLICATION_ID,
            "--private-key",
            str(key_path),
            "--redirect-uri",
            "http://localhost:8787/callback",
        ],
    )
    assert code == 0, stderr
    assert payload["ok"] is True
    assert payload["applicationIdMasked"] == "cf589be3…"
    assert payload["keyFingerprint"]
    assert "PRIVATE KEY" not in json.dumps(payload)
    assert paths.config_file.exists()
    assert (paths.config_file.stat().st_mode & 0o777) == 0o600

    code, status, stderr = run_cli(paths, ["auth", "status"])
    assert code == 0, stderr
    assert status["configured"] is True
    assert status["ready"] is False
    assert status["session"] is None


def test_auth_setup_private_key_stdin(paths, private_key_pem) -> None:
    code, payload, stderr = run_cli(
        paths,
        ["auth", "setup", "--application-id", APPLICATION_ID, "--private-key-stdin"],
        stdin=private_key_pem,
    )
    assert code == 0, stderr
    assert payload["result"] == "configured"
    assert paths.private_key_file.exists()
    assert private_key_pem.strip() not in stderr


def test_auth_complete_links_session(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    pending = _pending()
    save_pending_link(paths, pending)
    fake = FakeEnableBankingClient()
    code, payload, stderr = run_cli(
        paths,
        [
            "auth",
            "complete",
            "--callback-url",
            f"http://localhost:8787/callback?code=one-time-code&state={pending.state}",
        ],
        client_factory=lambda config, key: fake,
    )
    assert code == 0, stderr
    assert payload["status"] == "linked"
    assert len(payload["accounts"]) == 2
    assert fake.created_codes == ["one-time-code"]
    assert load_session(paths) is not None
    assert load_pending_link(paths) is None
    assert fake.session_payload["session_id"] not in json.dumps(payload)
    assert "one-time-code" not in json.dumps(payload)


def test_auth_complete_callback_stdin(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    pending = _pending()
    save_pending_link(paths, pending)
    fake = FakeEnableBankingClient()
    callback = f"code=abc&state={pending.state}"
    code, payload, stderr = run_cli(
        paths,
        ["auth", "complete", "--callback-url-stdin"],
        stdin=callback + "\n",
        client_factory=lambda config, key: fake,
    )
    assert code == 0, stderr
    assert payload["status"] == "linked"
    assert fake.created_codes == ["abc"]


def test_auth_complete_rejects_wrong_state(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    pending = _pending()
    save_pending_link(paths, pending)
    code, _payload, stderr = run_cli(
        paths,
        [
            "auth",
            "complete",
            "--callback-url",
            "http://localhost:8787/callback?code=secret-code&state=wrong",
        ],
        client_factory=lambda config, key: FakeEnableBankingClient(),
    )
    assert code == 4
    error = json.loads(stderr)
    assert error["error"]["code"] == "LINK_STATE_INVALID"
    assert "secret-code" not in stderr
    assert load_pending_link(paths) is not None


def test_auth_complete_denied(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    pending = _pending()
    save_pending_link(paths, pending)
    code, _, stderr = run_cli(
        paths,
        [
            "auth",
            "complete",
            "--callback-url",
            f"http://localhost:8787/callback?error=access_denied&state={pending.state}",
        ],
        client_factory=lambda config, key: FakeEnableBankingClient(),
    )
    assert code == 4
    assert json.loads(stderr)["error"]["code"] == "CONSENT_DENIED"
    assert load_pending_link(paths) is None


def test_accounts(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    _save_linked_session(paths)
    fake = FakeEnableBankingClient()
    code, payload, stderr = run_cli(
        paths, ["accounts"], client_factory=lambda config, key: fake
    )
    assert code == 0, stderr
    assert payload["schema"] == "bnp-sidecar/accounts/v1"
    assert payload["status"] == "ok"
    assert len(payload["accounts"]) == 2
    checking = payload["accounts"][0]
    assert checking["balance"] == 1000.5
    assert checking["availableBalance"] == 900.25
    assert payload["totals"]["balances"] == {"EUR": 6000.5}


def test_accounts_selector_and_partial(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    _save_linked_session(paths)
    fake = FakeEnableBankingClient()
    code, payload, stderr = run_cli(
        paths,
        ["accounts", "--account", "Livret A"],
        client_factory=lambda config, key: fake,
    )
    assert code == 0, stderr
    assert len(payload["accounts"]) == 1
    assert payload["accounts"][0]["name"] == "Livret A"

    fake.fail_accounts.add("uid-account-1")
    code, payload, stderr = run_cli(
        paths, ["accounts"], client_factory=lambda config, key: fake
    )
    assert code == 0, stderr
    assert payload["status"] == "partial"
    assert len(payload["errors"]) == 1
    assert len(payload["accounts"]) == 1


def test_accounts_unknown_selector(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    _save_linked_session(paths)
    code, _, stderr = run_cli(
        paths,
        ["accounts", "--account", "inconnu"],
        client_factory=lambda config, key: FakeEnableBankingClient(),
    )
    assert code == 2
    assert json.loads(stderr)["error"]["code"] == "USAGE_ERROR"


def test_transactions(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    _save_linked_session(paths)
    fake = FakeEnableBankingClient()
    code, payload, stderr = run_cli(
        paths,
        ["transactions", "--from", "2026-11-01", "--to", "2026-11-30"],
        client_factory=lambda config, key: fake,
    )
    assert code == 0, stderr
    assert payload["schema"] == "bnp-sidecar/transactions/v1"
    assert payload["status"] == "ok"
    assert payload["summary"] == {"accounts": 2, "transactions": 3}
    checking = payload["accounts"][0]
    assert checking["transactions"][0]["id"] == "TX-1"
    assert checking["transactions"][0]["amount"] == -12.34
    assert payload["dateFrom"] == "2026-11-01"
    assert all(
        call["date_from"] == "2026-11-01" and call["date_to"] == "2026-11-30"
        for call in fake.transaction_calls
    )


def test_transactions_limit_and_pending(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    _save_linked_session(paths)
    fake = FakeEnableBankingClient()
    code, payload, stderr = run_cli(
        paths,
        ["transactions", "--account", "uid-account-1", "--limit", "1", "--pending"],
        client_factory=lambda config, key: fake,
    )
    assert code == 0, stderr
    assert len(payload["accounts"][0]["transactions"]) == 1
    assert payload["accounts"][0]["limited"] is True
    assert payload["transactionStatus"] == "PDNG"
    assert fake.transaction_calls[0]["transaction_status"] == "PDNG"


def test_transactions_validation(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    _save_linked_session(paths)
    code, _, stderr = run_cli(
        paths,
        ["transactions", "--from", "2026-02-30"],
        client_factory=lambda config, key: FakeEnableBankingClient(),
    )
    assert code == 2
    assert json.loads(stderr)["error"]["code"] == "USAGE_ERROR"

    code, _, stderr = run_cli(
        paths,
        ["transactions", "--from", "2026-12-01", "--to", "2026-11-01"],
        client_factory=lambda config, key: FakeEnableBankingClient(),
    )
    assert code == 2


def test_export_and_output_file(paths, private_key_pem, tmp_path) -> None:
    _configure(paths, private_key_pem)
    _save_linked_session(paths)
    fake = FakeEnableBankingClient()
    code, payload, stderr = run_cli(
        paths, ["export"], client_factory=lambda config, key: fake
    )
    assert code == 0, stderr
    assert payload["schema"] == "bnp-sidecar/export/v1"
    assert payload["status"] == "ok"
    assert payload["totals"]["balances"] == {"EUR": 6000.5}
    assert payload["totals"]["transactions"] == 3

    output = tmp_path / "export.json"
    code, receipt, stderr = run_cli(
        paths,
        ["export", "--output", str(output)],
        client_factory=lambda config, key: fake,
    )
    assert code == 0, stderr
    assert receipt["schema"] == "bnp-sidecar/export-file/v1"
    assert receipt["path"] == str(output.resolve())
    assert (output.stat().st_mode & 0o777) == 0o600
    document = json.loads(output.read_text())
    assert document["schema"] == "bnp-sidecar/export/v1"
    assert "PRIVATE KEY" not in output.read_text()


def test_export_partial(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    _save_linked_session(paths)
    fake = FakeEnableBankingClient()
    fake.fail_accounts.add("uid-account-1")
    code, payload, stderr = run_cli(
        paths, ["export"], client_factory=lambda config, key: fake
    )
    assert code == 0, stderr
    assert payload["status"] == "partial"
    assert payload["errors"][0]["step"] == "account"
    assert len(payload["accounts"]) == 2
    assert payload["accounts"][0]["transactions"] == []
    assert payload["accounts"][0]["transactionsTruncated"] is True
    assert payload["accounts"][1]["transactions"]


def test_doctor(paths, private_key_pem) -> None:
    code, payload, stderr = run_cli(paths, ["doctor"])
    assert code == 1, stderr
    assert payload["configured"] is False
    assert any(check["name"] == "config" and not check["ok"] for check in payload["checks"])

    _configure(paths, private_key_pem)
    _save_linked_session(paths)
    fake = FakeEnableBankingClient()
    code, payload, stderr = run_cli(
        paths, ["doctor", "--network"], client_factory=lambda config, key: fake
    )
    assert code == 0, stderr
    assert payload["ready"] is True
    assert any(check["name"] == "aspsp" and check["ok"] for check in payload["checks"])


def test_logout_and_forget(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    _save_linked_session(paths)
    pending = _pending()
    save_pending_link(paths, pending)
    fake = FakeEnableBankingClient()
    code, payload, stderr = run_cli(
        paths, ["auth", "logout"], client_factory=lambda config, key: fake
    )
    assert code == 0, stderr
    assert payload["sessionDeleted"] is True
    assert payload["remoteSessionRevoked"] is True
    assert payload["pendingLinkDeleted"] is True
    assert fake.deleted_sessions == ["11111111-2222-3333-4444-555555555555"]
    assert paths.config_file.exists()

    code, payload, stderr = run_cli(
        paths, ["auth", "logout", "--forget"], client_factory=lambda config, key: fake
    )
    assert code == 0, stderr
    assert payload["forgot"] is True
    assert not paths.config_file.exists()
    assert not paths.private_key_file.exists()


def test_auth_link_no_wait(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    fake = FakeEnableBankingClient()
    opened: list[str] = []
    code, payload, stderr = run_cli(
        paths,
        ["auth", "link", "--no-wait", "--no-open"],
        client_factory=lambda config, key: fake,
        browser_opener=lambda url: opened.append(url) or True,
    )
    assert code == 0, stderr
    assert payload["status"] == "pending"
    assert payload["authUrl"].startswith("https://auth.enablebanking.com/")
    assert payload["waiting"] is False
    pending = load_pending_link(paths)
    assert pending is not None
    assert pending.state not in json.dumps(payload)
    assert opened == []


def test_auth_link_full_local_callback(paths, private_key_pem) -> None:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    redirect = f"http://127.0.0.1:{port}/callback"
    _configure(paths, private_key_pem, redirect_uri=redirect)
    fake = FakeEnableBankingClient()

    def opener(auth_url: str) -> bool:
        pending = load_pending_link(paths)
        assert pending is not None
        query = urllib.parse.urlencode({"code": "callback-code", "state": pending.state})
        with urllib.request.urlopen(f"{redirect}?{query}", timeout=5) as response:
            assert response.status == 200
        return True

    code, payload, stderr = run_cli(
        paths,
        ["auth", "link", "--timeout", "5"],
        client_factory=lambda config, key: fake,
        browser_opener=opener,
    )
    assert code == 0, stderr
    assert payload["status"] == "linked"
    assert fake.created_codes == ["callback-code"]
    assert load_session(paths) is not None


def test_error_message_is_redacted(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    _save_linked_session(paths)

    class LeakyClient(FakeEnableBankingClient):
        def get_account_details(self, uid: str):
            raise UpstreamError(f"échec avec {APPLICATION_ID} et une clé {private_key_pem}")

    code, _, stderr = run_cli(
        paths, ["accounts"], client_factory=lambda config, key: LeakyClient()
    )
    assert code == 5
    assert APPLICATION_ID not in stderr
    assert "PRIVATE KEY" not in stderr
    assert json.loads(stderr)["error"]["code"] == "UPSTREAM_ERROR"


def test_missing_session(paths, private_key_pem) -> None:
    _configure(paths, private_key_pem)
    code, _, stderr = run_cli(paths, ["accounts"])
    assert code == 3
    assert json.loads(stderr)["error"]["code"] == "SESSION_ERROR"


def test_unknown_command(paths) -> None:
    code, _, stderr = run_cli(paths, ["nope"])
    assert code == 2
    assert json.loads(stderr)["error"]["code"] == "USAGE_ERROR"
