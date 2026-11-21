"""Tests de la session PSD2 et de l'état de liaison."""

from __future__ import annotations

from datetime import timedelta

import pytest

from bnp_sidecar.errors import SessionError, SessionExpired, UsageError
from bnp_sidecar.session import (
    PendingLink,
    SessionAccount,
    SessionRecord,
    accounts_from_session_payload,
    delete_pending_link,
    delete_session_file,
    isoformat,
    load_pending_link,
    load_session,
    require_session,
    save_pending_link,
    save_session,
    select_accounts,
    utc_now,
)
from tests.conftest import session_payload


def _session(accounts: list[SessionAccount] | None = None, **overrides) -> SessionRecord:
    now = utc_now()
    data = {
        "session_id": "11111111-2222-3333-4444-555555555555",
        "created_at": isoformat(now),
        "valid_until": isoformat(now + timedelta(days=170)),
        "aspsp_name": "BNP Paribas",
        "aspsp_country": "FR",
        "psu_type": "personal",
        "redirect_uri": "https://localhost:8787/callback",
        "accounts": accounts or [SessionAccount(uid="uid-1", name="Compte")],
        "status": "AUTHORIZED",
    }
    data.update(overrides)
    return SessionRecord(**data)


def test_session_roundtrip(paths) -> None:
    session = _session()
    save_session(paths, session)
    loaded = load_session(paths)
    assert loaded is not None
    assert loaded.session_id == session.session_id
    assert loaded.accounts[0].uid == "uid-1"
    assert load_session(paths).valid_until == session.valid_until


def test_require_session_missing(paths) -> None:
    with pytest.raises(SessionError, match="Aucune session"):
        require_session(paths)


def test_expired_session_is_refused(paths) -> None:
    session = _session(valid_until=isoformat(utc_now() - timedelta(seconds=1)))
    save_session(paths, session)
    assert session.is_expired()
    with pytest.raises(SessionExpired, match="expiré"):
        require_session(paths)


def test_session_days_remaining() -> None:
    session = _session(valid_until=isoformat(utc_now() + timedelta(days=10, hours=1)))
    assert session.days_remaining() == 10


def test_session_summary_does_not_expose_id(paths) -> None:
    session = _session()
    summary = session.summary()
    assert session.session_id not in str(summary)
    assert summary["accounts"] == 1


def test_delete_session_refuses_symlink(paths) -> None:
    target = paths.root / "target.json"
    target.write_text("{}")
    paths.session_file.parent.mkdir(parents=True, exist_ok=True)
    paths.session_file.symlink_to(target)
    with pytest.raises(SessionError, match="lien symbolique"):
        delete_session_file(paths)
    assert target.exists()


def test_pending_link_roundtrip_and_state(paths) -> None:
    now = utc_now()
    pending = PendingLink(
        state="x" * 43,
        created_at=isoformat(now),
        expires_at=isoformat(now + timedelta(minutes=10)),
        aspsp_name="BNP Paribas",
        aspsp_country="FR",
        psu_type="personal",
        redirect_uri="https://localhost:8787/callback",
    )
    save_pending_link(paths, pending)
    loaded = load_pending_link(paths)
    assert loaded is not None
    assert loaded.matches_state("x" * 43)
    assert not loaded.matches_state("y" * 43)
    assert not loaded.is_expired()
    assert delete_pending_link(paths) is True
    assert load_pending_link(paths) is None


def test_expired_pending_link() -> None:
    now = utc_now()
    pending = PendingLink(
        state="x" * 43,
        created_at=isoformat(now - timedelta(minutes=20)),
        expires_at=isoformat(now - timedelta(minutes=1)),
        aspsp_name="BNP Paribas",
        aspsp_country="FR",
        psu_type="personal",
        redirect_uri="https://localhost:8787/callback",
    )
    assert pending.is_expired()


def test_accounts_from_post_session() -> None:
    accounts = accounts_from_session_payload(session_payload())
    assert [account.uid for account in accounts] == ["uid-account-1", "uid-account-2"]
    assert accounts[0].identification_hash == "hash-account-1"
    assert accounts[0].iban == "FR7630006000011234567890189"


def test_accounts_from_get_session() -> None:
    payload = {
        "accounts": ["uid-a", "uid-b"],
        "accounts_data": [
            {"uid": "uid-a", "identification_hash": "hash-a"},
            {"uid": "uid-b", "identification_hash": "hash-b"},
        ],
    }
    accounts = accounts_from_session_payload(payload)
    assert [(account.uid, account.identification_hash) for account in accounts] == [
        ("uid-a", "hash-a"),
        ("uid-b", "hash-b"),
    ]


def test_accounts_are_deduplicated() -> None:
    payload = {
        "accounts": [
            {"uid": "uid-a", "name": "A"},
            {"uid": "uid-a", "name": "A bis"},
        ],
        "accounts_data": [{"uid": "uid-a", "identification_hash": "hash-a"}],
    }
    accounts = accounts_from_session_payload(payload)
    assert len(accounts) == 1
    assert accounts[0].identification_hash == "hash-a"


def test_select_accounts_by_uid_iban_and_name() -> None:
    accounts = [
        SessionAccount(uid="uid-a", name="Compte de dépôt", iban="FR7611111111111111111111111"),
        SessionAccount(uid="uid-b", name="Livret A", iban="FR7622222222222222222222222"),
    ]
    session = _session(accounts=accounts)
    assert [account.uid for account in select_accounts(session, ["uid-a"])] == ["uid-a"]
    assert [account.uid for account in select_accounts(session, ["fr7622222222222222222222222"])] == ["uid-b"]
    assert [account.uid for account in select_accounts(session, ["Livret A"])] == ["uid-b"]


def test_select_accounts_unknown_and_ambiguous() -> None:
    accounts = [
        SessionAccount(uid="uid-a", name="Compte"),
        SessionAccount(uid="uid-b", name="Compte"),
    ]
    session = _session(accounts=accounts)
    with pytest.raises(UsageError, match="Aucun compte"):
        select_accounts(session, ["nope"])
    with pytest.raises(UsageError, match="plusieurs comptes"):
        select_accounts(session, ["Compte"])
