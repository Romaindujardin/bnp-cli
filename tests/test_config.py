"""Tests de la configuration Enable Banking."""

from __future__ import annotations

import stat

import pytest

from bnp_sidecar.config import (
    DEFAULT_BASE_URL,
    MAX_CONSENT_SECONDS,
    AppConfig,
    config_secrets,
    config_summary,
    delete_config,
    load_config,
    mask_application_id,
    redirect_is_loopback,
    save_config,
    validate_base_url,
    validate_redirect_uri,
)
from bnp_sidecar.errors import ConfigError


def test_save_and_load_roundtrip(paths, app_config, private_key_pem) -> None:
    save_config(paths, app_config, private_key_pem)
    loaded, key = load_config(paths)
    assert loaded == app_config
    assert key is not None and "PRIVATE KEY" in key
    assert stat.S_IMODE(paths.config_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(paths.private_key_file.stat().st_mode) == 0o600
    assert "privateKey" not in paths.config_file.read_text()


def test_load_without_key(paths, app_config, private_key_pem) -> None:
    save_config(paths, app_config, private_key_pem)
    loaded, key = load_config(paths, require_private_key=False)
    assert loaded == app_config
    assert key is None


def test_load_requires_private_key(paths, app_config, private_key_pem) -> None:
    save_config(paths, app_config, private_key_pem)
    paths.private_key_file.write_text("not-a-key", encoding="utf-8")
    paths.private_key_file.chmod(0o600)
    with pytest.raises(ConfigError):
        load_config(paths)


def test_config_rejects_unknown_schema(paths, private_key_pem) -> None:
    paths.ensure()
    (paths.config_file).write_text('{"schema": "other/v1", "applicationId": "abc"}')
    (paths.private_key_file).write_text(private_key_pem)
    for path in (paths.config_file, paths.private_key_file):
        path.chmod(0o600)
    with pytest.raises(ConfigError, match="Schéma"):
        load_config(paths)


def test_validation_rejects_bad_values() -> None:
    with pytest.raises(ConfigError):
        AppConfig(application_id="").validate()
    with pytest.raises(ConfigError):
        AppConfig(application_id="has space").validate()
    with pytest.raises(ConfigError):
        AppConfig(application_id="abc", aspsp_country="FRA").validate()
    with pytest.raises(ConfigError):
        AppConfig(application_id="abc", psu_type="robot").validate()
    with pytest.raises(ConfigError):
        AppConfig(application_id="abc", language="français").validate()
    with pytest.raises(ConfigError):
        AppConfig(application_id="abc", base_url="https://evil.example").validate()


def test_redirect_uri_rules() -> None:
    assert validate_redirect_uri("https://localhost:8787/callback")
    assert validate_redirect_uri("http://127.0.0.1:8787/callback")
    with pytest.raises(ConfigError):
        validate_redirect_uri("http://example.com/callback")
    with pytest.raises(ConfigError):
        validate_redirect_uri("ftp://example.com/callback")
    with pytest.raises(ConfigError):
        validate_redirect_uri("https://user:pass@example.com/callback")
    with pytest.raises(ConfigError):
        validate_redirect_uri("https://example.com/callback#fragment")
    with pytest.raises(ConfigError):
        validate_redirect_uri("https://example.com")
    assert redirect_is_loopback("https://localhost:8787/callback")
    assert redirect_is_loopback("http://[::1]:8787/callback")
    assert not redirect_is_loopback("https://example.com/callback")


def test_base_url_is_fixed() -> None:
    assert validate_base_url(DEFAULT_BASE_URL) == DEFAULT_BASE_URL
    with pytest.raises(ConfigError):
        validate_base_url("https://evil.example")


def test_mask_and_summary(paths, app_config, private_key_pem) -> None:
    save_config(paths, app_config, private_key_pem)
    loaded, key = load_config(paths)
    assert mask_application_id(loaded.application_id).endswith("…")
    summary = config_summary(paths, loaded, key)
    assert summary["applicationIdMasked"] == "cf589be3…"
    assert summary["keyFingerprint"]
    assert "PRIVATE KEY" not in str(summary)
    secrets = config_secrets(loaded, key)
    assert loaded.application_id in secrets
    assert key in secrets


def test_delete_config(paths, app_config, private_key_pem) -> None:
    save_config(paths, app_config, private_key_pem)
    removed = delete_config(paths)
    assert "config.json" in removed and "private-key.pem" in removed
    assert not paths.config_file.exists()
    assert not paths.private_key_file.exists()


def test_delete_refuses_symlink(paths, app_config, private_key_pem) -> None:
    save_config(paths, app_config, private_key_pem)
    target = paths.root / "target.json"
    target.write_text("{}")
    paths.config_file.unlink()
    paths.config_file.symlink_to(target)
    with pytest.raises(ConfigError, match="lien symbolique"):
        delete_config(paths)
    assert target.exists()


def test_consent_cap_is_180_days() -> None:
    assert MAX_CONSENT_SECONDS == 180 * 24 * 3600
