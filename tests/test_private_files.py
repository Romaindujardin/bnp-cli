"""Tests des fichiers privés : modes 0600, symlinks, atomicité."""

from __future__ import annotations

import json
import os
import stat

import pytest

from bnp_sidecar.errors import ConfigError, SidecarError
from bnp_sidecar.private_files import (
    delete_private_file,
    private_file_info,
    read_private_json,
    read_private_text,
    write_private_json,
    write_private_text,
)


def test_write_read_json_is_private(tmp_path) -> None:
    path = tmp_path / "data" / "secret.json"
    write_private_json(path, {"value": "secret"})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert read_private_json(path, error_cls=ConfigError, label="test") == {"value": "secret"}


def test_write_read_text_is_private(tmp_path) -> None:
    path = tmp_path / "secret.txt"
    write_private_text(path, "hello\n")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert read_private_text(path, error_cls=ConfigError, label="test") == "hello\n"


def test_write_creates_private_parent_directory(tmp_path) -> None:
    path = tmp_path / "nested" / "secret.json"
    write_private_json(path, {"value": "secret"})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_reads_refuse_loose_mode(tmp_path) -> None:
    path = tmp_path / "secret.json"
    write_private_json(path, {"a": 1})
    os.chmod(path, 0o644)
    with pytest.raises(ConfigError, match="groupe ou aux autres"):
        read_private_json(path, error_cls=ConfigError, label="test")


def test_reads_refuse_symlink(tmp_path) -> None:
    target = tmp_path / "target.json"
    write_private_json(target, {"a": 1})
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ConfigError, match="lien symbolique"):
        read_private_json(link, error_cls=ConfigError, label="test")


def test_writes_refuse_symlink(tmp_path) -> None:
    target = tmp_path / "target.json"
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(SidecarError, match="lien symbolique"):
        write_private_json(link, {"a": 1})
    assert not target.exists()


def test_reads_refuse_oversized_file(tmp_path) -> None:
    path = tmp_path / "big.json"
    write_private_text(path, "x" * (64 * 1024 + 1))
    with pytest.raises(ConfigError, match="trop volumineux"):
        read_private_json(path, error_cls=ConfigError, label="test")


def test_reads_refuse_invalid_json(tmp_path) -> None:
    path = tmp_path / "bad.json"
    write_private_text(path, "{not json")
    with pytest.raises(ConfigError, match="JSON valide"):
        read_private_json(path, error_cls=ConfigError, label="test")


def test_private_file_info_does_not_follow_symlink(tmp_path) -> None:
    target = tmp_path / "target.json"
    write_private_json(target, {"a": 1})
    link = tmp_path / "link.json"
    link.symlink_to(target)
    info = private_file_info(link)
    assert info["symlink"] is True
    assert info["regular"] is False


def test_delete_refuses_symlink(tmp_path) -> None:
    target = tmp_path / "target.json"
    write_private_json(target, {"a": 1})
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(SidecarError, match="lien symbolique"):
        delete_private_file(link)
    assert target.exists()


def test_json_is_utf8_and_has_no_ascii_escapes(tmp_path) -> None:
    path = tmp_path / "data.json"
    write_private_json(path, {"label": "Épargne"})
    assert "Épargne" in path.read_text(encoding="utf-8")
    assert json.loads(path.read_text(encoding="utf-8"))["label"] == "Épargne"
