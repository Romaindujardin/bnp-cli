"""Lecture et écriture sécurisées des fichiers privés.

Les fichiers sensibles (configuration, clé privée RSA, session PSD2, état de
liaison) sont ouverts sans suivre un lien symbolique, vérifiés comme fichiers
réguliers et refusés si le groupe ou les autres peuvent les lire. Les écritures
sont atomiques et appliquent ``0600`` avant même d'écrire le contenu.
"""

from __future__ import annotations

import errno
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from .errors import SidecarError

MAX_PRIVATE_FILE_BYTES = 64 * 1024


def _open_error(path: Path, exc: OSError, *, error_cls: type[SidecarError], label: str) -> SidecarError:
    if exc.errno == errno.ELOOP:
        return error_cls(
            f"{label} {path} est un lien symbolique. "
            "Utilisez le chemin réel du fichier, ou supprimez le lien."
        )
    if exc.errno == errno.ENOENT:
        return error_cls(f"{label} introuvable: {path}")
    return error_cls(f"Impossible d'ouvrir {label} {path}: {exc}")


def read_private_text(path: Path, *, error_cls: type[SidecarError], label: str) -> str:
    """Lit un fichier texte privé en refusant liens, modes trop larges et excès de taille."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise _open_error(path, exc, error_cls=error_cls, label=label) from exc

    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise error_cls(f"{label} {path} n'est pas un fichier régulier.")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o077:
            raise error_cls(
                f"{label} {path} est accessible au groupe ou aux autres "
                f"(mode {mode:o}). Corrigez avec: chmod 600 {path}"
            )
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            content = handle.read(MAX_PRIVATE_FILE_BYTES + 1)
        if len(content) > MAX_PRIVATE_FILE_BYTES:
            raise error_cls(f"{label} {path} est trop volumineux.")
        return content
    except UnicodeDecodeError as exc:
        raise error_cls(f"{label} {path} n'est pas un texte UTF-8 valide.") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def read_private_json(path: Path, *, error_cls: type[SidecarError], label: str) -> dict[str, Any]:
    content = read_private_text(path, error_cls=error_cls, label=label)
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise error_cls(f"{label} {path} n'est pas un JSON valide ({exc.msg}).") from exc
    if not isinstance(payload, dict):
        raise error_cls(f"{label} {path} doit contenir un objet JSON.")
    return payload


def write_private_text(path: Path, content: str) -> Path:
    """Écrit un texte en mode ``0600`` de façon atomique.

    Un lien symbolique existant est refusé explicitement : le sidecar ne doit
    jamais écrire à travers un lien, même vers un fichier apparemment privé.
    """
    if path.is_symlink():
        raise SidecarError(
            f"Le chemin {path} est un lien symbolique; refus d'écriture. "
            "Supprimez le lien après vérification."
        )
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}-", suffix=".tmp", dir=str(path.parent)
    )
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        tmp_path.unlink(missing_ok=True)
        raise
    return path


def write_private_json(path: Path, payload: dict[str, Any]) -> Path:
    """Écrit un objet JSON en mode ``0600`` de façon atomique."""
    content = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    return write_private_text(path, content)


def private_file_info(path: Path) -> dict[str, Any]:
    """Métadonnées non sensibles d'un fichier privé, pour ``doctor``/``auth``."""
    info: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "symlink": path.is_symlink(),
        "mode": None,
        "size": None,
        "regular": None,
    }
    try:
        stat_result = path.lstat()
    except OSError:
        return info
    info["mode"] = f"{stat.S_IMODE(stat_result.st_mode):o}"
    info["size"] = stat_result.st_size
    info["regular"] = stat.S_ISREG(stat_result.st_mode)
    return info


def delete_private_file(path: Path) -> bool:
    if path.is_symlink():
        raise SidecarError(
            f"Le fichier {path} est un lien symbolique; le sidecar refuse de le supprimer. "
            "Supprimez-le manuellement après vérification."
        )
    if path.exists():
        path.unlink()
        return True
    return False
