"""Chemins et isolation du sidecar.

Tout ce que le sidecar écrit (configuration Enable Banking, session PSD2,
pending link) reste sous un répertoire unique, avec des permissions privées.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .errors import UsageError

APP_DIR_NAME = "bnp-sidecar"


def _ensure_private_directory(path: Path) -> None:
    """Crée un répertoire privé sans modifier un répertoire préexistant.

    Un répertoire déjà présent peut appartenir à l'utilisateur ou être partagé
    (par exemple ``/tmp``) : le sidecar ne doit jamais en changer les
    permissions. Seuls les répertoires qu'il crée passent en ``0700``.
    """
    if path.exists():
        if not path.is_dir():
            raise UsageError(
                f"Le chemin {path} existe mais n'est pas un répertoire. "
                "Choisissez un autre --data-dir ou BNP_SIDECAR_HOME."
            )
        return

    try:
        path.mkdir(parents=True, mode=0o700)
    except FileExistsError:
        if not path.is_dir():
            raise UsageError(
                f"Le chemin {path} existe mais n'est pas un répertoire. "
                "Choisissez un autre --data-dir ou BNP_SIDECAR_HOME."
            ) from None
        return
    except OSError as exc:
        raise UsageError(f"Impossible de créer le répertoire {path}: {exc}") from exc

    os.chmod(path, 0o700)


@dataclass(frozen=True)
class SidecarPaths:
    root: Path
    config_dir: Path
    data_dir: Path
    cache_dir: Path
    home_dir: Path
    config_file: Path
    private_key_file: Path
    session_file: Path
    pending_link_file: Path

    @classmethod
    def from_root(cls, root: str | os.PathLike[str]) -> SidecarPaths:
        root_path = Path(root).expanduser().resolve()
        config_dir = root_path / "config"
        data_dir = root_path / "data"
        cache_dir = root_path / "cache"
        home_dir = root_path / "home"
        return cls(
            root=root_path,
            config_dir=config_dir,
            data_dir=data_dir,
            cache_dir=cache_dir,
            home_dir=home_dir,
            config_file=config_dir / "config.json",
            private_key_file=config_dir / "private-key.pem",
            session_file=data_dir / "session.json",
            pending_link_file=data_dir / "pending-link.json",
        )

    @classmethod
    def default(cls) -> SidecarPaths:
        configured = os.environ.get("BNP_SIDECAR_HOME")
        if configured:
            return cls.from_root(configured)
        return cls.from_root(Path.home() / ".local" / "share" / APP_DIR_NAME)

    def ensure(self) -> SidecarPaths:
        for directory in (
            self.root,
            self.config_dir,
            self.data_dir,
            self.cache_dir,
            self.home_dir,
        ):
            _ensure_private_directory(directory)
        return self

    def apply_sandbox_env(self) -> dict[str, str | None]:
        """Isole les éventuelles écritures de bibliothèques tierces.

        Le sidecar n'utilise que la bibliothèque standard et ``cryptography``,
        qui n'écrit pas dans le HOME. Cette isolation est une défense
        supplémentaire, pas une dépendance fonctionnelle.
        """
        keys = ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME")
        previous = {key: os.environ.get(key) for key in keys}
        os.environ["HOME"] = str(self.home_dir)
        os.environ["XDG_CONFIG_HOME"] = str(self.config_dir)
        os.environ["XDG_DATA_HOME"] = str(self.data_dir)
        os.environ["XDG_CACHE_HOME"] = str(self.cache_dir)
        return previous

    @staticmethod
    def restore_env(previous: dict[str, str | None]) -> None:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
