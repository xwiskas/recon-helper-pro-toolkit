"""Configuration, data locations, and the settings defaults (PRD 7.4, 7.6, 19).

Settings live in the ``settings`` table of the SQLite database; this module owns
the defaults, the type coercion, and the resolution of where data is stored.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

APP_DIR_NAME = "ReconHelperPro"
ENV_DATA_DIR = "RHP_DATA_DIR"

#: Default settings. Keys are dotted strings stored verbatim in the DB.
DEFAULTS: dict[str, Any] = {
    # --- request policy (PRD 7.4) -------------------------------------
    "request.delay_ms": 1000,
    # Reserved: the phase 1 client issues requests sequentially, which is always
    # within this ceiling. It is honoured as an upper bound, not a target.
    "request.max_concurrency": 2,
    "request.enumerative_budget": 100,
    "request.timeout_s": 10,
    "request.max_redirects": 5,
    "request.max_body_bytes": 2 * 1024 * 1024,
    "request.user_agent": (
        "ReconHelperPro/0.1 (+https://example.invalid/recon-helper-pro; "
        "read-only recon; contact the operator of this scan)"
    ),
    # --- global ceilings / kill switch (PRD 7.4) ----------------------
    "limits.per_host_requests": 500,
    "limits.per_engagement_requests": 2000,
    # --- data at rest (PRD 7.6, 19) -----------------------------------
    "retention.artifact_days": 30,
    "encryption.artifacts": False,
    # --- behaviour ----------------------------------------------------
    "verbosity": "beginner",
    "lab.allow_private": True,
    "robots.respect": True,
    "scope.enforcement": "warn",  # "warn" (PRD default) or "block"
}

VERBOSITY_LEVELS = ("beginner", "normal", "quiet")

#: Folder names that usually mean "this directory is synced to the cloud".
CLOUD_SYNC_MARKERS = (
    "onedrive",
    "dropbox",
    "google drive",
    "googledrive",
    "my drive",
    "icloud",
    "icloud drive",
    "com~apple~clouddocs",
    "box",
    "boxsync",
    "pcloud",
    "mega",
    "nextcloud",
    "owncloud",
    "sync.com",
    "creative cloud files",
    "synologydrive",
    "yandexdisk",
)


def default_data_dir() -> Path:
    """Return the platform-appropriate data directory."""
    override = os.environ.get(ENV_DATA_DIR)
    if override:
        return Path(override).expanduser().resolve()
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_DIR_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_DIR_NAME
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "recon-helper-pro"


def cloud_sync_warning(path: Path) -> str | None:
    """Return a warning string if *path* looks like it lives in a synced folder.

    Recon data contains hostnames, headers and anything redaction missed, so it
    should not be replicated to a third-party cloud by accident (PRD 7.6).
    """
    parts = [p.lower() for p in Path(path).resolve().parts]
    for part in parts:
        for marker in CLOUD_SYNC_MARKERS:
            if marker in part:
                return (
                    f"The data directory {path} appears to sit inside a cloud-synced or "
                    f"backup folder ('{part}'). Recon data can contain hostnames, headers "
                    "and secrets that redaction missed. Consider moving it: set the "
                    f"{ENV_DATA_DIR} environment variable to a local-only path."
                )
    return None


@dataclass(slots=True)
class Paths:
    """Every filesystem location the app uses."""

    data_dir: Path

    @property
    def db_path(self) -> Path:
        return self.data_dir / "rhp.sqlite3"

    @property
    def artifacts_dir(self) -> Path:
        return self.data_dir / "artifacts"

    @property
    def exports_dir(self) -> Path:
        return self.data_dir / "exports"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def cancel_flag(self) -> Path:
        return self.data_dir / "cancel.flag"

    @property
    def state_path(self) -> Path:
        """Small JSON file holding non-secret UI state (e.g. current engagement)."""
        return self.data_dir / "state.json"

    def ensure(self) -> "Paths":
        for directory in (self.data_dir, self.artifacts_dir, self.exports_dir, self.logs_dir):
            directory.mkdir(parents=True, exist_ok=True)
        return self


def resolve_paths(data_dir: str | os.PathLike[str] | None = None) -> Paths:
    """Build a :class:`Paths` for *data_dir* (or the platform default)."""
    root = Path(data_dir).expanduser().resolve() if data_dir else default_data_dir()
    return Paths(data_dir=root)


def coerce(key: str, raw: str) -> Any:
    """Coerce a stored string setting back to the type of its default."""
    default = DEFAULTS.get(key)
    if isinstance(default, bool):
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(default, int):
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default
    return raw


def merged_settings(stored: Mapping[str, str]) -> dict[str, Any]:
    """Overlay *stored* string settings on top of :data:`DEFAULTS`."""
    settings = dict(DEFAULTS)
    for key, value in stored.items():
        if key in DEFAULTS:
            settings[key] = coerce(key, value)
        else:
            settings[key] = value
    return settings
