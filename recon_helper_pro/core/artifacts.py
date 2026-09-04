"""Storage and retention for raw artifacts (PRD 7.6, 19).

Artifacts are the raw material behind an observation - a robots.txt, a
certificate, WHOIS text. They are redacted before they get here, stored under a
content hash, pruned after the retention window, and can optionally be
encrypted at rest behind a passphrase.

Scope note: the optional encryption implemented here covers the artifact files.
Encrypting the SQLite database itself needs SQLCipher, which is not a pure-pip
dependency on every platform, so it is not enabled in this build - the README
says so plainly rather than implying more protection than exists.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .errors import ConfigError

ENV_PASSPHRASE = "RHP_PASSPHRASE"
SALT_FILENAME = ".artifact-salt"
ENCRYPTED_SUFFIX = ".enc"


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390_000)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


@dataclass(slots=True)
class StoredArtifact:
    path: Path
    sha256: str
    encrypted: bool


class ArtifactStore:
    """Content-addressed artifact files with optional encryption at rest."""

    def __init__(
        self,
        directory: Path,
        *,
        encrypt: bool = False,
        passphrase: str | None = None,
        retention_days: int = 30,
    ) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.retention_days = retention_days
        self.encrypt = encrypt
        self._passphrase = passphrase if passphrase is not None else os.environ.get(ENV_PASSPHRASE)
        if self.encrypt and not self._passphrase:
            raise ConfigError(
                "Encryption at rest is enabled but no passphrase was provided. Set the "
                f"{ENV_PASSPHRASE} environment variable, or turn it off with "
                "'rhp config set encryption.artifacts false'."
            )

    # -- key management ---------------------------------------------------
    def _salt(self) -> bytes:
        path = self.directory / SALT_FILENAME
        if path.exists():
            return path.read_bytes()
        salt = os.urandom(16)
        path.write_bytes(salt)
        return salt

    def _fernet(self):
        from cryptography.fernet import Fernet

        assert self._passphrase is not None
        return Fernet(_derive_key(self._passphrase, self._salt()))

    # -- storage ----------------------------------------------------------
    def store(self, artifact_type: str, content: bytes | str) -> StoredArtifact:
        payload = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        digest = hashlib.sha256(payload).hexdigest()
        safe_type = "".join(char for char in artifact_type if char.isalnum() or char in "-_")
        name = f"{digest[:16]}-{safe_type or 'artifact'}"
        if self.encrypt:
            payload = self._fernet().encrypt(payload)
            name += ENCRYPTED_SUFFIX
        path = self.directory / name
        path.write_bytes(payload)
        return StoredArtifact(path=path, sha256=digest, encrypted=self.encrypt)

    def read(self, path: Path | str) -> bytes:
        location = Path(path)
        payload = location.read_bytes()
        if location.name.endswith(ENCRYPTED_SUFFIX):
            if not self._passphrase:
                raise ConfigError(
                    f"{location.name} is encrypted; set {ENV_PASSPHRASE} to read it."
                )
            return self._fernet().decrypt(payload)
        return payload

    def retention_policy(self) -> str:
        return f"days:{self.retention_days}" if self.retention_days > 0 else "keep"

    def is_expired(self, created_at: str, retention_policy: str) -> bool:
        if not retention_policy.startswith("days:"):
            return False
        try:
            days = int(retention_policy.split(":", 1)[1])
        except ValueError:
            return False
        if days <= 0:
            return False
        try:
            created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - created > timedelta(days=days)

    def delete(self, path: Path | str) -> None:
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            pass
