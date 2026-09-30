from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GitCredentials:
    username: str | None = None
    password: str | None = None
    token: str | None = None
    private_key: str | None = None
    ssh_key_path: Path | None = None
    passphrase: str | None = None
