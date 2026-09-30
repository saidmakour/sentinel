from dataclasses import dataclass


@dataclass(frozen=True)
class GitForgeConfig:
    """
    Configuration used to authenticate against a Git forge.
    """

    name: str
    host: str
    username: str | None = None
    token: str | None = None
    enabled: bool = True
