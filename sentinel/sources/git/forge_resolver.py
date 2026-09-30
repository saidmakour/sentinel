from __future__ import annotations

from sentinel.config.settings import Settings
from sentinel.dto.git_forge_config import GitForgeConfig
from sentinel.sources.git.forge_registry import GitForgeRegistry
from sentinel.sources.git.remote_parser import GitRemoteParser


class GitForgeResolver:
    """
    Resolves the Git forge to use for a repository.
    """

    def __init__(
        self,
        registry: GitForgeRegistry,
        settings: Settings | None = None,
    ) -> None:
        self.registry = registry
        self.settings = settings or Settings()

    def resolve(
        self,
        remote_url: str,
        forge_name: str | None = None,
    ) -> GitForgeConfig | None:
        """
        Resolve the Git forge.

        Priority:
        1. Explicit forge name.
        2. Configured default forge.
        3. Automatic detection from remote URL.
        """

        selected_forge = forge_name or self.settings.git_forge

        if selected_forge:
            return self.registry.get_by_name(
                selected_forge,
            )

        host = GitRemoteParser.extract_host(
            remote_url,
        )

        if host is None:
            return None

        return self.registry.get_by_host(
            host,
        )
