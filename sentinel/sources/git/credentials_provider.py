from __future__ import annotations

from sentinel.dto.git_credentials import GitCredentials
from sentinel.sources.git.forge_resolver import GitForgeResolver


class GitCredentialsProvider:
    """
    Provides Git credentials for repository operations.
    """

    def __init__(
        self,
        resolver: GitForgeResolver,
    ) -> None:
        self.resolver = resolver

    def get(
        self,
        remote_url: str,
        forge_name: str | None = None,
    ) -> GitCredentials | None:
        """
        Return credentials for the given Git remote URL.

        An explicit forge name takes precedence over automatic
        forge detection from the remote URL.
        """

        forge = self.resolver.resolve(
            remote_url=remote_url,
            forge_name=forge_name,
        )

        if forge is None:
            return None

        if not forge.token:
            return None

        return GitCredentials(
            username=forge.username,
            password=forge.token,
        )
