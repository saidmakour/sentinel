from __future__ import annotations

from sentinel.config.settings import Settings
from sentinel.dto.git_forge_config import GitForgeConfig
from sentinel.sources.git.forge_registry import GitForgeRegistry
from sentinel.sources.git.remote_parser import GitRemoteParser


class GitForgeRegistryFactory:
    """
    Creates a Git forge registry from application settings.
    """

    @staticmethod
    def create(
        settings: Settings,
    ) -> GitForgeRegistry:
        forges: list[GitForgeConfig] = []

        if settings.gitlab_url:
            host = GitRemoteParser.extract_host(
                settings.gitlab_url,
            )

            if host:
                forges.append(
                    GitForgeConfig(
                        name="gitlab",
                        host=host,
                        token=settings.gitlab_token or None,
                    ),
                )

        return GitForgeRegistry(
            forges=forges,
        )

    @staticmethod
    def _extract_host(
        remote_url: str,
    ) -> str | None:
        value = remote_url.strip()

        if not value:
            return None

        if "://" in value:
            from urllib.parse import urlparse

            parsed = urlparse(
                value,
            )

            return parsed.hostname.lower() if parsed.hostname else None

        if ":" not in value:
            return None

        host = value.split(
            ":",
            1,
        )[0]

        if "@" in host:
            host = host.split(
                "@",
                1,
            )[1]

        host = host.strip()

        return host.lower() or None
