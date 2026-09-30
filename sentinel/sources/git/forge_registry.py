from __future__ import annotations

from sentinel.dto.git_forge_config import GitForgeConfig


class GitForgeRegistry:
    """
    Registry of configured Git forges.
    """

    def __init__(
        self,
        forges: list[GitForgeConfig] | None = None,
    ) -> None:
        self.forges = forges or []

    def get_by_name(
        self,
        name: str,
    ) -> GitForgeConfig | None:
        normalized_name = name.lower().strip()

        for forge in self.forges:
            if forge.enabled and forge.name.lower().strip() == normalized_name:
                return forge

        return None

    def get_by_host(
        self,
        host: str,
    ) -> GitForgeConfig | None:
        normalized_host = host.lower().strip()

        for forge in self.forges:
            if forge.enabled and forge.host.lower().strip() == normalized_host:
                return forge

        return None
