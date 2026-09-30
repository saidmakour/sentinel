from collections.abc import Callable

from sentinel.config.settings import settings
from sentinel.enums.provider import Provider
from sentinel.providers.base import BaseProvider
from sentinel.providers.ghsa.provider import GHSAProvider
from sentinel.providers.github.provider import GitHubAdvisoryProvider
from sentinel.providers.nvd.provider import NVDProvider
from sentinel.providers.osv.provider import OSVProvider


class ProviderRegistry:
    def __init__(self) -> None:
        self._registry: dict[
            Provider,
            tuple[
                bool,
                Callable[[], BaseProvider],
            ],
        ] = {
            Provider.OSV: (
                settings.osv_enabled,
                OSVProvider,
            ),
            Provider.NVD: (
                settings.nvd_enabled,
                NVDProvider,
            ),
            Provider.GHSA: (
                settings.ghsa_enabled,
                GHSAProvider,
            ),
            Provider.GITHUB_ADVISORY: (
                settings.github_advisory_enabled,
                GitHubAdvisoryProvider,
            ),
        }

    def create_all(self) -> list[BaseProvider]:
        providers: list[BaseProvider] = []

        for enabled, factory in self._registry.values():
            if enabled:
                providers.append(factory())

        return providers

    def create(
        self,
        providers: list[Provider],
    ) -> list[BaseProvider]:

        result: list[BaseProvider] = []

        for provider in providers:
            entry = self._registry.get(provider)

            if not entry:
                continue

            enabled, factory = entry

            if enabled:
                result.append(
                    factory(),
                )

        return result

    def is_available(
        self,
        provider: Provider,
    ) -> bool:
        entry = self._registry.get(
            provider,
        )

        if entry is None:
            return False

        enabled, _ = entry

        return enabled
