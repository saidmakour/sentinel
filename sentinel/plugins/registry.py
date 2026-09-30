from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.base import SentinelPlugin
from sentinel.scanners.definition import ScannerDefinition
from sentinel.services.version_comparators.base import BaseVersionComparator


class PluginRegistry:
    def __init__(
        self,
        plugins: list[SentinelPlugin] | None = None,
    ) -> None:
        self._plugins: list[SentinelPlugin] = []

        for plugin in plugins or []:
            self.register(plugin)

    def register(
        self,
        plugin: SentinelPlugin,
    ) -> None:
        if any(existing.name == plugin.name for existing in self._plugins):
            raise ValueError(f"Plugin already registered: {plugin.name}")

        self._plugins.append(plugin)

    @property
    def plugins(self) -> tuple[SentinelPlugin, ...]:
        return tuple(self._plugins)

    @property
    def scanners(self) -> dict[str, ScannerDefinition]:
        scanners: dict[str, ScannerDefinition] = {}

        for plugin in self._plugins:
            for definition in plugin.scanners.values():
                for language in definition.languages:
                    key = language.lower()

                    if key in scanners:
                        raise ValueError(
                            "Scanner already registered for language: "
                            f"{language}"
                        )

                    scanners[key] = definition

        return scanners

    @property
    def comparators(
        self,
    ) -> dict[Ecosystem, BaseVersionComparator]:
        comparators: dict[
            Ecosystem,
            BaseVersionComparator,
        ] = {}

        for plugin in self._plugins:
            for ecosystem, comparator in plugin.comparators.items():
                if ecosystem in comparators:
                    raise ValueError(
                        "Comparator already registered for ecosystem: "
                        f"{ecosystem}"
                    )

                comparators[ecosystem] = comparator

        return comparators
