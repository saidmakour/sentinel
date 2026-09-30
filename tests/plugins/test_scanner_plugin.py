from sentinel.plugins.scanner_plugin import ScannerPlugin
from sentinel.scanners.registry import ScannerRegistry
from sentinel.services.version_comparators.registry import (
    VersionComparatorRegistry,
)


class DumnyPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "test"

    def register_scanners(
        self,
        registry: ScannerRegistry,
    ) -> None:
        pass

    def register_version_comparators(
        self,
        registry: VersionComparatorRegistry,
    ) -> None:
        pass


def test_plugin_can_be_created() -> None:
    plugin = DumnyPlugin()

    assert plugin is not None
    assert plugin.name == "test"


def test_plugin_requires_name() -> None:
    assert isinstance(DumnyPlugin.name, property)


def test_plugin_defines_scanner_registration_contract() -> None:
    assert callable(DumnyPlugin.register_scanners)


def test_plugin_defines_version_comparator_registration_contract() -> None:
    assert callable(DumnyPlugin.register_version_comparators)
