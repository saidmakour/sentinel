from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.go.plugin import GoPlugin
from sentinel.plugins.registry import PluginRegistry


class TestGoPluginRegistry:
    def test_registers_go_scanner(self) -> None:
        registry = PluginRegistry(
            plugins=[GoPlugin()],
        )

        assert "go" in registry.scanners
        assert registry.scanners["go"].languages == ("go",)

    def test_registers_go_comparator(self) -> None:
        registry = PluginRegistry(
            plugins=[GoPlugin()],
        )

        assert Ecosystem.GOLANG in registry.comparators
