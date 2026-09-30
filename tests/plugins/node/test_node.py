from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.node.plugin import NodePlugin
from sentinel.plugins.node.scanner import NodeScanner
from sentinel.plugins.node.version_comparator import NPMVersionComparator


def test_node_plugin_can_be_created() -> None:
    plugin = NodePlugin()

    assert plugin is not None


def test_node_plugin_name() -> None:
    plugin = NodePlugin()

    assert plugin.name == "node"


def test_node_plugin_languages() -> None:
    plugin = NodePlugin()

    assert plugin.languages == (
        "node",
        "javascript",
        "typescript",
    )


def test_node_plugin_registers_node_scanner() -> None:
    plugin = NodePlugin()
    definition = plugin.scanners["node"]
    assert definition.scanner is NodeScanner


def test_node_plugin_registers_npm_comparator() -> None:
    plugin = NodePlugin()

    assert isinstance(
        plugin.comparators[Ecosystem.NPM],
        NPMVersionComparator,
    )


def test_node_plugin_provides_node_scanner_definition() -> None:
    plugin = NodePlugin()

    definition = plugin.scanners["node"]

    assert definition.scanner is NodeScanner
    assert len(definition.parsers) == 4


def test_node_plugin_declares_language_aliases() -> None:
    plugin = NodePlugin()

    definition = plugin.scanners["node"]

    assert definition.languages == (
        "node",
        "javascript",
        "typescript",
    )


def test_node_plugin_defines_one_scanner_definition() -> None:
    plugin = NodePlugin()

    assert len(plugin.scanners) == 1
    assert "node" in plugin.scanners
