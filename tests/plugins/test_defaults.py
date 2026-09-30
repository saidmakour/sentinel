from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.defaults import create_plugin_registry
from sentinel.plugins.go.version_comparator import GoVersionComparator
from sentinel.plugins.java.version_comparator import JavaVersionComparator
from sentinel.plugins.node.scanner import NodeScanner
from sentinel.plugins.node.version_comparator import NPMVersionComparator
from sentinel.plugins.php.version_comparator import PHPVersionComparator
from sentinel.plugins.python.version_comparator import PyPIVersionComparator
from sentinel.plugins.ruby.version_comparator import RubyVersionComparator


def test_create_plugin_registry_registers_node_aliases() -> None:
    registry = create_plugin_registry()

    assert registry.scanners["node"].scanner is NodeScanner
    assert registry.scanners["javascript"].scanner is NodeScanner
    assert registry.scanners["typescript"].scanner is NodeScanner


def test_create_plugin_registry_registers_all_comparators() -> None:
    registry = create_plugin_registry()

    assert isinstance(
        registry.comparators[Ecosystem.PYPI],
        PyPIVersionComparator,
    )
    assert isinstance(
        registry.comparators[Ecosystem.NPM],
        NPMVersionComparator,
    )
    assert isinstance(
        registry.comparators[Ecosystem.COMPOSER],
        PHPVersionComparator,
    )
    assert isinstance(
        registry.comparators[Ecosystem.MAVEN],
        JavaVersionComparator,
    )
    assert isinstance(
        registry.comparators[Ecosystem.GOLANG],
        GoVersionComparator,
    )
    assert isinstance(
        registry.comparators[Ecosystem.RUBYGEMS],
        RubyVersionComparator,
    )


def test_create_plugin_registry_registers_all_plugins() -> None:
    registry = create_plugin_registry()

    assert {plugin.name for plugin in registry.plugins} == {
        "python",
        "node",
        "php",
        "java",
        "go",
        "ruby",
    }
