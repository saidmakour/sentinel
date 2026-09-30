from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.defaults import create_plugin_registry
from sentinel.plugins.go.scanner import GoScanner
from sentinel.plugins.java.scanner import JavaScanner
from sentinel.plugins.java.version_comparator import JavaVersionComparator
from sentinel.plugins.node.scanner import NodeScanner
from sentinel.plugins.node.version_comparator import NPMVersionComparator
from sentinel.plugins.php.scanner import PHPScanner
from sentinel.plugins.php.version_comparator import PHPVersionComparator
from sentinel.plugins.python.scanner import PythonScanner
from sentinel.plugins.python.version_comparator import PyPIVersionComparator
from sentinel.plugins.ruby.scanner import RubyScanner


def test_create_plugin_registry_registers_all_scanners() -> None:
    registry = create_plugin_registry()

    assert registry.scanners["python"].scanner is PythonScanner
    assert registry.scanners["node"].scanner is NodeScanner
    assert registry.scanners["php"].scanner is PHPScanner
    assert registry.scanners["java"].scanner is JavaScanner
    assert registry.scanners["go"].scanner is GoScanner
    assert registry.scanners["ruby"].scanner is RubyScanner


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
