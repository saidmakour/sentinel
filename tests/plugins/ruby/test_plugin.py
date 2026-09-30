from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.ruby.plugin import RubyPlugin
from sentinel.plugins.ruby.scanner import RubyScanner
from sentinel.plugins.ruby.version_comparator import RubyVersionComparator


def test_plugin_name() -> None:
    plugin = RubyPlugin()

    assert plugin.name == "ruby"


def test_plugin_languages() -> None:
    plugin = RubyPlugin()

    assert plugin.languages == ("ruby",)


def test_plugin_scanners() -> None:
    plugin = RubyPlugin()

    scanners = plugin.scanners

    assert "ruby" in scanners

    definition = scanners["ruby"]

    assert definition.scanner is RubyScanner
    assert definition.languages == ("ruby",)


def test_plugin_scanner_parsers() -> None:
    plugin = RubyPlugin()

    definition = plugin.scanners["ruby"]

    assert len(definition.parsers) == 2
    assert definition.parsers[0].__class__.__name__ == "GemfileLockParser"
    assert definition.parsers[1].__class__.__name__ == "GemfileParser"


def test_plugin_comparators() -> None:
    plugin = RubyPlugin()

    comparators = plugin.comparators

    assert Ecosystem.RUBYGEMS in comparators
    assert isinstance(
        comparators[Ecosystem.RUBYGEMS],
        RubyVersionComparator,
    )
