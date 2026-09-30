from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.php.parsers.composer_json_parser import (
    ComposerJsonParser,
)
from sentinel.plugins.php.parsers.composer_lock_parser import (
    ComposerLockParser,
)
from sentinel.plugins.php.plugin import PHPPlugin
from sentinel.plugins.php.scanner import PHPScanner
from sentinel.plugins.php.version_comparator import PHPVersionComparator


def test_php_plugin_can_be_created() -> None:
    plugin = PHPPlugin()

    assert plugin is not None


def test_php_plugin_name() -> None:
    plugin = PHPPlugin()

    assert plugin.name == "php"


def test_php_plugin_languages() -> None:
    plugin = PHPPlugin()

    assert plugin.languages == ("php",)


def test_php_plugin_registers_php_scanner() -> None:
    plugin = PHPPlugin()
    definition = plugin.scanners["php"]
    assert definition.scanner is PHPScanner


def test_php_plugin_registers_pypi_comparator() -> None:
    plugin = PHPPlugin()

    assert isinstance(
        plugin.comparators[Ecosystem.COMPOSER],
        PHPVersionComparator,
    )


def test_php_plugin_languages_match_scanners() -> None:
    plugin = PHPPlugin()

    assert set(plugin.languages) == set(plugin.scanners)


def test_php_plugin_provides_php_scanner_definition() -> None:
    plugin = PHPPlugin()

    definition = plugin.scanners["php"]

    assert definition.scanner is PHPScanner

    assert len(definition.parsers) == 2


def test_php_plugin_provides_expected_parsers() -> None:
    plugin = PHPPlugin()

    parser_types = {type(parser) for parser in plugin.scanners["php"].parsers}

    assert parser_types == {
        ComposerLockParser,
        ComposerJsonParser,
    }
