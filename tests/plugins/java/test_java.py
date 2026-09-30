from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.java.parsers.gradle_kts_parser import GradleKtsParser
from sentinel.plugins.java.parsers.gradle_parser import GradleParser
from sentinel.plugins.java.parsers.pom_parser import PomParser
from sentinel.plugins.java.plugin import JavaPlugin
from sentinel.plugins.java.scanner import JavaScanner
from sentinel.plugins.java.version_comparator import JavaVersionComparator


def test_java_plugin_can_be_created() -> None:
    plugin = JavaPlugin()

    assert plugin is not None


def test_java_plugin_name() -> None:
    plugin = JavaPlugin()

    assert plugin.name == "java"


def test_java_plugin_languages() -> None:
    plugin = JavaPlugin()

    assert plugin.languages == ("java",)


def test_java_plugin_registers_java_scanner() -> None:
    plugin = JavaPlugin()
    definition = plugin.scanners["java"]

    assert definition.scanner is JavaScanner


def test_java_plugin_languages_match_scanners() -> None:
    plugin = JavaPlugin()

    assert set(plugin.languages) == set(plugin.scanners)


def test_java_plugin_registers_maven_comparator() -> None:
    plugin = JavaPlugin()

    assert isinstance(
        plugin.comparators[Ecosystem.MAVEN],
        JavaVersionComparator,
    )


def test_java_plugin_provides_java_scanner_definition() -> None:
    plugin = JavaPlugin()

    definition = plugin.scanners["java"]

    assert definition.scanner is JavaScanner
    assert len(definition.parsers) == 3


def test_java_plugin_provides_expected_parsers() -> None:
    plugin = JavaPlugin()

    parser_types = {type(parser) for parser in plugin.scanners["java"].parsers}

    assert parser_types == {
        PomParser,
        GradleParser,
        GradleKtsParser,
    }
