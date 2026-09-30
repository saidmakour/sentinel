from sentinel.enums.ecosystem import Ecosystem
from sentinel.plugins.python.parsers.pipfile_lock_parser import (
    PipfileLockParser,
)
from sentinel.plugins.python.parsers.pipfile_parser import PipfileParser
from sentinel.plugins.python.parsers.poetry_lock_parser import PoetryLockParser
from sentinel.plugins.python.parsers.pyproject_parser import PyProjectParser
from sentinel.plugins.python.parsers.requirements_parser import (
    RequirementsParser,
)
from sentinel.plugins.python.parsers.uv_lock_parser import UVLockParser
from sentinel.plugins.python.plugin import PythonPlugin
from sentinel.plugins.python.scanner import PythonScanner
from sentinel.plugins.python.version_comparator import PyPIVersionComparator


def test_python_plugin_can_be_created() -> None:
    plugin = PythonPlugin()

    assert plugin is not None


def test_python_plugin_name() -> None:
    plugin = PythonPlugin()

    assert plugin.name == "python"


def test_python_plugin_languages() -> None:
    plugin = PythonPlugin()

    assert plugin.languages == ("python",)


def test_python_plugin_registers_python_scanner() -> None:
    plugin = PythonPlugin()

    definition = plugin.scanners["python"]

    assert definition.scanner is PythonScanner


def test_python_plugin_registers_pypi_comparator() -> None:
    plugin = PythonPlugin()

    assert isinstance(
        plugin.comparators[Ecosystem.PYPI],
        PyPIVersionComparator,
    )


def test_python_plugin_languages_match_scanners() -> None:
    plugin = PythonPlugin()

    assert set(plugin.languages) == set(plugin.scanners)


def test_python_plugin_provides_python_scanner_definition() -> None:
    plugin = PythonPlugin()

    definition = plugin.scanners["python"]

    assert definition.scanner is PythonScanner
    assert len(definition.parsers) == 6


def test_python_plugin_provides_expected_parsers() -> None:
    plugin = PythonPlugin()

    parser_types = {
        type(parser) for parser in plugin.scanners["python"].parsers
    }

    assert parser_types == {
        UVLockParser,
        PoetryLockParser,
        PipfileLockParser,
        RequirementsParser,
        PipfileParser,
        PyProjectParser,
    }
