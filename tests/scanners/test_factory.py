from unittest.mock import Mock

import pytest

from sentinel.exceptions.scanner import UnsupportedLanguageError
from sentinel.plugins.registry import PluginRegistry
from sentinel.scanners.base import BaseScanner
from sentinel.scanners.definition import ScannerDefinition
from sentinel.scanners.factory import ScannerFactory


class DummyScanner(BaseScanner):
    def __init__(self, parsers=None) -> None:
        super().__init__(parsers or [])


def make_registry() -> PluginRegistry:
    plugin = Mock()
    plugin.scanners = {
        "python": ScannerDefinition(
            scanner=DummyScanner,
            parsers=(),
            languages=("python",),
        ),
    }
    return PluginRegistry([plugin])


def test_factory_can_be_created() -> None:
    registry = make_registry()

    factory = ScannerFactory(registry)

    assert factory.registry is registry


def test_create_returns_scanner_from_definition() -> None:
    factory = ScannerFactory(make_registry())

    scanner = factory.create("python")

    assert isinstance(scanner, DummyScanner)


def test_create_is_case_insensitive() -> None:
    factory = ScannerFactory(make_registry())

    scanner = factory.create("PYTHON")

    assert isinstance(scanner, DummyScanner)


def test_create_raises_for_unknown_language() -> None:
    factory = ScannerFactory(make_registry())

    with pytest.raises(
        UnsupportedLanguageError,
        match="Unsupported language: rust",
    ):
        factory.create("rust")


def test_create_passes_definition_parsers_to_scanner() -> None:
    parser = Mock()

    plugin = Mock()
    plugin.scanners = {
        "python": ScannerDefinition(
            scanner=DummyScanner,
            parsers=(parser,),
            languages=("python",),
        ),
    }

    registry = PluginRegistry([plugin])
    factory = ScannerFactory(registry)

    scanner = factory.create("python")

    assert scanner.parsers == [parser]
