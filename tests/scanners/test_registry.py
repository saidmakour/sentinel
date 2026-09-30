from unittest.mock import MagicMock

from sentinel.scanners.base import BaseScanner
from sentinel.scanners.registry import ScannerRegistry


class DummyScanner(BaseScanner):
    pass


def test_registry_can_be_created() -> None:
    registry = ScannerRegistry()

    assert registry is not None


def test_register_scanner() -> None:
    registry = ScannerRegistry()

    registry.register("python", DummyScanner)

    assert registry.get("python") is DummyScanner


def test_get_returns_none_for_unknown_language() -> None:
    registry = ScannerRegistry()

    assert registry.get("python") is None


def test_supports_returns_true_for_registered_language() -> None:
    registry = ScannerRegistry()

    registry.register("python", DummyScanner)

    assert registry.supports("python")


def test_supports_returns_false_for_unknown_language() -> None:
    registry = ScannerRegistry()

    assert not registry.supports("python")


def test_language_lookup_is_case_insensitive() -> None:
    registry = ScannerRegistry()

    registry.register("Python", DummyScanner)

    assert registry.get("python") is DummyScanner
    assert registry.get("PYTHON") is DummyScanner
    assert registry.supports("PyThOn")


def test_custom_scanners_can_be_provided() -> None:
    scanner = MagicMock(spec=BaseScanner)

    registry = ScannerRegistry(
        scanners={
            "python": scanner,
        },
    )

    assert registry.get("python") is scanner


def test_register_replaces_existing_scanner() -> None:
    first_scanner = MagicMock(spec=BaseScanner)
    second_scanner = MagicMock(spec=BaseScanner)

    registry = ScannerRegistry(
        scanners={
            "python": first_scanner,
        },
    )

    registry.register("python", second_scanner)

    assert registry.get("python") is second_scanner
