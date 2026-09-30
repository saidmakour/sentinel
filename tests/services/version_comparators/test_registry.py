from unittest.mock import Mock

from sentinel.enums.ecosystem import Ecosystem
from sentinel.services.version_comparators.base import BaseVersionComparator
from sentinel.services.version_comparators.registry import (
    VersionComparatorRegistry,
)


def make_comparator() -> BaseVersionComparator:
    return Mock(spec=BaseVersionComparator)


def test_register_and_get_comparator() -> None:
    registry = VersionComparatorRegistry()
    comparator = make_comparator()

    registry.register(
        Ecosystem.PYPI,
        comparator,
    )

    assert registry.get(Ecosystem.PYPI) is comparator


def test_get_returns_none_for_unknown_ecosystem() -> None:
    registry = VersionComparatorRegistry()

    assert registry.get(Ecosystem.GOLANG) is None


def test_supports_returns_true_for_registered_ecosystem() -> None:
    registry = VersionComparatorRegistry()
    comparator = make_comparator()

    registry.register(
        Ecosystem.NPM,
        comparator,
    )

    assert registry.supports(Ecosystem.NPM) is True


def test_supports_returns_false_for_unregistered_ecosystem() -> None:
    registry = VersionComparatorRegistry()

    assert registry.supports(Ecosystem.GOLANG) is False


def test_register_replaces_existing_comparator() -> None:
    registry = VersionComparatorRegistry()

    first = make_comparator()
    second = make_comparator()

    registry.register(
        Ecosystem.MAVEN,
        first,
    )

    registry.register(
        Ecosystem.MAVEN,
        second,
    )

    assert registry.get(Ecosystem.MAVEN) is second


def test_registry_can_be_initialized_with_comparators() -> None:
    comparator = make_comparator()

    registry = VersionComparatorRegistry(
        {
            Ecosystem.COMPOSER: comparator,
        }
    )

    assert registry.get(Ecosystem.COMPOSER) is comparator
    assert registry.supports(Ecosystem.COMPOSER) is True


def test_comparators_returns_registered_comparators() -> None:
    registry = VersionComparatorRegistry()
    comparator = make_comparator()

    registry.register(
        Ecosystem.PYPI,
        comparator,
    )

    assert registry.comparators[Ecosystem.PYPI] is comparator


def test_comparators_returns_a_copy() -> None:
    registry = VersionComparatorRegistry()
    comparator = make_comparator()

    registry.register(
        Ecosystem.PYPI,
        comparator,
    )

    comparators = registry.comparators

    comparators.clear()

    assert registry.get(Ecosystem.PYPI) is comparator


def test_empty_registry_has_no_comparators() -> None:
    registry = VersionComparatorRegistry()

    assert registry.comparators == {}
