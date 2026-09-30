from enum import IntEnum

from sentinel.enums.dependency_source_priority import DependencySourcePriority


def test_dependency_source_priority_is_int_enum():
    assert issubclass(DependencySourcePriority, IntEnum)


def test_dependency_source_priority_values():
    assert DependencySourcePriority.LOCK_FILE == 10
    assert DependencySourcePriority.MANIFEST == 20
    assert DependencySourcePriority.METADATA == 30


def test_dependency_source_priority_order():
    assert (
        DependencySourcePriority.LOCK_FILE < DependencySourcePriority.MANIFEST
    )
    assert (
        DependencySourcePriority.MANIFEST < DependencySourcePriority.METADATA
    )
