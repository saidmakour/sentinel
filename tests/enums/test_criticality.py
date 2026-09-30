from enum import IntEnum

from sentinel.enums.criticality import Criticality


def test_criticality_is_int_enum():
    assert issubclass(Criticality, IntEnum)


def test_criticality_values():
    # Remplace selon les vraies valeurs de ton enum
    assert Criticality.LOW.value == 1
    assert Criticality.MEDIUM.value == 2
    assert Criticality.HIGH.value == 3
