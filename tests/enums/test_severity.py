from enum import StrEnum

from sentinel.enums.severity import Severity


def test_severity_is_str_enum():
    assert issubclass(Severity, StrEnum)


def test_severity_values():
    assert Severity.CRITICAL.value == "CRITICAL"
    assert Severity.HIGH.value == "HIGH"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.LOW.value == "LOW"
    assert Severity.UNKNOWN.value == "UNKNOWN"


def test_severity_string_behavior():
    assert str(Severity.CRITICAL) == "CRITICAL"
    assert str(Severity.HIGH) == "HIGH"
    assert str(Severity.MEDIUM) == "MEDIUM"
    assert str(Severity.LOW) == "LOW"
    assert str(Severity.UNKNOWN) == "UNKNOWN"
