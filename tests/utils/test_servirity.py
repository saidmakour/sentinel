from sentinel.enums.severity import Severity
from sentinel.utils.severity import severity_from_cvss


def test_none_returns_unknown() -> None:
    assert severity_from_cvss(None) == Severity.UNKNOWN


def test_low() -> None:
    assert severity_from_cvss(0.1) == Severity.LOW
    assert severity_from_cvss(3.9) == Severity.LOW


def test_medium() -> None:
    assert severity_from_cvss(4.0) == Severity.MEDIUM
    assert severity_from_cvss(6.9) == Severity.MEDIUM


def test_high() -> None:
    assert severity_from_cvss(7.0) == Severity.HIGH
    assert severity_from_cvss(8.9) == Severity.HIGH


def test_critical() -> None:
    assert severity_from_cvss(9.0) == Severity.CRITICAL
    assert severity_from_cvss(10.0) == Severity.CRITICAL
