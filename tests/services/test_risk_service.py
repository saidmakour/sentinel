from sentinel.enums.severity import Severity
from sentinel.services.risk_service import RiskService


def test_risk_service_can_be_created() -> None:
    service = RiskService()

    assert service is not None


def test_calculate_returns_all_severity_counts() -> None:
    service = RiskService()

    result = service.calculate(
        {
            Severity.CRITICAL.value: 2,
            Severity.HIGH.value: 3,
            Severity.MEDIUM.value: 4,
            Severity.LOW.value: 5,
        }
    )

    assert result == (
        2,
        3,
        4,
        5,
        48,
    )


def test_calculate_applies_correct_weights() -> None:
    service = RiskService()

    result = service.calculate(
        {
            Severity.CRITICAL.value: 1,
            Severity.HIGH.value: 1,
            Severity.MEDIUM.value: 1,
            Severity.LOW.value: 1,
        }
    )

    # 1 * 10 + 1 * 5 + 1 * 2 + 1 * 1 = 18
    assert result == (
        1,
        1,
        1,
        1,
        18,
    )


def test_calculate_returns_zero_for_empty_counts() -> None:
    service = RiskService()

    result = service.calculate({})

    assert result == (
        0,
        0,
        0,
        0,
        0,
    )


def test_calculate_defaults_missing_severities_to_zero() -> None:
    service = RiskService()

    result = service.calculate(
        {
            Severity.CRITICAL.value: 2,
            Severity.MEDIUM.value: 3,
        }
    )

    assert result == (
        2,
        0,
        3,
        0,
        26,
    )


def test_calculate_ignores_unknown_severities() -> None:
    service = RiskService()

    result = service.calculate(
        {
            Severity.HIGH.value: 2,
            "UNKNOWN_CUSTOM_SEVERITY": 100,
        }
    )

    assert result == (
        0,
        2,
        0,
        0,
        10,
    )


def test_calculate_handles_zero_counts() -> None:
    service = RiskService()

    result = service.calculate(
        {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
        }
    )

    assert result == (
        0,
        0,
        0,
        0,
        0,
    )
