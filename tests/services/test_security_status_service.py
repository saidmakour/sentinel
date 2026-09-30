from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.security_status import SecurityStatus
from sentinel.enums.severity import Severity
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.services.security_status_service import SecurityStatusService


def create_finding(
    *,
    severity: Severity = Severity.MEDIUM,
    status: VulnerabilityStatus = VulnerabilityStatus.OPEN,
    known_exploited: bool = False,
    vulncheck_known_exploited: bool = False,
) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-0001",
        aliases=[],
        sources=[],
        summary="Test vulnerability",
        severity=severity,
        cvss=5.0,
        status=status,
        known_exploited=known_exploited,
        vulncheck_known_exploited=vulncheck_known_exploited,
    )


def test_no_findings_is_secure() -> None:
    service = SecurityStatusService()

    result = service.calculate([])

    assert result == SecurityStatus.SECURE


def test_resolved_finding_is_secure() -> None:
    service = SecurityStatusService()

    finding = create_finding(
        status=VulnerabilityStatus.RESOLVED,
    )

    result = service.calculate([finding])

    assert result == SecurityStatus.SECURE


def test_open_medium_is_at_risk() -> None:
    service = SecurityStatusService()

    finding = create_finding(
        severity=Severity.MEDIUM,
    )

    result = service.calculate([finding])

    assert result == SecurityStatus.AT_RISK


def test_open_high_is_at_risk() -> None:
    service = SecurityStatusService()

    finding = create_finding(
        severity=Severity.HIGH,
    )

    result = service.calculate([finding])

    assert result == SecurityStatus.AT_RISK


def test_open_critical_is_critical() -> None:
    service = SecurityStatusService()

    finding = create_finding(
        severity=Severity.CRITICAL,
    )

    result = service.calculate([finding])

    assert result == SecurityStatus.CRITICAL


def test_known_exploited_is_critical() -> None:
    service = SecurityStatusService()

    finding = create_finding(
        severity=Severity.HIGH,
        known_exploited=True,
    )

    result = service.calculate([finding])

    assert result == SecurityStatus.CRITICAL


def test_unknown_finding_returns_unknown() -> None:
    service = SecurityStatusService()

    finding = create_finding(
        status=VulnerabilityStatus.UNKNOWN,
    )

    result = service.calculate([finding])

    assert result == SecurityStatus.UNKNOWN


def test_unknown_does_not_hide_open_high() -> None:
    service = SecurityStatusService()

    unknown = create_finding(
        status=VulnerabilityStatus.UNKNOWN,
    )

    high = create_finding(
        severity=Severity.HIGH,
        status=VulnerabilityStatus.OPEN,
    )

    result = service.calculate(
        [
            unknown,
            high,
        ],
    )

    assert result == SecurityStatus.AT_RISK


def test_vulncheck_kev_is_critical() -> None:
    service = SecurityStatusService()

    finding = create_finding(
        severity=Severity.HIGH,
        vulncheck_known_exploited=True,
    )

    result = service.calculate([finding])

    assert result == SecurityStatus.CRITICAL


def test_calculate_returns_critical_for_vulncheck_kev() -> None:
    finding = create_finding(
        status=VulnerabilityStatus.OPEN,
    )
    finding.vulncheck_known_exploited = True

    service = SecurityStatusService()

    result = service.calculate(
        [finding],
    )

    assert result == SecurityStatus.CRITICAL
