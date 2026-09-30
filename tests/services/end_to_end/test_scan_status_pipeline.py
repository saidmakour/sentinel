from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.services.vulnerability_status_service import (
    VulnerabilityStatusService,
)


def create_vulnerability(
    *,
    version: str,
    remediation: RemediationInfo | None,
) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        dependency_name="requests",
        dependency_version=version,
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-48998",
        aliases=[],
        sources=[Provider.NVD],
        summary="Test vulnerability",
        severity=Severity.HIGH,
        cvss=7.5,
        remediation=remediation,
    )


def test_vulnerability_status_unknown_without_fix():

    finding = create_vulnerability(version="2.13.0", remediation=None)

    result = VulnerabilityStatusService().apply(
        finding,
    )

    assert result.status == VulnerabilityStatus.UNKNOWN


def test_vulnerability_status_open_when_fix_is_newer():

    finding = create_vulnerability(
        version="2.13.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    fixed="2.14.0",
                    affected_range="<2.14.0",
                ),
            ],
        ),
    )

    result = VulnerabilityStatusService().apply(
        finding,
    )

    assert result.status == VulnerabilityStatus.OPEN


def test_vulnerability_status_resolved_when_version_is_fixed():

    finding = create_vulnerability(
        version="2.14.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    fixed="2.14.0",
                    affected_range="<2.14.0",
                ),
            ],
        ),
    )

    result = VulnerabilityStatusService().apply(
        finding,
    )

    assert result.status == VulnerabilityStatus.RESOLVED
