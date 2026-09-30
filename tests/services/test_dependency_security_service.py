from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.security_status import SecurityStatus
from sentinel.enums.severity import Severity
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.services.dependency_security_service import (
    DependencySecurityService,
)


def test_summarize_marks_dependency_at_risk() -> None:
    service = DependencySecurityService()

    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-0001",
        aliases=[],
        sources=[],
        summary="Security vulnerability",
        severity=Severity.HIGH,
        cvss=8.0,
        status=VulnerabilityStatus.OPEN,
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="2.0.0",
                    fixed="2.32.0",
                    affected_range="<2.32.0",
                ),
            ],
        ),
        fixed_versions=["2.32.0"],
    )

    summaries = service.summarize([finding])

    assert len(summaries) == 1

    summary = summaries[0]

    assert summary.dependency_name == "requests"
    assert summary.installed_version == "2.31.0"
    assert summary.ecosystem == Ecosystem.PYPI
    assert summary.security_status == SecurityStatus.AT_RISK
    assert summary.finding_count == 1
    assert summary.open_finding_count == 1
    assert summary.recommended_version == "2.32.0"


def test_summarize_selects_highest_recommended_version() -> None:
    service = DependencySecurityService()

    finding_one = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-0001",
        aliases=[],
        sources=[],
        summary="First vulnerability",
        severity=Severity.HIGH,
        cvss=8.0,
        status=VulnerabilityStatus.OPEN,
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="2.0.0",
                    fixed="2.32.0",
                    affected_range="<2.32.0",
                ),
            ],
        ),
        fixed_versions=["2.32.0"],
    )

    finding_two = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-0002",
        aliases=[],
        sources=[],
        summary="Second vulnerability",
        severity=Severity.MEDIUM,
        cvss=5.0,
        status=VulnerabilityStatus.OPEN,
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="2.0.0",
                    fixed="2.33.0",
                    affected_range="<2.33.0",
                ),
            ],
        ),
        fixed_versions=["2.33.0"],
    )

    summaries = service.summarize(
        [
            finding_one,
            finding_two,
        ]
    )

    assert len(summaries) == 1

    summary = summaries[0]

    assert summary.dependency_name == "requests"
    assert summary.finding_count == 2
    assert summary.open_finding_count == 2
    assert summary.security_status == SecurityStatus.AT_RISK

    assert summary.recommended_version == "2.33.0"


def test_summarize_marks_dependency_secure_when_findings_are_resolved() -> (
    None
):
    service = DependencySecurityService()

    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.32.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-0001",
        aliases=[],
        sources=[],
        summary="Fixed vulnerability",
        severity=Severity.HIGH,
        cvss=8.0,
        status=VulnerabilityStatus.RESOLVED,
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="2.0.0",
                    fixed="2.32.0",
                    affected_range="<2.32.0",
                ),
            ],
        ),
        fixed_versions=["2.32.0"],
    )

    summaries = service.summarize([finding])

    assert len(summaries) == 1

    summary = summaries[0]

    assert summary.security_status == SecurityStatus.SECURE
    assert summary.finding_count == 1
    assert summary.open_finding_count == 0
    assert summary.recommended_version is None


def test_summarize_keeps_at_risk_without_recommended_version() -> None:
    service = DependencySecurityService()

    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-0001",
        aliases=[],
        sources=[],
        summary="Vulnerability without remediation",
        severity=Severity.HIGH,
        cvss=8.0,
        status=VulnerabilityStatus.OPEN,
        remediation=None,
        fixed_versions=[],
    )

    summaries = service.summarize([finding])

    summary = summaries[0]

    assert summary.security_status == SecurityStatus.AT_RISK
    assert summary.open_finding_count == 1
    assert summary.recommended_version is None


def test_summarize_groups_findings_by_dependency() -> None:
    service = DependencySecurityService()

    requests_finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-REQUESTS",
        aliases=[],
        sources=[],
        summary="Requests vulnerability",
        severity=Severity.HIGH,
        cvss=8.0,
        status=VulnerabilityStatus.OPEN,
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="2.0.0",
                    fixed="2.32.0",
                    affected_range="<2.32.0",
                ),
            ],
        ),
        fixed_versions=["2.32.0"],
    )

    urllib_finding = VulnerabilityInfo(
        dependency_name="urllib3",
        dependency_version="2.1.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-URLLIB3",
        aliases=[],
        sources=[],
        summary="urllib3 vulnerability",
        severity=Severity.MEDIUM,
        cvss=5.0,
        status=VulnerabilityStatus.OPEN,
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="2.0.0",
                    fixed="2.2.0",
                    affected_range="<2.2.0",
                ),
            ],
        ),
        fixed_versions=["2.2.0"],
    )

    summaries = service.summarize(
        [
            requests_finding,
            urllib_finding,
        ]
    )

    assert len(summaries) == 2

    requests_summary = next(
        summary
        for summary in summaries
        if summary.dependency_name == "requests"
    )

    urllib_summary = next(
        summary
        for summary in summaries
        if summary.dependency_name == "urllib3"
    )

    assert requests_summary.recommended_version == "2.32.0"
    assert urllib_summary.recommended_version == "2.2.0"


def test_recommended_version_resolves_all_open_findings():
    service = DependencySecurityService()

    findings = [
        VulnerabilityInfo(
            dependency_name="requests",
            dependency_version="2.31.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-2024-0001",
            aliases=[],
            sources=[],
            summary="Vulnerability 1",
            severity=Severity.HIGH,
            cvss=None,
            status=VulnerabilityStatus.OPEN,
            remediation=RemediationInfo(
                rules=[
                    RemediationRule(
                        introduced=None,
                        fixed="2.32.0",
                        affected_range=None,
                    ),
                ],
            ),
        ),
        VulnerabilityInfo(
            dependency_name="requests",
            dependency_version="2.31.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-2024-0002",
            aliases=[],
            sources=[],
            summary="Vulnerability 2",
            severity=Severity.MEDIUM,
            cvss=None,
            status=VulnerabilityStatus.OPEN,
            remediation=RemediationInfo(
                rules=[
                    RemediationRule(
                        introduced=None,
                        fixed="2.31.5",
                        affected_range=None,
                    ),
                ],
            ),
        ),
    ]

    summaries = service.summarize(findings)

    assert len(summaries) == 1

    summary = summaries[0]

    assert summary.dependency_name == "requests"
    assert summary.installed_version == "2.31.0"
    assert summary.ecosystem == Ecosystem.PYPI

    assert summary.security_status == SecurityStatus.AT_RISK
    assert summary.finding_count == 2
    assert summary.open_finding_count == 2

    assert summary.recommended_version == "2.32.0"


def test_resolved_findings_are_ignored_for_recommendation():
    service = DependencySecurityService()

    findings = [
        VulnerabilityInfo(
            dependency_name="requests",
            dependency_version="2.31.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-OPEN",
            aliases=[],
            sources=[],
            summary="Open vulnerability",
            severity=Severity.HIGH,
            cvss=None,
            status=VulnerabilityStatus.OPEN,
            remediation=RemediationInfo(
                rules=[
                    RemediationRule(
                        introduced=None,
                        fixed="2.32.0",
                        affected_range=None,
                    ),
                ],
            ),
        ),
        VulnerabilityInfo(
            dependency_name="requests",
            dependency_version="2.31.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-RESOLVED",
            aliases=[],
            sources=[],
            summary="Resolved vulnerability",
            severity=Severity.LOW,
            cvss=None,
            status=VulnerabilityStatus.RESOLVED,
            remediation=RemediationInfo(
                rules=[
                    RemediationRule(
                        introduced=None,
                        fixed="99.0.0",
                        affected_range=None,
                    ),
                ],
            ),
        ),
    ]

    summaries = service.summarize(findings)

    summary = summaries[0]

    assert summary.security_status == SecurityStatus.AT_RISK
    assert summary.open_finding_count == 1
    assert summary.recommended_version == "2.32.0"


def test_secure_dependency_has_no_recommended_version():
    service = DependencySecurityService()

    findings = [
        VulnerabilityInfo(
            dependency_name="requests",
            dependency_version="2.32.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-2024-0001",
            aliases=[],
            sources=[],
            summary="Resolved vulnerability",
            severity=Severity.HIGH,
            cvss=None,
            status=VulnerabilityStatus.RESOLVED,
            remediation=RemediationInfo(
                rules=[
                    RemediationRule(
                        introduced=None,
                        fixed="2.32.0",
                        affected_range=None,
                    ),
                ],
            ),
        ),
    ]

    summaries = service.summarize(findings)

    summary = summaries[0]

    assert summary.security_status == SecurityStatus.SECURE
    assert summary.open_finding_count == 0
    assert summary.recommended_version is None


def test_no_recommended_version_when_no_candidate_resolves_all_findings():
    service = DependencySecurityService()

    findings = [
        VulnerabilityInfo(
            dependency_name="requests",
            dependency_version="2.31.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-1",
            aliases=[],
            sources=[],
            summary="Vulnerability 1",
            severity=Severity.HIGH,
            cvss=None,
            status=VulnerabilityStatus.OPEN,
            remediation=RemediationInfo(
                rules=[
                    RemediationRule(
                        introduced=None,
                        fixed="2.32.0",
                        affected_range=None,
                    ),
                ],
            ),
        ),
        VulnerabilityInfo(
            dependency_name="requests",
            dependency_version="2.31.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-2",
            aliases=[],
            sources=[],
            summary="Vulnerability 2",
            severity=Severity.HIGH,
            cvss=None,
            status=VulnerabilityStatus.OPEN,
            remediation=RemediationInfo(
                rules=[
                    RemediationRule(
                        introduced=None,
                        fixed="2.31.5",
                        affected_range=">=3.0,<3.1",
                    ),
                ],
            ),
        ),
    ]

    summaries = service.summarize(findings)

    summary = summaries[0]

    assert summary.security_status == SecurityStatus.AT_RISK
    assert summary.open_finding_count == 2
    assert summary.recommended_version is None


def test_dependencies_are_grouped_independently():
    service = DependencySecurityService()

    requests_finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-REQUESTS",
        aliases=[],
        sources=[],
        summary="Requests vulnerability",
        severity=Severity.HIGH,
        cvss=None,
        status=VulnerabilityStatus.OPEN,
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced=None,
                    fixed="2.32.0",
                    affected_range=None,
                ),
            ],
        ),
    )

    httpx_finding = VulnerabilityInfo(
        dependency_name="httpx",
        dependency_version="0.28.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-HTTPX",
        aliases=[],
        sources=[],
        summary="HTTPX vulnerability",
        severity=Severity.MEDIUM,
        cvss=None,
        status=VulnerabilityStatus.OPEN,
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced=None,
                    fixed="0.28.1",
                    affected_range=None,
                ),
            ],
        ),
    )

    summaries = service.summarize(
        [
            requests_finding,
            httpx_finding,
        ],
    )

    assert len(summaries) == 2

    requests_summary = next(
        summary
        for summary in summaries
        if summary.dependency_name == "requests"
    )

    httpx_summary = next(
        summary for summary in summaries if summary.dependency_name == "httpx"
    )

    assert requests_summary.recommended_version == "2.32.0"
    assert httpx_summary.recommended_version == "0.28.1"
