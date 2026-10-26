from datetime import date
from datetime import datetime

from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.scan_report import ScanReport
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.scan_status import ScanStatus
from sentinel.enums.security_status import SecurityStatus
from sentinel.enums.severity import Severity
from sentinel.enums.source_type import SourceType
from sentinel.reports.markdown import MarkdownReportRenderer


def test_render_empty_report() -> None:
    report = ScanReport(
        scan_id=1,
        repository_id=1,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.SECURE,
        started_at=datetime(
            2026,
            1,
            1,
        ),
        finished_at=None,
        duration_seconds=None,
        source_type=SourceType.GIT,
        source_reference="https://github.com/test/project.git",
        source_branch="main",
        source_commit="abc123",
        findings=[],
        dependency_summaries=[],
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        risk_score=0,
        error_message="",
    )

    renderer = MarkdownReportRenderer()

    output = renderer.render(report)

    assert "# Sentinel Scan Report" in output
    assert "No vulnerabilities found." in output


def test_render_report_with_finding() -> None:

    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        identifier="CVE-2024-12345",
        ecosystem=Ecosystem.PYPI,
        aliases=["CVE-2024-12345"],
        severity=Severity.HIGH,
        sources=[Provider.NVD],
        cvss=8.1,
        summary="A vulnerability in requests package.",
        known_exploited=False,
        epss_score=0.42,
        epss_percentile=0.75,
    )

    report = ScanReport(
        scan_id=1,
        repository_id=1,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.SECURE,
        started_at=datetime.now(),
        finished_at=datetime.now(),
        duration_seconds=120,
        source_type=SourceType.GIT,
        source_reference="https://github.com/test/project.git",
        source_branch="main",
        source_commit="abc123",
        findings=[finding],
        dependency_summaries=[],
        critical_count=0,
        high_count=1,
        medium_count=0,
        low_count=0,
        risk_score=8,
        error_message="",
    )

    renderer = MarkdownReportRenderer()

    output = renderer.render(
        report,
    )

    assert "# Sentinel Vulnerability Report" in output

    assert "## Scan Information" in output
    assert "Engine Version: 1.0-dev" in output
    assert "Status: success" in output

    assert "## Source" in output
    assert "git" in output
    assert "https://github.com/test/project.git" in output
    assert "main" in output
    assert "abc123" in output

    assert "Error: N/A" in output

    assert "## Executive Summary" in output

    assert "## Vulnerabilities" in output
    assert "requests" in output
    assert "2.31.0" in output
    assert "CVE-2024-12345" in output
    assert "HIGH" in output
    assert "8.1" in output


def test_render_report_with_enriched_finding() -> None:

    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-12345",
        aliases=["CVE-2024-12345"],
        severity=Severity.HIGH,
        sources=[
            Provider.NVD,
        ],
        cvss=8.1,
        summary=("A vulnerability exists in requests package."),
        known_exploited=True,
        epss_score=0.42,
        epss_percentile=0.75,
        kev_date_added=date(2026, 1, 15),
        kev_vendor="Example Vendor",
        kev_product="Example Product",
        kev_known_ransomware="Known",
    )

    report = ScanReport(
        scan_id=1,
        repository_id=1,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.AT_RISK,
        started_at=datetime(2026, 7, 17, 10, 0, 0),
        finished_at=datetime(2026, 7, 17, 10, 2, 0),
        duration_seconds=120,
        source_type=SourceType.GIT,
        source_reference="https://github.com/test/project.git",
        source_branch="main",
        source_commit="abc123",
        findings=[
            finding,
        ],
        dependency_summaries=[],
        critical_count=0,
        high_count=1,
        medium_count=0,
        low_count=0,
        risk_score=8,
        error_message="Message d'erreur",
    )

    renderer = MarkdownReportRenderer()

    output = renderer.render(
        report,
    )
    print(output)
    assert "# Sentinel Vulnerability Report" in output

    assert "Message d'erreur" in output

    assert "## Executive Summary" in output
    assert f"Security Status: {SecurityStatus.AT_RISK.value}" in output
    assert "Risk Score: 8" in output
    assert "High Findings: 1" in output

    assert "## Vulnerabilities" in output

    assert "Dependency" in output
    assert "Version" in output
    assert "Identifier" in output
    assert "Severity" in output
    assert "CVSS" in output
    assert "KEV" in output
    assert "EPSS" in output
    assert "Sources" in output

    assert "requests" in output
    assert "2.31.0" in output
    assert "CVE-2024-12345" in output
    assert "HIGH" in output
    assert "8.1" in output
    assert "Yes" in output
    assert "0.42" in output
    assert "NVD" in output

    assert "Known Exploited Vulnerabilities" in output
    assert "Example Vendor" in output
    assert "Example Product" in output
    assert "Known" in output
    assert "2026-01-15" in output

    assert "## Recommendations" in output
    assert "Prioritize remediation of high severity vulnerabilities." in output

    assert "Prioritize vulnerabilities marked as known exploited." in output


def test_render_report_with_high_epss_recommendation() -> None:

    finding = VulnerabilityInfo(
        dependency_name="django",
        dependency_version="5.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-9999",
        aliases=["CVE-2026-9999"],
        severity=Severity.MEDIUM,
        sources=[
            Provider.NVD,
        ],
        cvss=6.5,
        summary="High EPSS vulnerability.",
        epss_score=0.75,
    )

    report = ScanReport(
        scan_id=1,
        repository_id=1,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.AT_RISK,
        started_at=datetime.now(),
        finished_at=datetime.now(),
        duration_seconds=60,
        source_type=SourceType.LOCAL,
        source_reference=None,
        source_branch=None,
        source_commit=None,
        findings=[finding],
        dependency_summaries=[],
        critical_count=0,
        high_count=0,
        medium_count=1,
        low_count=0,
        risk_score=2,
        error_message=None,
    )

    output = MarkdownReportRenderer().render(report)

    assert "Review vulnerabilities with high EPSS scores." in output


def test_render_report_with_remediation_and_fixed_versions() -> None:
    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-0001",
        aliases=["CVE-2026-0001"],
        sources=[Provider.OSV],
        summary="Test vulnerability.",
        severity=Severity.HIGH,
        cvss=7.5,
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="2.0.0",
                    fixed="2.32.4",
                    affected_range="<2.32.4",
                ),
                RemediationRule(
                    introduced="3.0.0",
                    fixed="3.1.0",
                    affected_range=">=3.0.0,<3.1.0",
                ),
            ],
        ),
        fixed_versions=[
            "2.32.4",
            "3.1.0",
        ],
    )

    report = ScanReport(
        scan_id=1,
        repository_id=1,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.SECURE,
        started_at=datetime(2026, 8, 11, 10, 0, 0),
        finished_at=datetime(2026, 8, 11, 10, 2, 0),
        duration_seconds=120,
        source_type=SourceType.GIT,
        source_reference="https://github.com/test/project.git",
        source_branch="main",
        source_commit="abc123",
        findings=[finding],
        dependency_summaries=[],
        critical_count=0,
        high_count=1,
        medium_count=0,
        low_count=0,
        risk_score=5,
        error_message=None,
    )

    output = MarkdownReportRenderer().render(report)

    assert "## Remediation" in output
    assert "Fixed versions" in output
    assert "2.32.4" in output
    assert "3.1.0" in output
    assert "<2.32.4" in output
    assert ">=3.0.0,<3.1.0" in output
