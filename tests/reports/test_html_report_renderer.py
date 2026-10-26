from datetime import datetime

from sentinel.dto.dependency_security_summary import DependencySecuritySummary
from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.scan_report import ScanReport
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.scan_status import ScanStatus
from sentinel.enums.security_status import SecurityStatus
from sentinel.enums.severity import Severity
from sentinel.enums.source_type import SourceType
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.reports.html import HtmlReportRenderer


def _build_report(
    *,
    findings: list[VulnerabilityInfo] | None = None,
    dependency_summaries: list[DependencySecuritySummary] | None = None,
    error_message: str | None = None,
) -> ScanReport:
    return ScanReport(
        scan_id=12,
        repository_id=1,
        profile_name="default",
        engine_version="0.1.0",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.AT_RISK,
        started_at=datetime(2026, 8, 16, 10, 0, 0),
        finished_at=datetime(2026, 8, 16, 10, 1, 30),
        duration_seconds=90,
        source_type=SourceType.GIT,
        source_reference="https://github.com/example/project",
        source_branch="main",
        source_commit="abc123",
        findings=findings or [],
        dependency_summaries=dependency_summaries or [],
        critical_count=1,
        high_count=2,
        medium_count=3,
        low_count=4,
        risk_score=29,
        error_message=error_message,
    )


def _build_finding(
    *,
    dependency_name: str = "GitPython",
    dependency_version: str = "3.1.45",
    identifier: str = "CVE-2026-44243",
    severity: Severity = Severity.HIGH,
    status: VulnerabilityStatus = VulnerabilityStatus.OPEN,
    known_exploited: bool = False,
    remediation: RemediationInfo | None = None,
    fixed_versions: list[str] | None = None,
) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        dependency_name=dependency_name,
        dependency_version=dependency_version,
        ecosystem=Ecosystem.PYPI,
        identifier=identifier,
        aliases=[],
        sources=[],
        summary="Test vulnerability",
        severity=severity,
        cvss=7.8,
        status=status,
        remediation=remediation,
        fixed_versions=fixed_versions or [],
        known_exploited=known_exploited,
        epss_score=0.0148,
    )


def test_render_contains_document_structure() -> None:
    report = _build_report()

    result = HtmlReportRenderer().render(report)

    assert "<!DOCTYPE html>" in result
    assert '<html lang="en">' in result
    assert "<head>" in result
    assert "<body>" in result
    assert "Sentinel Vulnerability Report" in result


def test_render_contains_scan_information() -> None:
    report = _build_report()

    result = HtmlReportRenderer().render(report)

    assert "Scan Information" in result
    assert "12" in result
    assert "default" in result
    assert "0.1.0" in result
    assert "success" in result
    assert "2026-08-16" in result
    assert "29" in result


def test_render_contains_source_information() -> None:
    report = _build_report()

    result = HtmlReportRenderer().render(report)

    assert "Source" in result
    assert "git" in result
    assert "https://github.com/example/project" in result
    assert "main" in result
    assert "abc123" in result


def test_render_contains_security_status() -> None:
    report = _build_report()

    result = HtmlReportRenderer().render(report)

    assert "Project is at risk" in result
    assert "open vulnerabilities" in result


def test_render_contains_risk_summary() -> None:
    report = _build_report()

    result = HtmlReportRenderer().render(report)

    assert "Risk Score" in result
    assert "29" in result
    assert "Critical" in result
    assert "High" in result
    assert "Medium" in result
    assert "Low" in result


def test_render_contains_vulnerability_table() -> None:
    finding = _build_finding()

    report = _build_report(
        findings=[finding],
    )

    result = HtmlReportRenderer().render(report)

    assert "Vulnerabilities" in result
    assert "GitPython" in result
    assert "3.1.45" in result
    assert "PyPI" in result
    assert "CVE-2026-44243" in result
    assert "HIGH" in result
    assert "OPEN" in result
    assert "7.8" in result
    assert "0.0148" in result


def test_render_open_finding_has_open_status() -> None:
    finding = _build_finding(
        status=VulnerabilityStatus.OPEN,
    )

    report = _build_report(
        findings=[finding],
    )

    result = HtmlReportRenderer().render(report)

    assert "OPEN" in result


def test_render_resolved_finding_has_resolved_status() -> None:
    finding = _build_finding(
        status=VulnerabilityStatus.RESOLVED,
    )

    report = _build_report(
        findings=[finding],
    )

    result = HtmlReportRenderer().render(report)

    assert "RESOLVED" in result


def test_render_unknown_finding_has_unknown_status() -> None:
    finding = _build_finding(
        severity=Severity.UNKNOWN,
        status=VulnerabilityStatus.UNKNOWN,
    )

    report = _build_report(
        findings=[finding],
    )

    result = HtmlReportRenderer().render(report)

    assert "UNKNOWN" in result


def test_render_kev_finding() -> None:
    finding = _build_finding(
        known_exploited=True,
    )

    report = _build_report(
        findings=[finding],
    )

    result = HtmlReportRenderer().render(report)

    assert "Known Exploited Vulnerabilities" in result
    assert "YES" in result


def test_render_without_kev_does_not_render_kev_section() -> None:
    finding = _build_finding(
        known_exploited=False,
    )

    report = _build_report(
        findings=[finding],
    )

    result = HtmlReportRenderer().render(report)

    assert "Known Exploited Vulnerabilities" not in result


def test_render_dependency_security() -> None:
    summary = DependencySecuritySummary(
        dependency_name="GitPython",
        installed_version="3.1.45",
        ecosystem=Ecosystem.PYPI,
        security_status=SecurityStatus.AT_RISK,
        finding_count=27,
        open_finding_count=22,
        recommended_version="3.1.58",
    )

    report = _build_report(
        dependency_summaries=[summary],
    )

    result = HtmlReportRenderer().render(report)

    assert "Dependency Security" in result
    assert "GitPython" in result
    assert "3.1.45" in result
    assert "27" in result
    assert "22" in result
    assert "3.1.58" in result
    assert SecurityStatus.AT_RISK.value in result


def test_render_recommendations() -> None:
    summary = DependencySecuritySummary(
        dependency_name="GitPython",
        installed_version="3.1.45",
        ecosystem=Ecosystem.PYPI,
        security_status=SecurityStatus.AT_RISK,
        finding_count=27,
        open_finding_count=22,
        recommended_version="3.1.58",
    )

    report = _build_report(
        dependency_summaries=[summary],
    )

    result = HtmlReportRenderer().render(report)

    assert "Recommended Actions" in result
    assert "GitPython" in result
    assert "3.1.45" in result
    assert "3.1.58" in result


def test_render_no_recommendation() -> None:
    summary = DependencySecuritySummary(
        dependency_name="GitPython",
        installed_version="3.1.45",
        ecosystem=Ecosystem.PYPI,
        security_status=SecurityStatus.SECURE,
        finding_count=0,
        open_finding_count=0,
        recommended_version=None,
    )

    report = _build_report(
        dependency_summaries=[summary],
    )

    result = HtmlReportRenderer().render(report)

    assert "Recommended Actions" in result
    assert (
        "No immediate dependency upgrade recommendation is available."
        in result
    )


def test_render_remediation() -> None:
    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced=None,
                fixed="3.1.58",
                affected_range="<3.1.58",
            ),
        ],
    )

    finding = _build_finding(
        remediation=remediation,
        fixed_versions=["3.1.58"],
    )

    report = _build_report(
        findings=[finding],
    )

    result = HtmlReportRenderer().render(report)

    assert "Remediation" in result
    assert "Introduced" in result
    assert "Fixed" in result
    assert "Affected Range" in result
    assert "3.1.58" in result
    assert "&lt;3.1.58" in result


def test_render_fixed_versions() -> None:
    finding = _build_finding(
        fixed_versions=["3.1.48", "3.1.58"],
    )

    report = _build_report(
        findings=[finding],
    )

    result = HtmlReportRenderer().render(report)

    assert "Fixed versions:" in result
    assert "3.1.48" in result
    assert "3.1.58" in result


def test_render_error_message() -> None:
    report = _build_report(
        error_message="Scan failed: invalid repository",
    )

    result = HtmlReportRenderer().render(report)

    assert "Scan Error" in result
    assert "Scan failed: invalid repository" in result


def test_render_without_error_does_not_render_error_section() -> None:
    report = _build_report()

    result = HtmlReportRenderer().render(report)

    assert "Scan Error" not in result


def test_render_escapes_html_values() -> None:
    finding = _build_finding(
        dependency_name="<script>alert('x')</script>",
        identifier="<b>CVE-TEST</b>",
    )

    report = _build_report(
        findings=[finding],
    )

    result = HtmlReportRenderer().render(report)

    assert "<script>alert('x')</script>" not in result
    assert "&lt;script&gt;alert(" in result
    assert "&lt;b&gt;CVE-TEST&lt;/b&gt;" in result


def test_render_empty_findings() -> None:
    report = _build_report()

    result = HtmlReportRenderer().render(report)

    assert "Vulnerabilities" in result
    assert "<tbody>" in result
