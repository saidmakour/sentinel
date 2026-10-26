import json
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
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.models.finding import Finding
from sentinel.models.scan import Scan
from sentinel.reports.html import HtmlReportRenderer
from sentinel.reports.json import JsonReportRenderer
from sentinel.reports.markdown import MarkdownReportRenderer
from sentinel.reports.sarif import SarifReportRenderer
from sentinel.services.scan_report_service import ScanReportService
from sentinel.services.version_service import VersionService


def test_requests_vulnerability_produces_at_risk_scan_report() -> None:
    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="2.0.0",
                fixed="2.32.0",
                affected_range="<2.32.0",
            ),
        ],
    )

    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-35195",
        aliases=[],
        sources=[Provider.OSV],
        summary="Requests vulnerability",
        severity=Severity.HIGH,
        cvss=8.1,
        remediation=remediation,
        fixed_versions=["2.32.0"],
    )

    version_service = VersionService()

    finding.status = version_service.determine_status(
        ecosystem=finding.ecosystem,
        installed_version=finding.dependency_version,
        remediation=finding.remediation,
    )

    assert finding.status == VulnerabilityStatus.OPEN

    report = ScanReport(
        scan_id=1,
        repository_id=1,
        profile_name="default",
        engine_version="0.1.0",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.AT_RISK,
        started_at=datetime(2026, 8, 12, 10, 0, 0),
        finished_at=datetime(2026, 8, 12, 10, 0, 5),
        duration_seconds=5,
        source_type=SourceType.GIT,
        source_reference="main",
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

    assert report.security_status == SecurityStatus.AT_RISK.value

    renderer = JsonReportRenderer()

    data = json.loads(renderer.render(report))

    assert data["scan"]["status"] == "success"
    assert data["scan"]["security_status"] == SecurityStatus.AT_RISK.value

    assert data["findings"][0]["dependency"] == "requests"
    assert data["findings"][0]["version"] == "2.31.0"
    assert data["findings"][0]["status"] == "OPEN"

    assert data["findings"][0]["fixed_versions"] == ["2.32.0"]

    assert data["findings"][0]["remediation"]["rules"][0]["fixed"] == "2.32.0"
    assert (
        data["findings"][0]["remediation"]["rules"][0]["affected_range"]
        == "<2.32.0"
    )

    assert data["scan"]["security_status"] == SecurityStatus.AT_RISK


def test_requests_vulnerability_produces_at_risk_json_report(
    db_session,
) -> None:
    scan = Scan(
        repository_id=1,
        profile_name="default",
        engine_version="0.1.0",
        status=ScanStatus.SUCCESS,
        source_type=SourceType.LOCAL,
        source_reference=".",
        source_branch=None,
        source_commit=None,
        started_at=datetime(2026, 8, 12, 10, 0, 0),
        finished_at=datetime(2026, 8, 12, 10, 0, 5),
        duration_seconds=1,
        error_message=None,
    )

    db_session.add(scan)
    db_session.flush()

    finding = Finding(
        scan_id=scan.id,
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-35195",
        severity=Severity.HIGH,
        status=VulnerabilityStatus.OPEN,
        summary="Requests vulnerability",
        cvss=7.5,
        remediation={
            "rules": [
                {
                    "introduced": "0",
                    "fixed": "2.32.0",
                    "affected_range": None,
                },
            ],
        },
        fixed_versions=["2.32.0"],
    )

    db_session.add(finding)
    db_session.commit()

    service = ScanReportService(db_session)

    report = service.get_report(scan.id)

    result = JsonReportRenderer().render(report)
    data = json.loads(result)

    assert data["scan"]["security_status"] == (SecurityStatus.AT_RISK.value)

    assert len(data["dependency_security"]) == 1

    dependency = data["dependency_security"][0]

    assert dependency["dependency"] == "requests"
    assert dependency["version"] == "2.31.0"
    assert dependency["ecosystem"] == Ecosystem.PYPI.value

    assert dependency["security_status"] == (SecurityStatus.AT_RISK.value)

    assert dependency["finding_count"] == 1
    assert dependency["open_finding_count"] == 1
    assert dependency["recommended_version"] == "2.32.0"

    assert data["findings"][0]["dependency"] == "requests"
    assert data["findings"][0]["version"] == "2.31.0"
    assert data["findings"][0]["status"] == (VulnerabilityStatus.OPEN.value)

    assert data["findings"][0]["fixed_versions"] == [
        "2.32.0",
    ]


def test_requests_vulnerability_produces_at_risk_markdown_report(
    db_session,
) -> None:
    scan = Scan(
        repository_id=1,
        profile_name="default",
        engine_version="0.1.0",
        status=ScanStatus.SUCCESS,
        source_type=SourceType.LOCAL,
        source_reference=".",
        source_branch=None,
        source_commit=None,
        started_at=datetime(2026, 8, 12, 10, 0, 0),
        finished_at=datetime(2026, 8, 12, 10, 0, 5),
        duration_seconds=1,
        error_message=None,
    )

    db_session.add(scan)
    db_session.flush()

    finding = Finding(
        scan_id=scan.id,
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-35195",
        severity=Severity.HIGH,
        status=VulnerabilityStatus.OPEN,
        summary="Requests vulnerability",
        cvss=7.5,
        remediation={
            "rules": [
                {
                    "introduced": "0",
                    "fixed": "2.32.0",
                    "affected_range": None,
                },
            ],
        },
        fixed_versions=["2.32.0"],
    )

    db_session.add(finding)
    db_session.commit()

    service = ScanReportService(db_session)

    report = service.get_report(scan.id)

    result = MarkdownReportRenderer().render(report)
    print(result)
    assert "## Executive Summary" in result
    assert f"- Security Status: {SecurityStatus.AT_RISK.value}" in result

    assert "## Dependency Security" in result

    assert (
        "| requests | 2.31.0 | PyPI | at_risk | 1 | 1 | `2.32.0` |" in result
    )

    assert "## Recommended Actions" in result

    assert "- Upgrade requests from `2.31.0` to `2.32.0`." in result

    assert "## Vulnerabilities" in result
    assert "CVE-2024-35195" in result


def test_requests_vulnerability_produces_at_risk_html_report(
    db_session,
) -> None:
    scan = Scan(
        repository_id=1,
        profile_name="default",
        engine_version="0.1.0",
        status=ScanStatus.SUCCESS,
        source_type=SourceType.LOCAL,
        source_reference=".",
        source_branch=None,
        source_commit=None,
        started_at=datetime(2026, 8, 12, 10, 0, 0),
        finished_at=datetime(2026, 8, 12, 10, 0, 5),
        duration_seconds=1,
        error_message=None,
    )

    db_session.add(scan)
    db_session.flush()

    finding = Finding(
        scan_id=scan.id,
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-35195",
        severity=Severity.HIGH,
        status=VulnerabilityStatus.OPEN,
        summary="Requests vulnerability",
        cvss=7.5,
        remediation={
            "rules": [
                {
                    "introduced": "0",
                    "fixed": "2.32.0",
                    "affected_range": None,
                },
            ],
        },
        fixed_versions=["2.32.0"],
    )

    db_session.add(finding)
    db_session.commit()

    service = ScanReportService(db_session)

    report = service.get_report(scan.id)

    result = HtmlReportRenderer().render(report)

    assert "Dependency Security" in result
    assert "requests" in result
    assert "2.31.0" in result
    assert "at_risk" in result
    assert "2.32.0" in result
    assert "Recommended Actions" in result


def test_requests_vulnerability_produces_at_risk_sarif_report(
    db_session,
) -> None:
    scan = Scan(
        repository_id=1,
        profile_name="default",
        engine_version="0.1.0",
        status=ScanStatus.SUCCESS,
        source_type=SourceType.LOCAL,
        source_reference=".",
        source_branch=None,
        source_commit=None,
        started_at=datetime(2026, 8, 12, 10, 0, 0),
        finished_at=datetime(2026, 8, 12, 10, 0, 5),
        duration_seconds=1,
        error_message=None,
    )

    db_session.add(scan)
    db_session.flush()

    finding = Finding(
        scan_id=scan.id,
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-35195",
        severity=Severity.HIGH,
        status=VulnerabilityStatus.OPEN,
        summary="Requests vulnerability",
        cvss=7.5,
        remediation={
            "rules": [
                {
                    "introduced": "0",
                    "fixed": "2.32.0",
                    "affected_range": None,
                },
            ],
        },
        fixed_versions=["2.32.0"],
    )

    db_session.add(finding)
    db_session.commit()

    service = ScanReportService(db_session)

    report = service.get_report(scan.id)

    result = SarifReportRenderer().render(report)

    data = json.loads(result)

    run = data["runs"][0]
    properties = run["properties"]

    assert data["version"] == "2.1.0"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "CVE-2024-35195"

    assert properties["security_status"] == "at_risk"

    dependency = properties["dependency_security"][0]

    assert dependency["dependency"] == "requests"
    assert dependency["version"] == "2.31.0"
    assert dependency["security_status"] == "at_risk"
    assert dependency["recommended_version"] == "2.32.0"

    assert (
        "Upgrade requests from 2.31.0 to 2.32.0."
        in properties["recommended_actions"]
    )
