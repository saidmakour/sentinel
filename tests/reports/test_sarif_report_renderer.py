import json
from datetime import date
from datetime import datetime

import pytest

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
from sentinel.reports.sarif import SarifReportRenderer


def test_render_sarif_report_with_finding() -> None:

    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        identifier="CVE-2024-12345",
        ecosystem=Ecosystem.PYPI,
        aliases=["CVE-2024-12345"],
        severity=Severity.HIGH,
        sources=[
            Provider.NVD,
        ],
        cvss=8.1,
        summary="A vulnerability in requests package.",
        status=VulnerabilityStatus.OPEN,
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    fixed="2.32.0",
                ),
            ],
        ),
        fixed_versions=[
            "2.32.0",
        ],
        known_exploited=True,
        kev_vendor="Example Vendor",
        kev_product="Example Product",
        kev_required_action="Update to a fixed version.",
        kev_known_ransomware=False,
        epss_score=0.42,
        epss_percentile=0.75,
    )

    report = ScanReport(
        scan_id=1,
        repository_id=1,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.AT_RISK,
        started_at=datetime(
            2026,
            7,
            17,
            10,
            0,
            0,
        ),
        finished_at=datetime(
            2026,
            7,
            17,
            10,
            2,
            0,
        ),
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
        error_message="",
    )

    renderer = SarifReportRenderer()

    output = renderer.render(
        report,
    )

    data = json.loads(
        output,
    )
    print(data)
    assert data["version"] == "2.1.0"

    assert len(data["runs"]) == 1

    run = data["runs"][0]

    assert run["tool"]["driver"]["name"] == "Sentinel"

    assert len(run["tool"]["driver"]["rules"]) == 1
    assert run["tool"]["driver"]["version"] == "1.0-dev"

    assert run["properties"]["repository_id"] == 1
    assert run["properties"]["source_type"] == "git"
    assert (
        run["properties"]["source_reference"]
        == "https://github.com/test/project.git"
    )
    assert run["properties"]["source_branch"] == "main"
    assert run["properties"]["source_commit"] == "abc123"

    rule = run["tool"]["driver"]["rules"][0]

    assert rule["id"] == "CVE-2024-12345"
    assert rule["name"] == "CVE-2024-12345"

    assert len(run["results"]) == 1

    result = run["results"][0]

    assert result["ruleId"] == "CVE-2024-12345"
    assert result["level"] == "error"

    assert result["message"]["text"] == "A vulnerability in requests package."

    assert result["properties"]["dependency"] == "requests"
    assert result["properties"]["version"] == "2.31.0"
    assert result["properties"]["status"] == "OPEN"

    assert result["properties"]["fixed_versions"] == [
        "2.32.0",
    ]

    assert result["properties"]["remediation"] == [
        {
            "introduced": None,
            "fixed": "2.32.0",
            "affected_range": None,
        },
    ]

    assert result["properties"]["known_exploited"] is True

    assert result["properties"]["kev_vendor"] == "Example Vendor"
    assert result["properties"]["kev_product"] == "Example Product"
    assert (
        result["properties"]["kev_required_action"]
        == "Update to a fixed version."
    )
    assert result["properties"]["kev_known_ransomware"] is False

    assert result["properties"]["epss_score"] == 0.42
    assert result["properties"]["epss_percentile"] == 0.75


@pytest.mark.parametrize(
    ("severity", "expected_level"),
    [
        ("CRITICAL", "error"),
        ("HIGH", "error"),
        ("MEDIUM", "warning"),
        ("LOW", "note"),
        ("UNKNOWN", "none"),
    ],
)
def test_severity_level(
    severity: str,
    expected_level: str,
) -> None:
    result = SarifReportRenderer._severity_level(
        severity,
    )

    assert result == expected_level


def test_render_empty_sarif_report() -> None:
    report = ScanReport(
        scan_id=1,
        repository_id=1,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.SECURE,
        started_at=datetime.now(),
        finished_at=datetime.now(),
        duration_seconds=1,
        source_type=SourceType.LOCAL,
        source_reference=None,
        source_branch=None,
        source_commit=None,
        findings=[],
        dependency_summaries=[],
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        risk_score=0,
        error_message=None,
    )

    output = SarifReportRenderer().render(report)

    data = json.loads(output)

    run = data["runs"][0]

    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_render_sarif_contains_required_fields() -> None:
    report = ScanReport(
        scan_id=1,
        repository_id=1,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.SECURE,
        started_at=datetime.now(),
        finished_at=datetime.now(),
        duration_seconds=1,
        source_type=SourceType.LOCAL,
        source_reference=None,
        source_branch=None,
        source_commit=None,
        findings=[],
        dependency_summaries=[],
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        risk_score=0,
        error_message=None,
    )

    data = json.loads(
        SarifReportRenderer().render(report),
    )

    assert "$schema" in data
    assert "runs" in data
    assert "tool" in data["runs"][0]
    assert "results" in data["runs"][0]


def test_render_uses_vulnerability_status_not_scan_status() -> None:
    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        identifier="CVE-2024-12345",
        ecosystem=Ecosystem.PYPI,
        aliases=[],
        severity=Severity.HIGH,
        sources=[Provider.NVD],
        cvss=8.1,
        summary="Test vulnerability",
        status=VulnerabilityStatus.RESOLVED,
    )

    report = ScanReport(
        scan_id=1,
        repository_id=1,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.UNKNOWN,
        started_at=datetime.now(),
        finished_at=datetime.now(),
        duration_seconds=1,
        source_type=SourceType.LOCAL,
        source_reference=None,
        source_branch=None,
        source_commit=None,
        findings=[finding],
        dependency_summaries=[],
        critical_count=0,
        high_count=1,
        medium_count=0,
        low_count=0,
        risk_score=8,
        error_message=None,
    )

    data = json.loads(
        SarifReportRenderer().render(report),
    )

    result = data["runs"][0]["results"][0]
    print(result)
    assert result["properties"]["status"] == "RESOLVED"
    assert result["properties"]["status"] != report.status.value


def test_render_sarif_serializes_kev_date() -> None:
    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        identifier="CVE-2024-12345",
        ecosystem=Ecosystem.PYPI,
        aliases=[],
        severity=Severity.HIGH,
        sources=[Provider.NVD],
        cvss=8.1,
        summary="Test vulnerability",
        status=VulnerabilityStatus.OPEN,
        kev_date_added=date(
            2026,
            1,
            15,
        ),
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
        duration_seconds=1,
        source_type=SourceType.LOCAL,
        source_reference=None,
        source_branch=None,
        source_commit=None,
        findings=[finding],
        dependency_summaries=[],
        critical_count=0,
        high_count=1,
        medium_count=0,
        low_count=0,
        risk_score=8,
        error_message=None,
    )

    data = json.loads(
        SarifReportRenderer().render(report),
    )

    result = data["runs"][0]["results"][0]
    assert (
        data["runs"][0]["properties"]["security_status"]
        == SecurityStatus.AT_RISK.value
    )

    assert result["properties"]["kev_date_added"] == "2026-01-15"
