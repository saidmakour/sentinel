import json
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
from sentinel.reports.json import JsonReportRenderer


def test_render_json_report_with_finding() -> None:

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
        summary="A vulnerability in requests package.",
        known_exploited=True,
        epss_score=0.42,
        epss_percentile=0.75,
        kev_date_added=date(
            2026,
            1,
            15,
        ),
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

    renderer = JsonReportRenderer()

    output = renderer.render(
        report,
    )

    data = json.loads(
        output,
    )

    assert data["scan"]["id"] == 1
    assert data["scan"]["repository_id"] == 1
    assert data["scan"]["profile"] == "default"
    assert data["scan"]["status"] == "success"

    assert data["source"]["type"] == "git"
    assert data["source"]["reference"] == "https://github.com/test/project.git"
    assert data["source"]["branch"] == "main"
    assert data["source"]["commit"] == "abc123"

    assert data["risk"]["score"] == 8
    assert data["risk"]["severity"]["high"] == 1
    assert data["risk"]["severity"]["critical"] == 0

    assert len(data["findings"]) == 1

    result = data["findings"][0]

    assert result["dependency"] == "requests"
    assert result["version"] == "2.31.0"
    assert result["identifier"] == "CVE-2024-12345"
    assert result["ecosystem"] == Ecosystem.PYPI.value
    assert result["aliases"] == ["CVE-2024-12345"]
    assert result["status"] == "UNKNOWN"
    assert result["summary"] == ("A vulnerability in requests package.")
    assert result["kev_date_added"] == "2026-01-15"
    assert result["kev_vendor"] == "Example Vendor"
    assert result["kev_product"] == "Example Product"
    assert result["kev_known_ransomware"] == "Known"
    assert result["epss_percentile"] == 0.75
    assert result["severity"] == Severity.HIGH.value
    assert result["cvss"] == 8.1
    assert result["known_exploited"] is True
    assert result["epss_score"] == 0.42
    assert "NVD" in result["sources"]

    assert data["scan"]["error_message"] == ""


def test_render_json_report_without_findings() -> None:
    report = ScanReport(
        scan_id=1,
        repository_id=1,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.SECURE,
        started_at=None,
        finished_at=None,
        duration_seconds=None,
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

    renderer = JsonReportRenderer()

    data = json.loads(
        renderer.render(report),
    )

    assert data["findings"] == []
    assert data["risk"]["score"] == 0


def test_render_includes_remediation_and_fixed_versions() -> None:
    remediation = RemediationInfo(
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
    )

    finding = VulnerabilityInfo(
        identifier="CVE-2026-0001",
        aliases=["CVE-2026-0001"],
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        sources=[Provider.OSV],
        summary="Test vulnerability",
        severity=Severity.HIGH,
        cvss=7.5,
        remediation=remediation,
        fixed_versions=[
            "2.32.4",
            "2.31.5",
        ],
    )

    report = ScanReport(
        scan_id=1,
        repository_id=1,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.SECURE,
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

    renderer = JsonReportRenderer()

    result = json.loads(
        renderer.render(report),
    )

    finding_data = result["findings"][0]

    assert finding_data["remediation"] == {
        "rules": [
            {
                "introduced": "2.0.0",
                "fixed": "2.32.4",
                "affected_range": "<2.32.4",
            },
            {
                "introduced": "3.0.0",
                "fixed": "3.1.0",
                "affected_range": ">=3.0.0,<3.1.0",
            },
        ],
    }

    assert finding_data["fixed_versions"] == [
        "2.32.4",
        "2.31.5",
    ]


def test_render_without_remediation_returns_null() -> None:

    finding = VulnerabilityInfo(
        identifier="CVE-2026-0001",
        aliases=["CVE-2026-0001"],
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        sources=[Provider.OSV],
        summary="Test vulnerability",
        severity=Severity.HIGH,
        cvss=7.5,
        remediation=None,
        fixed_versions=[],
    )

    report = ScanReport(
        scan_id=1,
        repository_id=1,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.UNKNOWN,
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

    renderer = JsonReportRenderer()

    result = json.loads(
        renderer.render(report),
    )

    finding_data = result["findings"][0]
    print(finding_data)
    assert finding_data["remediation"] is None
    assert finding_data["fixed_versions"] == []
