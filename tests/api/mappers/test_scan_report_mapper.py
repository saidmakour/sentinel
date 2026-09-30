from datetime import datetime

from sentinel.api.mappers.scan_report_mapper import scan_report_to_schema
from sentinel.api.schemas.scan_report import ScanReportSchema
from sentinel.api.schemas.vulnerability import RemediationInfoSchema
from sentinel.api.schemas.vulnerability import RemediationRuleSchema
from sentinel.api.schemas.vulnerability import VulnerabilityInfoSchema
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


def test_scan_report_to_schema_maps_all_fields() -> None:
    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-12345",
        aliases=[
            "CVE-2024-12345",
            "GHSA-test",
        ],
        sources=[
            Provider.NVD,
        ],
        summary="A vulnerability in requests package.",
        severity=Severity.HIGH,
        cvss=8.1,
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
        fixed_versions=[
            "2.32.0",
        ],
        known_exploited=True,
        kev_date_added=datetime(
            2026,
            7,
            20,
        ).date(),
        kev_vendor="Test Vendor",
        kev_product="requests",
        kev_required_action="Update to a fixed version.",
        kev_known_ransomware="Known",
        epss_score=0.42,
        epss_percentile=0.75,
    )

    report = ScanReport(
        scan_id=1,
        repository_id=123,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.SECURE,
        started_at=datetime(
            2026,
            7,
            25,
            9,
            0,
            0,
        ),
        finished_at=datetime(
            2026,
            7,
            25,
            9,
            5,
            0,
        ),
        duration_seconds=300,
        source_type=SourceType.GIT,
        source_reference="http://monsite.org/projet.git",
        source_branch="main",
        source_commit="abc123",
        findings=[
            finding,
        ],
        dependency_summaries=[],
        critical_count=1,
        high_count=1,
        medium_count=1,
        low_count=1,
        risk_score=82,
        error_message="",
    )

    result = scan_report_to_schema(
        report,
    )

    assert result == ScanReportSchema(
        scan_id=1,
        repository_id=123,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.SECURE,
        started_at=datetime(
            2026,
            7,
            25,
            9,
            0,
            0,
        ),
        finished_at=datetime(
            2026,
            7,
            25,
            9,
            5,
            0,
        ),
        duration_seconds=300,
        source_type=SourceType.GIT,
        source_reference="http://monsite.org/projet.git",
        source_branch="main",
        source_commit="abc123",
        findings=[
            VulnerabilityInfoSchema(
                dependency_name="requests",
                dependency_version="2.31.0",
                ecosystem=Ecosystem.PYPI,
                identifier="CVE-2024-12345",
                aliases=[
                    "CVE-2024-12345",
                    "GHSA-test",
                ],
                sources=[
                    Provider.NVD,
                ],
                summary="A vulnerability in requests package.",
                severity=Severity.HIGH,
                cvss=8.1,
                status=VulnerabilityStatus.OPEN,
                remediation=RemediationInfoSchema(
                    rules=[
                        RemediationRuleSchema(
                            introduced="2.0.0",
                            fixed="2.32.0",
                            affected_range="<2.32.0",
                        ),
                    ],
                ),
                fixed_versions=[
                    "2.32.0",
                ],
                known_exploited=True,
                kev_date_added=datetime(
                    2026,
                    7,
                    20,
                ).date(),
                kev_vendor="Test Vendor",
                kev_product="requests",
                kev_required_action=("Update to a fixed version."),
                kev_known_ransomware="Known",
                epss_score=0.42,
                epss_percentile=0.75,
            ),
        ],
        critical_count=1,
        high_count=1,
        medium_count=1,
        low_count=1,
        risk_score=82,
        error_message="",
    )


def test_scan_report_to_schema_maps_finding_without_remediation() -> None:
    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-12345",
        aliases=[],
        sources=[
            Provider.OSV,
        ],
        summary="A vulnerability.",
        severity=Severity.MEDIUM,
        cvss=None,
    )

    report = ScanReport(
        scan_id=1,
        repository_id=123,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.UNKNOWN,
        started_at=datetime(
            2026,
            7,
            25,
            9,
            0,
            0,
        ),
        finished_at=None,
        duration_seconds=None,
        source_type=SourceType.GIT,
        source_reference=None,
        source_branch=None,
        source_commit=None,
        findings=[
            finding,
        ],
        dependency_summaries=[],
        critical_count=0,
        high_count=0,
        medium_count=1,
        low_count=0,
        risk_score=2,
        error_message=None,
    )

    result = scan_report_to_schema(
        report,
    )

    assert result.findings[0].status == VulnerabilityStatus.UNKNOWN
    assert result.findings[0].remediation is None
    assert result.findings[0].fixed_versions == []
    assert result.findings[0].known_exploited is False
    assert result.findings[0].epss_score is None
    assert result.findings[0].epss_percentile is None
