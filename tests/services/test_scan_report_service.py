from datetime import UTC
from datetime import datetime
from unittest.mock import MagicMock

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
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.exceptions.scan import ScanNotFoundError
from sentinel.models.scan import Scan
from sentinel.services.scan_report_service import ScanReportService


def create_scan(
    *,
    scan_id: int = 1,
    repository_id: int = 10,
) -> Scan:
    return Scan(
        id=scan_id,
        repository_id=repository_id,
        profile_name="default",
        status=ScanStatus.SUCCESS,
        started_at=datetime(
            2026,
            1,
            1,
            tzinfo=UTC,
        ),
        finished_at=datetime(
            2026,
            1,
            1,
            0,
            1,
            tzinfo=UTC,
        ),
        duration_seconds=60,
    )


def create_finding(
    severity: Severity,
    identifier: str = "CVE-2026-0001",
    vulnerabilitystattus: VulnerabilityStatus = VulnerabilityStatus.UNKNOWN,
) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        identifier=identifier,
        aliases=["CVE-2026-0001"],
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        sources=[Provider.OSV],
        severity=severity,
        status=vulnerabilitystattus,
        cvss=7.5,
        summary="Test vulnerability",
    )


def create_service(
    monkeypatch,
    *,
    scan: Scan | None = None,
    findings: list[VulnerabilityInfo] | None = None,
    risk_result: tuple[int, int, int, int, float] = (
        1,
        2,
        1,
        1,
        23,
    ),
) -> tuple[
    ScanReportService,
    MagicMock,
    MagicMock,
    MagicMock,
]:
    session = MagicMock()

    scan_repository = MagicMock()
    scan_repository.get_by_id.return_value = scan

    monkeypatch.setattr(
        "sentinel.services.scan_report_service.ScanRepository",
        lambda session: scan_repository,
    )

    finding_service = MagicMock()
    finding_service.list_by_scan.return_value = (
        findings if findings is not None else []
    )

    monkeypatch.setattr(
        "sentinel.services.scan_report_service.FindingService",
        lambda session: finding_service,
    )

    risk_service = MagicMock()
    risk_service.calculate.return_value = risk_result

    monkeypatch.setattr(
        "sentinel.services.scan_report_service.RiskService",
        lambda: risk_service,
    )

    service = ScanReportService(session)

    return (
        service,
        scan_repository,
        finding_service,
        risk_service,
    )


def test_scan_report_service_can_be_created(
    monkeypatch,
) -> None:
    service, _, _, _ = create_service(
        monkeypatch,
    )

    assert service is not None
    assert service.scan_repo is not None
    assert service.finding_service is not None
    assert service.risk_service is not None


def test_get_report_returns_scan_report(
    monkeypatch,
) -> None:
    scan = create_scan()

    service, _, _, _ = create_service(
        monkeypatch,
        scan=scan,
    )

    result = service.get_report(
        scan_id=1,
    )

    assert isinstance(
        result,
        ScanReport,
    )


def test_get_report_raises_when_scan_not_found(
    monkeypatch,
) -> None:
    service, scan_repository, _, _ = create_service(
        monkeypatch,
        scan=None,
    )

    with pytest.raises(
        ScanNotFoundError,
        match="Scan '999' not found",
    ):
        service.get_report(
            scan_id=999,
        )

    scan_repository.get_by_id.assert_called_once_with(
        999,
    )


def test_get_report_does_not_load_findings_when_scan_not_found(
    monkeypatch,
) -> None:
    service, _, finding_service, risk_service = create_service(
        monkeypatch,
        scan=None,
    )

    with pytest.raises(ScanNotFoundError):
        service.get_report(
            scan_id=999,
        )

    finding_service.list_by_scan.assert_not_called()
    risk_service.calculate.assert_not_called()


def test_get_report_loads_findings_for_scan(
    monkeypatch,
) -> None:
    scan = create_scan()

    findings = [
        create_finding(
            Severity.HIGH,
        ),
    ]

    service, _, finding_service, _ = create_service(
        monkeypatch,
        scan=scan,
        findings=findings,
    )

    service.get_report(
        scan_id=1,
    )

    finding_service.list_by_scan.assert_called_once_with(
        1,
    )


def test_get_report_calculates_risk_from_open_findings(
    monkeypatch,
) -> None:
    scan = create_scan()

    findings = [
        create_finding(
            Severity.CRITICAL,
            "CVE-2026-0001",
            VulnerabilityStatus.OPEN,
        ),
        create_finding(
            Severity.HIGH,
            "CVE-2026-0002",
            VulnerabilityStatus.OPEN,
        ),
        create_finding(
            Severity.HIGH,
            "CVE-2026-0003",
            VulnerabilityStatus.OPEN,
        ),
        create_finding(
            Severity.MEDIUM,
            "CVE-2026-0004",
            VulnerabilityStatus.OPEN,
        ),
        create_finding(
            Severity.LOW,
            "CVE-2026-0005",
            VulnerabilityStatus.OPEN,
        ),
        create_finding(
            Severity.UNKNOWN,
            "CVE-2026-0006",
            VulnerabilityStatus.OPEN,
        ),
        create_finding(
            Severity.CRITICAL,
            "CVE-2026-0007",
            VulnerabilityStatus.RESOLVED,
        ),
    ]

    service, _, _, risk_service = create_service(
        monkeypatch,
        scan=scan,
        findings=findings,
    )

    report = service.get_report(
        scan_id=1,
    )
    print(risk_service.calculate.call_args)
    risk_service.calculate.assert_called_once_with(
        {
            "CRITICAL": 1,
            "HIGH": 2,
            "MEDIUM": 1,
            "LOW": 1,
            "UNKNOWN": 1,
        },
    )

    assert report.critical_count == 1
    assert report.high_count == 2
    assert report.medium_count == 1
    assert report.low_count == 1
    assert report.risk_score == 23


def test_get_report_contains_risk_information(
    monkeypatch,
) -> None:
    scan = create_scan()

    service, _, _, _ = create_service(
        monkeypatch,
        scan=scan,
        risk_result=(
            2,
            3,
            4,
            5,
            85,
        ),
    )

    result = service.get_report(
        scan_id=1,
    )

    assert result.critical_count == 2
    assert result.high_count == 3
    assert result.medium_count == 4
    assert result.low_count == 5
    assert result.risk_score == 85


def test_get_report_with_no_findings(
    monkeypatch,
) -> None:
    scan = create_scan()

    service, _, _, risk_service = create_service(
        monkeypatch,
        scan=scan,
        findings=[],
        risk_result=(
            0,
            0,
            0,
            0,
            0.0,
        ),
    )

    result = service.get_report(
        scan_id=1,
    )

    assert result.findings == []
    assert result.critical_count == 0
    assert result.high_count == 0
    assert result.medium_count == 0
    assert result.low_count == 0
    assert result.risk_score == 0.0

    risk_service.calculate.assert_called_once_with({})


def test_get_report_contains_scan_metadata(
    monkeypatch,
) -> None:
    scan = create_scan()

    scan.engine_version = "0.1.0"
    scan.source_reference = "https://git.example.com/project.git"
    scan.source_branch = "main"
    scan.source_commit = "abcdef123"

    service, _, _, _ = create_service(
        monkeypatch,
        scan=scan,
    )

    result = service.get_report(
        scan_id=1,
    )

    assert result.engine_version == "0.1.0"
    assert result.source_reference == ("https://git.example.com/project.git")
    assert result.source_branch == "main"
    assert result.source_commit == "abcdef123"


def test_get_report_returns_failed_scan_information(
    monkeypatch,
) -> None:
    scan = create_scan()

    scan.status = ScanStatus.FAILED
    scan.error_message = "Git clone failed"

    service, _, _, _ = create_service(
        monkeypatch,
        scan=scan,
    )

    result = service.get_report(
        scan_id=1,
    )

    assert result.status == ScanStatus.FAILED
    assert result.error_message == "Git clone failed"


def test_get_report_contains_risk_information_2(
    monkeypatch,
) -> None:
    scan = create_scan()

    service, _, _, _ = create_service(
        monkeypatch,
        scan=scan,
        risk_result=(
            2,
            3,
            4,
            5,
            51,
        ),
    )

    result = service.get_report(
        scan_id=1,
    )

    assert result.critical_count == 2
    assert result.high_count == 3
    assert result.medium_count == 4
    assert result.low_count == 5
    assert result.risk_score == 51


def test_get_report_returns_findings(
    monkeypatch,
) -> None:
    scan = create_scan()

    findings = [
        create_finding(
            Severity.HIGH,
            "CVE-2026-1234",
        ),
    ]

    service, _, _, _ = create_service(
        monkeypatch,
        scan=scan,
        findings=findings,
    )

    result = service.get_report(
        scan_id=1,
    )

    assert len(result.findings) == 1
    assert result.findings[0].identifier == "CVE-2026-1234"


def test_get_report_contains_dependency_security_summary(
    monkeypatch,
    db_session,
) -> None:
    service = ScanReportService(db_session)

    scan = create_scan()

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
    service, _, _, _ = create_service(
        monkeypatch,
        scan=scan,
        findings=[finding],
    )

    report = service.get_report(scan.id)

    assert len(report.dependency_summaries) == 1

    summary = report.dependency_summaries[0]

    assert summary.dependency_name == "requests"
    assert summary.installed_version == "2.31.0"
    assert summary.ecosystem == Ecosystem.PYPI
    assert summary.security_status == SecurityStatus.AT_RISK
    assert summary.finding_count == 1
    assert summary.open_finding_count == 1
    assert summary.recommended_version == "2.32.0"


def test_get_report_uses_highest_recommended_version(
    monkeypatch,
    db_session,
) -> None:
    service = ScanReportService(db_session)

    scan = create_scan()

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

    service, _, _, _ = create_service(
        monkeypatch,
        scan=scan,
        findings=[finding_one, finding_two],
    )
    report = service.get_report(scan.id)

    assert len(report.dependency_summaries) == 1

    summary = report.dependency_summaries[0]

    assert summary.dependency_name == "requests"
    assert summary.finding_count == 2
    assert summary.open_finding_count == 2
    assert summary.security_status == SecurityStatus.AT_RISK
    assert summary.recommended_version == "2.33.0"


def test_get_report_marks_dependency_secure_when_resolved(
    monkeypatch,
    db_session,
) -> None:
    service = ScanReportService(db_session)

    scan = create_scan()

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

    service, _, _, _ = create_service(
        monkeypatch,
        scan=scan,
        findings=[finding],
    )

    report = service.get_report(scan.id)

    assert len(report.dependency_summaries) == 1

    summary = report.dependency_summaries[0]

    assert summary.security_status == SecurityStatus.SECURE
    assert summary.finding_count == 1
    assert summary.open_finding_count == 0
    assert summary.recommended_version is None


def test_get_report_contains_global_security_status(
    monkeypatch,
    db_session,
) -> None:
    service = ScanReportService(db_session)

    scan = create_scan()

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
        status=VulnerabilityStatus.OPEN,
        remediation=RemediationInfo(
            rules=[],
        ),
        fixed_versions=["2.34.0"],
    )
    service, _, _, _ = create_service(
        monkeypatch,
        scan=scan,
        findings=[finding],
    )
    report = service.get_report(scan.id)

    assert report.security_status == SecurityStatus.AT_RISK
    assert report.dependency_summaries[0].security_status == (
        SecurityStatus.AT_RISK
    )
