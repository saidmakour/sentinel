from datetime import datetime

from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.scan_status import ScanStatus
from sentinel.enums.severity import Severity
from sentinel.models.finding import Finding
from sentinel.models.scan import Scan
from sentinel.repositories.finding_repository import FindingRepository


def test_create_finding(
    db_session,
):

    repo = FindingRepository(db_session)

    finding = Finding(
        scan_id=1,
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2025-0001",
        severity=Severity.HIGH,
        cvss=8.2,
        summary="Example vulnerability",
    )

    created = repo.create(finding)

    assert created.id is not None
    assert created.identifier == "CVE-2025-0001"


def test_add_many(db_session) -> None:
    repo = FindingRepository(db_session)

    findings = [
        VulnerabilityInfo(
            identifier="CVE-2025-0001",
            aliases=["CVE-2025-0001"],
            dependency_name="requests",
            dependency_version="2.31.0",
            ecosystem=Ecosystem.PYPI,
            sources=[Provider.OSV],
            severity=Severity.HIGH,
            cvss=8.1,
            summary="Test vulnerability",
        ),
        VulnerabilityInfo(
            identifier="CVE-2025-0002",
            aliases=["CVE-2025-0002"],
            dependency_name="urllib3",
            dependency_version="2.0.0",
            ecosystem=Ecosystem.PYPI,
            sources=[Provider.OSV],
            severity=Severity.MEDIUM,
            cvss=5.5,
            summary="Another vulnerability",
        ),
    ]

    repo.add_many(
        findings,
        scan_id=1,
    )

    stored = db_session.query(Finding).all()

    assert len(stored) == 2
    assert stored[0].identifier == "CVE-2025-0001"
    assert stored[1].identifier == "CVE-2025-0002"


def test_list_by_scan(
    db_session,
):

    repo = FindingRepository(db_session)

    repo.create(
        Finding(
            scan_id=10,
            dependency_name="requests",
            dependency_version="2.31.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-1",
            severity=Severity.HIGH,
            cvss=8.0,
            summary="Test",
        )
    )

    findings = repo.list_by_scan(10)

    assert len(findings) == 1
    assert findings[0].dependency_name == "requests"


def test_count_by_scan(db_session) -> None:
    repo = FindingRepository(db_session)

    repo.add_many(
        [
            VulnerabilityInfo(
                identifier="CVE-1",
                aliases=["CVE-1"],
                dependency_name="requests",
                dependency_version="2.31.0",
                ecosystem=Ecosystem.PYPI,
                sources=[Provider.OSV],
                severity=Severity.HIGH,
                cvss=8.0,
                summary="Test",
            ),
            VulnerabilityInfo(
                identifier="CVE-2",
                aliases=["CVE-2"],
                dependency_name="urllib3",
                dependency_version="2.0.0",
                ecosystem=Ecosystem.PYPI,
                sources=[Provider.OSV],
                severity=Severity.LOW,
                cvss=2.5,
                summary="Test",
            ),
        ],
        scan_id=1,
    )

    assert repo.count_by_scan(1) == 2
    assert repo.count_by_scan(999) == 0


def test_get_all_findings(db_session):

    finding1 = Finding(
        scan_id=1,
        dependency_name="requests",
        dependency_version="1.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-0001",
        severity=Severity.HIGH,
        summary="Test vulnerability",
    )

    finding2 = Finding(
        scan_id=2,
        dependency_name="flask",
        dependency_version="2.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-0002",
        severity=Severity.MEDIUM,
        summary="Test vulnerability",
    )

    db_session.add_all(
        [
            finding1,
            finding2,
        ],
    )

    db_session.flush()

    repository = FindingRepository(
        db_session,
    )

    findings = repository.get_all()

    assert len(findings) == 2


def test_count_by_severity(db_session):

    finding1 = Finding(
        scan_id=1,
        dependency_name="requests",
        dependency_version="1.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-0001",
        severity=Severity.HIGH,
        summary="Test high",
    )

    finding2 = Finding(
        scan_id=1,
        dependency_name="flask",
        dependency_version="2.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-0002",
        severity=Severity.HIGH,
        summary="Test high 2",
    )

    finding3 = Finding(
        scan_id=2,
        dependency_name="django",
        dependency_version="3.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-0003",
        severity=Severity.MEDIUM,
        summary="Test medium",
    )

    db_session.add_all(
        [
            finding1,
            finding2,
            finding3,
        ],
    )

    db_session.flush()

    repository = FindingRepository(
        db_session,
    )

    result = repository.count_by_severity()

    assert result["HIGH"] == 2
    assert result["MEDIUM"] == 1


def test_count_by_repository(db_session):

    scan1 = Scan(
        repository_id=1,
        profile_name="default",
        status="FINISHED",
    )

    scan2 = Scan(
        repository_id=2,
        profile_name="fast",
        status=ScanStatus.SUCCESS,
    )

    db_session.add_all(
        [
            scan1,
            scan2,
        ],
    )

    db_session.flush()

    finding1 = Finding(
        scan_id=scan1.id,
        dependency_name="requests",
        dependency_version="1.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-0001",
        severity=Severity.HIGH,
        summary="Test",
    )

    finding2 = Finding(
        scan_id=scan1.id,
        dependency_name="flask",
        dependency_version="2.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-0002",
        severity=Severity.MEDIUM,
        summary="Test",
    )

    finding3 = Finding(
        scan_id=scan2.id,
        dependency_name="django",
        dependency_version="3.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-0003",
        severity=Severity.LOW,
        summary="Test",
    )

    db_session.add_all(
        [
            finding1,
            finding2,
            finding3,
        ],
    )

    db_session.flush()

    repository = FindingRepository(
        db_session,
    )

    assert repository.count_by_repository(1) == 2
    assert repository.count_by_repository(2) == 1


def test_count_by_repository_and_severity(
    db_session,
):

    scan = Scan(
        repository_id=1,
        profile_name="default",
        status=ScanStatus.SUCCESS,
    )

    db_session.add(scan)
    db_session.flush()

    findings = [
        Finding(
            scan_id=scan.id,
            dependency_name="requests",
            dependency_version="1.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-0001",
            severity=Severity.HIGH,
            summary="High issue",
        ),
        Finding(
            scan_id=scan.id,
            dependency_name="flask",
            dependency_version="2.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-0002",
            severity=Severity.HIGH,
            summary="High issue 2",
        ),
        Finding(
            scan_id=scan.id,
            dependency_name="django",
            dependency_version="3.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-0003",
            severity=Severity.CRITICAL,
            summary="Critical issue",
        ),
    ]

    db_session.add_all(findings)
    db_session.flush()

    repository = FindingRepository(
        db_session,
    )

    result = repository.count_by_repository_and_severity(
        1,
    )

    assert result["HIGH"] == 2
    assert result["CRITICAL"] == 1


def test_add_many_persists_remediation_rules(db_session) -> None:
    repo = FindingRepository(db_session)

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="1.0.0",
                fixed="2.0.0",
                affected_range="<2.0.0",
            ),
            RemediationRule(
                introduced="3.0.0",
                fixed="3.1.0",
                affected_range=">=3.0.0,<3.1.0",
            ),
        ],
    )

    finding = VulnerabilityInfo(
        identifier="CVE-2025-0001",
        aliases=["GHSA-test"],
        dependency_name="requests",
        dependency_version="1.5.0",
        ecosystem=Ecosystem.PYPI,
        sources=[Provider.OSV],
        severity=Severity.HIGH,
        cvss=8.1,
        summary="Test vulnerability",
        remediation=remediation,
        fixed_versions=["2.0.0", "3.1.0"],
    )

    repo.add_many(
        [finding],
        scan_id=1,
    )

    stored = db_session.query(Finding).one()

    assert stored.remediation == {
        "rules": [
            {
                "introduced": "1.0.0",
                "fixed": "2.0.0",
                "affected_range": "<2.0.0",
            },
            {
                "introduced": "3.0.0",
                "fixed": "3.1.0",
                "affected_range": ">=3.0.0,<3.1.0",
            },
        ],
    }


def test_add_many_persists_vulncheck_kev_data(db_session) -> None:
    repo = FindingRepository(db_session)

    finding = VulnerabilityInfo(
        identifier="CVE-2026-0001",
        aliases=["CVE-2026-0001"],
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        sources=[Provider.OSV],
        severity=Severity.CRITICAL,
        cvss=9.8,
        summary="Known exploited vulnerability",
        vulncheck_known_exploited=True,
        vulncheck_date_added=datetime(2026, 2, 1),
        vulncheck_cisa_date_added=datetime(2026, 2, 2),
        vulncheck_due_date=datetime(2026, 3, 1),
        vulncheck_vendor="VulnCheck Vendor",
        vulncheck_product="VulnCheck Product",
        vulncheck_required_action="Apply the vendor patch",
        vulncheck_known_ransomware="Known",
        vulncheck_reported_exploited_by_canaries=True,
    )

    repo.add_many(
        [finding],
        scan_id=1,
    )

    stored = db_session.query(Finding).one()

    assert stored.vulncheck_known_exploited is True
    assert stored.vulncheck_date_added == datetime(2026, 2, 1).date()
    assert stored.vulncheck_cisa_date_added == datetime(2026, 2, 2).date()
    assert stored.vulncheck_due_date == datetime(2026, 3, 1).date()
    assert stored.vulncheck_vendor == "VulnCheck Vendor"
    assert stored.vulncheck_product == "VulnCheck Product"
    assert stored.vulncheck_required_action == "Apply the vendor patch"
    assert stored.vulncheck_known_ransomware == "Known"
    assert stored.vulncheck_reported_exploited_by_canaries is True
