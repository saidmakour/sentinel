from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.models.application import Application
from sentinel.models.dependency import Dependency
from sentinel.models.finding import Finding
from sentinel.models.repository import Repository
from sentinel.models.scan import Scan
from sentinel.services.findings_service import FindingService


def test_finding_persistence_pipeline(db_session):
    """
    Verify:
        Finding ORM
            ->
        Database
            ->
        FindingService
            ->
        VulnerabilityInfo
    """
    application = Application(
        name="test-application",
    )

    db_session.add(application)
    db_session.flush()

    repository = Repository(
        application_id=application.id,
        name="test-repository",
        remote_url="https://github.com/test/repository.git",
        default_branch="main",
    )

    db_session.add(repository)
    db_session.flush()

    scan = Scan(
        repository_id=repository.id,
        profile_name="default",
        engine_version="1.0.0-dev",
        status="SUCCESS",
        source_type="GIT",
        source_reference="test-repository",
        duration_seconds=10,
    )

    db_session.add(scan)
    db_session.flush()

    dependency = Dependency(
        scan_id=scan.id,
        name="requests",
        version="2.13.0",
        ecosystem="PyPI",
    )

    db_session.add(dependency)
    db_session.flush()

    finding = Finding(
        scan_id=scan.id,
        dependency_name="requests",
        dependency_version="2.13.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-48998",
        aliases=["GHSA-34xg-wgjx-8xph"],
        severity=Severity.HIGH,
        sources=[Provider.GHSA.value, Provider.NVD.value],
        cvss=7.5,
        status=VulnerabilityStatus.OPEN,
        summary="Test vulnerability",
        remediation={
            "rules": [
                {
                    "introduced": None,
                    "fixed": "2.10.2",
                    "affected_range": "<2.10.2",
                }
            ],
        },
        fixed_versions=["2.10.2"],
        known_exploited=False,
        epss_score=0.92,
        epss_percentile=0.99,
    )

    db_session.add(finding)

    db_session.commit()

    # Act
    service = FindingService(
        db_session,
    )

    findings = service.list_by_scan(
        scan.id,
    )

    # Assert
    assert len(findings) == 1

    result = findings[0]

    assert result.identifier == "CVE-2026-48998"

    assert result.dependency_name == "requests"
    assert result.dependency_version == "2.13.0"

    assert result.severity == Severity.HIGH

    assert result.ecosystem == Ecosystem.PYPI

    assert result.cvss == 7.5

    assert result.sources == [
        Provider.GHSA,
        Provider.NVD,
    ]

    assert result.status == VulnerabilityStatus.OPEN

    assert result.fixed_versions == [
        "2.10.2",
    ]

    assert result.summary == "Test vulnerability"
