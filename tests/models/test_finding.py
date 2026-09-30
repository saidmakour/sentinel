from sentinel.enums.ecosystem import Ecosystem
from sentinel.models.application import Application
from sentinel.models.finding import Finding
from sentinel.models.repository import Repository
from sentinel.models.scan import Scan


def test_finding_creation(db_session):
    app = Application(name="Sentinel")
    db_session.add(app)
    db_session.flush()

    repo = Repository(
        application_id=app.id,
        name="backend",
        local_path="/src/backend",
    )
    db_session.add(repo)
    db_session.flush()

    scan = Scan(repository_id=repo.id)
    db_session.add(scan)
    db_session.flush()

    finding = Finding(
        scan_id=scan.id,
        dependency_name="django",
        dependency_version="5.0.6",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-0001",
        severity="high",
        cvss=8.4,
        summary="Example vulnerability",
    )

    db_session.add(finding)
    db_session.flush()

    assert finding.id is not None
    assert finding.scan_id == scan.id
    assert finding.dependency_name == "django"
    assert finding.dependency_version == "5.0.6"
    assert finding.identifier == "CVE-2026-0001"
    assert finding.severity == "high"
    assert finding.cvss == 8.4
    assert finding.summary == "Example vulnerability"


def test_finding_cvss_can_be_none(db_session):
    app = Application(name="Sentinel")
    db_session.add(app)
    db_session.flush()

    repo = Repository(
        application_id=app.id,
        name="backend",
        local_path="/src/backend",
    )
    db_session.add(repo)
    db_session.flush()

    scan = Scan(repository_id=repo.id)
    db_session.add(scan)
    db_session.flush()

    finding = Finding(
        scan_id=scan.id,
        dependency_name="django",
        dependency_version="5.0.6",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-0001",
        severity="medium",
        cvss=None,
        summary="Example vulnerability",
    )
    db_session.add(finding)
    db_session.flush()

    assert finding.cvss is None


def test_finding_comparison_key() -> None:

    finding = Finding(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2025-1234",
        severity="HIGH",
        summary="test",
    )
    print(finding)
    assert finding.comparison_key == (
        "requests",
        "2.31.0",
        "CVE-2025-1234",
    )
