from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.severity import Severity
from sentinel.models.application import Application
from sentinel.models.dependency import Dependency
from sentinel.models.finding import Finding
from sentinel.models.repository import Repository
from sentinel.models.scan import Scan


def test_full_relationship_chain(db_session):
    app = Application(name="Sentinel")
    db_session.add(app)
    db_session.flush()

    repo = Repository(
        application_id=app.id,
        name="backend",
        local_path="/src/backend",
        remote_url="https://github.com/org/backend.git",
    )
    db_session.add(repo)
    db_session.flush()

    scan = Scan(repository_id=repo.id)
    db_session.add(scan)
    db_session.flush()

    dep = Dependency(
        scan_id=scan.id,
        name="django",
        version="5.0.6",
    )
    finding = Finding(
        scan_id=scan.id,
        dependency_name="django",
        dependency_version="5.0.6",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-0001",
        severity=Severity.HIGH,
        cvss=8.4,
        summary="Example vulnerability",
    )

    db_session.add_all([dep, finding])
    db_session.flush()

    db_session.refresh(app)
    db_session.refresh(repo)
    db_session.refresh(scan)

    assert app.repository_count == 1
    assert repo.scan_count == 1
    assert repo.is_remote is True
    assert scan.dependency_count == 1
    assert len(scan.findings) == 1
