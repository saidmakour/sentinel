from sentinel.enums.scan_status import ScanStatus
from sentinel.enums.source_type import SourceType
from sentinel.models.application import Application
from sentinel.models.dependency import Dependency
from sentinel.models.repository import Repository
from sentinel.models.scan import Scan


def test_scan_defaults(db_session):
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

    assert scan.id is not None
    assert scan.repository_id == repo.id
    assert scan.engine_version is not None
    assert scan.status == ScanStatus.STARTED
    assert scan.started_at is not None
    assert scan.finished_at is None
    assert scan.duration_seconds is None
    assert scan.is_finished is False


def test_scan_mark_finished(db_session):
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
    scan.mark_finished(12)
    db_session.add(scan)
    db_session.flush()

    assert scan.status == ScanStatus.SUCCESS
    assert scan.finished_at is not None
    assert scan.is_finished is True


def test_scan_mark_failed(db_session):
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

    scan.mark_failed()

    assert scan.status == ScanStatus.FAILED
    assert scan.finished_at is not None
    assert scan.is_finished is True


def test_scan_dependency_count(db_session):
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

    dep1 = Dependency(
        scan_id=scan.id,
        name="django",
        version="5.0.6",
    )
    dep2 = Dependency(
        scan_id=scan.id,
        name="requests",
        version="2.32.0",
    )

    db_session.add_all([dep1, dep2])
    db_session.flush()
    db_session.refresh(scan)

    assert scan.dependency_count == 2


def test_scan_has_source_information() -> None:

    scan = Scan(
        repository_id=1,
        status=ScanStatus.STARTED,
        source_type=SourceType.GIT,
        source_reference="https://gitlab.example.com/test.git",
    )

    assert scan.source_type == SourceType.GIT
    assert scan.source_reference == "https://gitlab.example.com/test.git"
