from sentinel.enums.ecosystem import Ecosystem
from sentinel.models.application import Application
from sentinel.models.dependency import Dependency
from sentinel.models.repository import Repository
from sentinel.models.scan import Scan


def test_dependency_defaults(db_session):
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

    dep = Dependency(
        scan_id=scan.id,
        name="django",
        version="5.0.6",
    )
    db_session.add(dep)
    db_session.flush()

    assert dep.id is not None
    assert dep.scan_id == scan.id
    assert dep.name == "django"
    assert dep.version == "5.0.6"
    assert dep.ecosystem == Ecosystem.PYPI.value


def test_dependency_purl(db_session):
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

    dep = Dependency(
        scan_id=scan.id,
        name="django",
        version="5.0.6",
        ecosystem="pypi",
    )
    db_session.add(dep)
    db_session.flush()

    assert dep.purl == "pkg:pypi/django@5.0.6"


def test_dependency_display_name(db_session):
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

    dep = Dependency(
        scan_id=scan.id,
        name="django",
        version="5.0.6",
    )
    db_session.add(dep)
    db_session.flush()

    assert dep.display_name == "django==5.0.6"
