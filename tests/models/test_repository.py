from sentinel.models.application import Application
from sentinel.models.repository import Repository
from sentinel.models.scan import Scan


def test_repository_defaults(db_session):
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

    assert repo.id is not None
    assert repo.remote_url == ""
    assert repo.default_branch == "main"
    assert repo.language == "python"
    assert repo.package_manager == "pip"
    assert repo.enabled is True
    assert repo.created_at is not None
    assert repo.updated_at is not None


def test_repository_scan_count(db_session):
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

    scan1 = Scan(repository_id=repo.id)
    scan2 = Scan(repository_id=repo.id)

    db_session.add_all([scan1, scan2])
    db_session.flush()
    db_session.refresh(repo)

    assert repo.scan_count == 2


def test_repository_is_remote_false_when_remote_url_empty(db_session):
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

    assert repo.is_remote is False


def test_repository_is_remote_true_when_remote_url_present(db_session):
    app = Application(name="Sentinel")
    db_session.add(app)
    db_session.flush()

    repo = Repository(
        application_id=app.id,
        name="backend",
        local_path="",
        remote_url="https://github.com/org/backend.git",
    )
    db_session.add(repo)
    db_session.flush()

    assert repo.is_remote is True
