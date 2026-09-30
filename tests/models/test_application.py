from sentinel.models.application import Application
from sentinel.models.repository import Repository


def test_application_defaults(db_session):
    app = Application(name="Sentinel")
    db_session.add(app)
    db_session.flush()

    assert app.name == "Sentinel"
    assert app.description == ""
    assert app.owner == ""
    assert app.criticality == 3
    assert app.enabled is True


def test_application_disable_enable():
    app = Application(name="Sentinel")

    app.disable()
    assert app.enabled is False

    app.enable()
    assert app.enabled is True


def test_application_repository_count():
    app = Application(name="Sentinel")
    assert app.repository_count == 0

    app.repositories = [
        Repository(name="repo1", local_path="/tmp/repo1"),
        Repository(name="repo2", local_path="/tmp/repo2"),
    ]

    assert app.repository_count == 2


def test_application_persisted(db_session):
    app = Application(name="Sentinel")

    db_session.add(app)
    db_session.flush()

    assert app.id is not None
    assert app.created_at is not None
    assert app.updated_at is not None


#
