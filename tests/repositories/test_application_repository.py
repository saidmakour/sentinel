from sentinel.models.application import Application
from sentinel.repositories.application_repository import ApplicationRepository


def create_application(
    name: str = "Test Application",
    enabled: bool = True,
) -> Application:
    return Application(
        name=name,
        description="Test description",
        owner="team-test",
        enabled=enabled,
    )


def test_create_application(db_session):
    repository = ApplicationRepository(db_session)

    application = create_application()

    result = repository.create(
        application,
    )

    assert result.id is not None
    assert result.name == "Test Application"


def test_get_by_id(db_session):
    repository = ApplicationRepository(db_session)

    application = create_application()

    repository.create(application)

    result = repository.get_by_id(
        application.id,
    )

    assert result is not None
    assert result.name == "Test Application"


def test_get_by_id_returns_none_when_not_found(db_session):
    repository = ApplicationRepository(db_session)

    result = repository.get_by_id(
        999,
    )

    assert result is None


def test_get_by_name(db_session):
    repository = ApplicationRepository(db_session)

    application = create_application()

    repository.create(application)

    result = repository.get_by_name(
        "Test Application",
    )

    assert result is not None
    assert result.name == "Test Application"


def test_get_by_name_returns_none_when_not_found(db_session):
    repository = ApplicationRepository(db_session)

    result = repository.get_by_name(
        "Unknown",
    )

    assert result is None


def test_list_all_applications(db_session):
    repository = ApplicationRepository(db_session)

    repository.create(
        create_application("Application 1"),
    )

    repository.create(
        create_application("Application 2"),
    )

    result = repository.list_all()

    assert len(result) == 2


def test_list_enabled_applications(db_session):
    repository = ApplicationRepository(db_session)

    repository.create(
        create_application(
            "Enabled App",
            True,
        ),
    )

    repository.create(
        create_application(
            "Disabled App",
            False,
        ),
    )

    result = repository.list_enabled()

    assert len(result) == 1
    assert result[0].name == "Enabled App"


def test_exists_returns_true(db_session):
    repository = ApplicationRepository(db_session)

    repository.create(
        create_application(),
    )

    assert repository.exists(
        "Test Application",
    )


def test_exists_returns_false(db_session):
    repository = ApplicationRepository(db_session)

    assert not repository.exists(
        "Unknown",
    )


def test_delete_application(db_session):
    repository = ApplicationRepository(db_session)

    application = create_application()

    repository.create(application)

    repository.delete(
        application,
    )

    result = repository.get_by_id(
        application.id,
    )

    assert result is None


def test_delete_by_name(db_session):
    repository = ApplicationRepository(db_session)

    repository.create(
        create_application(),
    )

    repository.delete_by_name(
        "Test Application",
    )

    result = repository.get_by_name(
        "Test Application",
    )

    assert result is None


def test_update_application(db_session):
    repository = ApplicationRepository(db_session)

    application = create_application()

    repository.create(application)

    application.description = "Updated description"

    result = repository.update(
        application,
    )

    assert result.description == "Updated description"
