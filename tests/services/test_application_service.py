import pytest
from sqlalchemy.orm import Session

from sentinel.enums.criticality import Criticality
from sentinel.exceptions.application import ApplicationAlreadyExistsError
from sentinel.exceptions.application import ApplicationLevelCriticalityError
from sentinel.exceptions.application import ApplicationNameNotEmptyError
from sentinel.exceptions.application import ApplicationNotFoundError
from sentinel.services.application_service import ApplicationService


def test_create_application(db_session):
    service = ApplicationService(db_session)

    application = service.create(
        name="Sentinel",
        description="Security platform",
        owner="Security Team",
        criticality=3,
    )

    assert application.id is not None
    assert application.name == "Sentinel"
    assert application.description == "Security platform"
    assert application.owner == "Security Team"
    assert application.criticality == Criticality.HIGH


def test_create_application_strips_values(db_session):
    service = ApplicationService(db_session)

    application = service.create(
        name="  Sentinel  ",
        description="  Security platform  ",
        owner="  Security Team  ",
    )

    assert application.name == "Sentinel"
    assert application.description == "Security platform"
    assert application.owner == "Security Team"


def test_create_application_with_empty_name_raises_error(db_session):
    service = ApplicationService(db_session)

    with pytest.raises(ApplicationNameNotEmptyError):
        service.create(name="   ")


def test_create_duplicate_application_raises_error(db_session):
    service = ApplicationService(db_session)

    service.create(name="Sentinel")

    with pytest.raises(ApplicationAlreadyExistsError):
        service.create(name="Sentinel")


def test_create_application_with_invalid_criticality_raises_error(
    db_session: Session,
):
    service = ApplicationService(db_session)

    with pytest.raises(ApplicationLevelCriticalityError):
        service.create(
            name="Sentinel",
            criticality=10,
        )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1, Criticality.LOW),
        (2, Criticality.MEDIUM),
        (3, Criticality.HIGH),
        (4, Criticality.CRITICAL),
    ],
)
def test_create_application_with_valid_criticality(
    db_session,
    value,
    expected,
):
    service = ApplicationService(db_session)

    application = service.create(
        name=f"Application-{value}",
        criticality=value,
    )

    assert application.criticality == expected


def test_list_all_applications(db_session):
    service = ApplicationService(db_session)

    service.create(name="Application A")
    service.create(name="Application B")

    applications = service.list_all()

    assert len(applications) == 2
    assert {application.name for application in applications} == {
        "Application A",
        "Application B",
    }


def test_list_enabled_applications(db_session):
    service = ApplicationService(db_session)

    first = service.create(name="Application A")
    second = service.create(name="Application B")

    first.enabled = False
    db_session.commit()

    applications = service.list_enabled()

    assert len(applications) == 1
    assert applications[0].id == second.id


def test_get_application_by_id(db_session):
    service = ApplicationService(db_session)

    created = service.create(name="Sentinel")

    application = service.get_by_id(created.id)

    assert application is not None
    assert application.id == created.id
    assert application.name == "Sentinel"


def test_get_application_by_id_returns_none_when_not_found(
    db_session: Session,
):
    service = ApplicationService(db_session)

    application = service.get_by_id(999999)

    assert application is None


def test_get_application_by_name(db_session):
    service = ApplicationService(db_session)

    service.create(name="Sentinel")

    application = service.get_by_name("Sentinel")

    assert application is not None
    assert application.name == "Sentinel"


def test_get_application_by_name_returns_none_when_not_found(
    db_session,
):
    service = ApplicationService(db_session)

    application = service.get_by_name("Unknown")

    assert application is None


def test_update_application(db_session):
    service = ApplicationService(db_session)

    created = service.create(
        name="Sentinel",
        description="Old description",
        owner="Old owner",
        criticality=2,
    )

    updated = service.update(
        created.id,
        name="Sentinel Updated",
        description="New description",
        owner="New owner",
        criticality=4,
    )

    assert updated.id == created.id
    assert updated.name == "Sentinel Updated"
    assert updated.description == "New description"
    assert updated.owner == "New owner"
    assert updated.criticality == Criticality.CRITICAL


def test_update_application_partial_fields(db_session):
    service = ApplicationService(db_session)

    created = service.create(
        name="Sentinel",
        description="Description",
        owner="Owner",
        criticality=2,
    )

    updated = service.update(
        created.id,
        name="Sentinel Updated",
    )

    assert updated.name == "Sentinel Updated"
    assert updated.description == "Description"
    assert updated.owner == "Owner"
    assert updated.criticality == Criticality.MEDIUM


def test_update_application_not_found_raises_error(db_session):
    service = ApplicationService(db_session)

    with pytest.raises(ApplicationNotFoundError):
        service.update(
            999999,
            name="Sentinel",
        )


def test_update_application_with_empty_name_raises_error(
    db_session,
):
    service = ApplicationService(db_session)

    created = service.create(name="Sentinel")

    with pytest.raises(ApplicationNameNotEmptyError):
        service.update(
            created.id,
            name="   ",
        )


def test_update_application_with_duplicate_name_raises_error(
    db_session,
):
    service = ApplicationService(db_session)

    first = service.create(name="Application A")
    service.create(name="Application B")

    with pytest.raises(ApplicationAlreadyExistsError):
        service.update(
            first.id,
            name="Application B",
        )


@pytest.mark.parametrize("criticality", [0, 5, -1, 10])
def test_update_application_with_invalid_criticality_raises_error(
    db_session: Session,
    criticality: int,
):
    service = ApplicationService(db_session)

    created = service.create(name="Sentinel")

    with pytest.raises(ApplicationLevelCriticalityError):
        service.update(
            created.id,
            criticality=criticality,
        )


def test_delete_application_by_name(db_session):
    service = ApplicationService(db_session)

    service.create(name="Sentinel")

    service.delete("Sentinel")

    assert service.get_by_name("Sentinel") is None


def test_delete_application_by_name_not_found_raises_error(
    db_session,
):
    service = ApplicationService(db_session)

    with pytest.raises(ApplicationNotFoundError):
        service.delete("Unknown")


def test_delete_application_by_id(
    db_session,
):
    service = ApplicationService(db_session)

    created = service.create(
        name="Sentinel",
    )

    service.delete_by_id(
        created.id,
    )

    assert (
        service.get_by_id(
            created.id,
        )
        is None
    )
