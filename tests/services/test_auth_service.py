import pytest
from sqlalchemy.orm import Session

from sentinel.exceptions.auth import LastAdminError
from sentinel.exceptions.auth import UserAlreadyExistsError
from sentinel.exceptions.auth import UserNotFoundError
from sentinel.services.auth_service import AuthService


def test_create_user(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    user = service.create_user(
        username="john",
        password="Password123!",
    )

    assert user.id is not None
    assert user.username == "john"
    assert user.is_active is True
    assert user.is_admin is False
    assert user.password_hash != "Password123!"


def test_create_admin(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    user = service.create_user(
        username="admin",
        password="Password123!",
        is_admin=True,
    )

    assert user.is_admin is True
    assert user.is_active is True


def test_create_user_with_duplicate_username(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    service.create_user(
        username="john",
        password="Password123!",
    )

    with pytest.raises(UserAlreadyExistsError):
        service.create_user(
            username="john",
            password="AnotherPassword123!",
        )


def test_authenticate_with_valid_credentials(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    created_user = service.create_user(
        username="john",
        password="Password123!",
    )

    authenticated_user = service.authenticate(
        username="john",
        password="Password123!",
    )

    assert authenticated_user is not None
    assert authenticated_user.id == created_user.id


def test_authenticate_with_invalid_password(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    service.create_user(
        username="john",
        password="Password123!",
    )

    authenticated_user = service.authenticate(
        username="john",
        password="WrongPassword!",
    )

    assert authenticated_user is None


def test_authenticate_with_unknown_user(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    authenticated_user = service.authenticate(
        username="unknown",
        password="Password123!",
    )

    assert authenticated_user is None


def test_authenticate_with_disabled_user(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    service.create_user(
        username="john",
        password="Password123!",
    )

    service.disable_user(
        "john",
    )

    authenticated_user = service.authenticate(
        username="john",
        password="Password123!",
    )

    assert authenticated_user is None


def test_list_users(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    service.create_user(
        username="john",
        password="Password123!",
    )

    service.create_user(
        username="jane",
        password="Password123!",
    )

    users = service.list_users()

    assert len(users) == 2
    assert users[0].username == "john"
    assert users[1].username == "jane"


def test_change_password(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    service.create_user(
        username="john",
        password="OldPassword123!",
    )

    service.change_password(
        username="john",
        password="NewPassword123!",
    )

    assert (
        service.authenticate(
            username="john",
            password="OldPassword123!",
        )
        is None
    )

    assert (
        service.authenticate(
            username="john",
            password="NewPassword123!",
        )
        is not None
    )


def test_change_password_for_unknown_user(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    with pytest.raises(UserNotFoundError):
        service.change_password(
            username="unknown",
            password="Password123!",
        )


def test_promote_user(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    service.create_user(
        username="john",
        password="Password123!",
    )

    user = service.promote_user(
        "john",
    )

    assert user.is_admin is True


def test_promote_unknown_user(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    with pytest.raises(UserNotFoundError):
        service.promote_user(
            "unknown",
        )


def test_demote_user(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    service.create_user(
        username="admin1",
        password="Password123!",
        is_admin=True,
    )

    service.create_user(
        username="admin2",
        password="Password123!",
        is_admin=True,
    )

    user = service.demote_user(
        "admin1",
    )

    assert user.is_admin is False


def test_cannot_demote_last_active_admin(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    service.create_user(
        username="admin",
        password="Password123!",
        is_admin=True,
    )

    with pytest.raises(LastAdminError):
        service.demote_user(
            "admin",
        )


def test_disable_user(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    service.create_user(
        username="john",
        password="Password123!",
    )

    user = service.disable_user(
        "john",
    )

    assert user.is_active is False


def test_enable_user(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    service.create_user(
        username="john",
        password="Password123!",
    )

    service.disable_user(
        "john",
    )

    user = service.enable_user(
        "john",
    )

    assert user.is_active is True


def test_cannot_disable_last_active_admin(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    service.create_user(
        username="admin",
        password="Password123!",
        is_admin=True,
    )

    with pytest.raises(LastAdminError):
        service.disable_user(
            "admin",
        )


def test_delete_user(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    service.create_user(
        username="john",
        password="Password123!",
    )

    service.delete_user(
        "john",
    )

    assert (
        service.authenticate(
            username="john",
            password="Password123!",
        )
        is None
    )


def test_delete_unknown_user(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    with pytest.raises(UserNotFoundError):
        service.delete_user(
            "unknown",
        )


def test_cannot_delete_last_admin(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    service.create_user(
        username="admin",
        password="Password123!",
        is_admin=True,
    )

    with pytest.raises(LastAdminError):
        service.delete_user(
            "admin",
        )


def test_delete_admin_when_another_admin_exists(
    db_session: Session,
) -> None:
    service = AuthService(
        db_session,
    )

    service.create_user(
        username="admin1",
        password="Password123!",
        is_admin=True,
    )

    service.create_user(
        username="admin2",
        password="Password123!",
        is_admin=True,
    )

    service.delete_user(
        "admin1",
    )

    assert (
        service.user_repository.get_by_username(
            "admin1",
        )
        is None
    )
