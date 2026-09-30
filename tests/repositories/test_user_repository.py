from sentinel.models.user import User
from sentinel.repositories.user_repository import UserRepository


def create_user(
    username: str = "test-user",
    is_active: bool = True,
    is_admin: bool = False,
) -> User:
    return User(
        username=username,
        password_hash="test-password-hash",
        is_active=is_active,
        is_admin=is_admin,
    )


def test_create_user(db_session):
    repository = UserRepository(db_session)

    user = create_user()

    result = repository.create(
        user,
    )

    assert result.id is not None
    assert result.username == "test-user"
    assert result.password_hash == "test-password-hash"


def test_get_by_id(db_session):
    repository = UserRepository(db_session)

    user = create_user()

    repository.create(
        user,
    )

    result = repository.get_by_id(
        user.id,
    )

    assert result is not None
    assert result.username == "test-user"


def test_get_by_id_returns_none_when_not_found(db_session):
    repository = UserRepository(db_session)

    result = repository.get_by_id(
        999,
    )

    assert result is None


def test_get_by_username(db_session):
    repository = UserRepository(db_session)

    repository.create(
        create_user(),
    )

    result = repository.get_by_username(
        "test-user",
    )

    assert result is not None
    assert result.username == "test-user"


def test_get_by_username_returns_none_when_not_found(db_session):
    repository = UserRepository(db_session)

    result = repository.get_by_username(
        "unknown",
    )

    assert result is None


def test_list_users(db_session):
    repository = UserRepository(db_session)

    repository.create(
        create_user("user-1"),
    )

    repository.create(
        create_user("user-2"),
    )

    result = repository.list()

    assert len(result) == 2
    assert result[0].username == "user-1"
    assert result[1].username == "user-2"


def test_update_user(db_session):
    repository = UserRepository(db_session)

    user = create_user()

    repository.create(
        user,
    )

    user.is_active = False
    user.is_admin = True

    result = repository.update(
        user,
    )

    assert result.is_active is False
    assert result.is_admin is True


def test_delete_user(db_session):
    repository = UserRepository(db_session)

    user = create_user()

    repository.create(
        user,
    )

    repository.delete(
        user,
    )

    result = repository.get_by_id(
        user.id,
    )

    assert result is None


def test_user_defaults(db_session):
    repository = UserRepository(db_session)

    user = User(
        username="default-user",
        password_hash="test-password-hash",
    )

    result = repository.create(
        user,
    )

    assert result.is_active is True
    assert result.is_admin is False
