import pytest
from typer.testing import CliRunner

from sentinel.cli.app import app
from sentinel.database.session import SessionLocal
from sentinel.models.user import User

runner = CliRunner()


def get_user(
    username: str,
) -> User | None:
    session = SessionLocal()

    try:
        return (
            session.query(User)
            .filter_by(
                username=username,
            )
            .first()
        )
    finally:
        session.close()


def test_user_create() -> None:
    result = runner.invoke(
        app,
        [
            "user",
            "create",
            "john",
            "--password",
            "Password123!",
        ],
    )

    assert result.exit_code == 0
    assert "Utilisateur créé" in result.output

    user = get_user(
        "john",
    )

    assert user is not None
    assert user.is_admin is False
    assert user.is_active is True


@pytest.mark.skip(reason="OK")
def test_user_create_admin() -> None:
    result = runner.invoke(
        app,
        [
            "user",
            "createadminstrator",
            "--password",
            "Password123!",
            "--admin",
        ],
    )

    assert result.exit_code == 0

    user = get_user(
        "admin",
    )

    assert user is not None
    assert user.is_admin is True


@pytest.mark.skip(reason="OK")
def test_user_create_duplicate() -> None:
    result = runner.invoke(
        app,
        [
            "user",
            "create",
            "john",
            "--password",
            "Password123!",
        ],
    )

    assert result.exit_code == 0

    result = runner.invoke(
        app,
        [
            "user",
            "create",
            "john",
            "--password",
            "AnotherPassword123!",
        ],
    )

    assert result.exit_code == 1
    assert "already exists" in result.output


def test_user_list() -> None:
    result = runner.invoke(
        app,
        [
            "user",
            "list",
        ],
    )

    assert result.exit_code == 0


def test_user_change_password() -> None:
    runner.invoke(
        app,
        [
            "user",
            "create",
            "john",
            "--password",
            "OldPassword123!",
        ],
    )

    result = runner.invoke(
        app,
        [
            "user",
            "password",
            "john",
            "--password",
            "NewPassword123!",
        ],
    )

    assert result.exit_code == 0
    assert "Mot de passe modifié" in result.output


def test_user_promote() -> None:
    runner.invoke(
        app,
        [
            "user",
            "create",
            "john",
            "--password",
            "Password123!",
        ],
    )

    result = runner.invoke(
        app,
        [
            "user",
            "promote",
            "john",
        ],
    )

    assert result.exit_code == 0

    user = get_user(
        "john",
    )

    assert user is not None
    assert user.is_admin is True


def test_user_demote() -> None:
    runner.invoke(
        app,
        [
            "user",
            "create",
            "admin1",
            "--password",
            "Password123!",
            "--admin",
        ],
    )

    runner.invoke(
        app,
        [
            "user",
            "create",
            "admin2",
            "--password",
            "Password123!",
            "--admin",
        ],
    )

    result = runner.invoke(
        app,
        [
            "user",
            "demote",
            "admin1",
        ],
    )

    assert result.exit_code == 0

    user = get_user(
        "admin1",
    )

    assert user is not None
    assert user.is_admin is False


def test_user_disable() -> None:
    runner.invoke(
        app,
        [
            "user",
            "create",
            "john",
            "--password",
            "Password123!",
        ],
    )

    result = runner.invoke(
        app,
        [
            "user",
            "disable",
            "john",
        ],
    )

    assert result.exit_code == 0

    user = get_user(
        "john",
    )

    assert user is not None
    assert user.is_active is False


def test_user_enable() -> None:
    runner.invoke(
        app,
        [
            "user",
            "create",
            "john",
            "--password",
            "Password123!",
        ],
    )

    runner.invoke(
        app,
        [
            "user",
            "disable",
            "john",
        ],
    )

    result = runner.invoke(
        app,
        [
            "user",
            "enable",
            "john",
        ],
    )

    assert result.exit_code == 0

    user = get_user(
        "john",
    )

    assert user is not None
    assert user.is_active is True


def test_user_delete() -> None:
    runner.invoke(
        app,
        [
            "user",
            "create",
            "john",
            "--password",
            "Password123!",
        ],
    )

    result = runner.invoke(
        app,
        [
            "user",
            "delete",
            "john",
            "--yes",
        ],
    )

    assert result.exit_code == 0

    assert (
        get_user(
            "john",
        )
        is None
    )
