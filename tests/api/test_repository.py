from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from sentinel.enums.git_auth_method import GitAuthMethod
from sentinel.models.application import Application
from sentinel.models.repository import Repository
from sentinel.models.user import User
from sentinel.security.jwt import create_access_token
from sentinel.security.password import hash_password


def create_user(
    db_session: Session,
    username: str,
    is_admin: bool = False,
) -> User:
    user = User(
        username=username,
        password_hash=hash_password("password"),
        is_active=True,
        is_admin=is_admin,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def auth_headers(user: User) -> dict[str, str]:
    token = create_access_token(
        user_id=user.id,
        username=user.username,
    )
    return {
        "Authorization": f"Bearer {token}",
    }


def create_application(
    db_session: Session,
) -> Application:
    application = Application(
        name="Sentinel",
        description="Security platform",
        owner="Security",
        criticality=4,
    )
    db_session.add(application)
    db_session.commit()
    db_session.refresh(application)
    return application


def create_repository(
    db_session: Session,
    application: Application,
    local_path: Path,
    name: str = "backend",
) -> Repository:
    repository = Repository(
        application_id=application.id,
        name=name,
        local_path=str(local_path),
    )
    db_session.add(repository)
    db_session.commit()
    db_session.refresh(repository)
    return repository


def test_create_repository(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    response = client.post(
        "/repositories",
        headers=auth_headers(admin),
        json={
            "application_id": application.id,
            "name": "backend",
            "local_path": str(tmp_path),
            "remote_url": "",
            "auth_method": "none",
            "default_branch": "main",
            "language": "python",
            "package_manager": "pip",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["name"] == "backend"
    assert data["local_path"] == str(tmp_path)
    assert data["auth_method"] == GitAuthMethod.NONE.value
    assert data["default_branch"] == "main"
    assert data["language"] == "python"
    assert data["package_manager"] == "pip"


def test_create_repository_with_https_authentication(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    response = client.post(
        "/repositories",
        headers=auth_headers(admin),
        json={
            "application_id": application.id,
            "name": "backend",
            "local_path": str(tmp_path),
            "remote_url": "https://git.example.com/backend.git",
            "auth_method": GitAuthMethod.HTTPS.value,
            "default_branch": "main",
            "language": "python",
            "package_manager": "pip",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["remote_url"] == "https://git.example.com/backend.git"
    assert data["auth_method"] == GitAuthMethod.HTTPS.value


def test_create_repository_with_ssh_authentication(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    response = client.post(
        "/repositories",
        headers=auth_headers(admin),
        json={
            "application_id": application.id,
            "name": "backend",
            "local_path": str(tmp_path),
            "remote_url": "git@git.example.com:backend.git",
            "auth_method": GitAuthMethod.SSH.value,
            "default_branch": "main",
            "language": "python",
            "package_manager": "pip",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["remote_url"] == "git@git.example.com:backend.git"
    assert data["auth_method"] == GitAuthMethod.SSH.value


def test_create_repository_requires_authentication(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    application = create_application(
        db_session,
    )

    response = client.post(
        "/repositories",
        json={
            "application_id": application.id,
            "name": "backend",
            "local_path": str(tmp_path),
        },
    )

    assert response.status_code == 401


def test_create_repository_requires_admin(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    user = create_user(
        db_session,
        "user",
    )

    application = create_application(
        db_session,
    )

    response = client.post(
        "/repositories",
        headers=auth_headers(user),
        json={
            "application_id": application.id,
            "name": "backend",
            "local_path": str(tmp_path),
        },
    )

    assert response.status_code == 403
    assert response.json() == {
        "detail": "Admin privileges required",
    }


def test_create_repository_application_not_found(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    response = client.post(
        "/repositories",
        headers=auth_headers(admin),
        json={
            "application_id": 999999,
            "name": "backend",
            "local_path": str(tmp_path),
            "language": "python",
            "package_manager": "pip",
        },
    )

    assert response.status_code == 404


def test_create_repository_duplicate_name(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    payload = {
        "application_id": application.id,
        "name": "backend",
        "local_path": str(tmp_path),
        "language": "python",
        "package_manager": "pip",
    }

    first = client.post(
        "/repositories",
        headers=auth_headers(admin),
        json=payload,
    )

    assert first.status_code == 201

    second = client.post(
        "/repositories",
        headers=auth_headers(admin),
        json=payload,
    )

    assert second.status_code == 409


def test_create_repository_duplicate_path(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    first = client.post(
        "/repositories",
        headers=auth_headers(admin),
        json={
            "application_id": application.id,
            "name": "backend",
            "local_path": str(tmp_path),
        },
    )

    assert first.status_code == 201

    second = client.post(
        "/repositories",
        headers=auth_headers(admin),
        json={
            "application_id": application.id,
            "name": "frontend",
            "local_path": str(tmp_path),
        },
    )

    assert second.status_code == 409


def test_create_repository_empty_name(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    response = client.post(
        "/repositories",
        headers=auth_headers(admin),
        json={
            "application_id": application.id,
            "name": "",
            "local_path": str(tmp_path),
        },
    )

    assert response.status_code == 400


def test_create_repository_empty_path(
    client: TestClient,
    db_session: Session,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    response = client.post(
        "/repositories",
        headers=auth_headers(admin),
        json={
            "application_id": application.id,
            "name": "backend",
            "local_path": "",
        },
    )

    assert response.status_code == 400


def test_create_repository_path_not_found(
    client: TestClient,
    db_session: Session,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    response = client.post(
        "/repositories",
        headers=auth_headers(admin),
        json={
            "application_id": application.id,
            "name": "backend",
            "local_path": "/path/that/does/not/exist",
        },
    )

    assert response.status_code == 400


def test_create_repository_remote_requires_default_branch(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    response = client.post(
        "/repositories",
        headers=auth_headers(admin),
        json={
            "application_id": application.id,
            "name": "backend",
            "local_path": str(tmp_path),
            "remote_url": "https://git.example.com/backend.git",
            "default_branch": "",
            "language": "python",
            "package_manager": "pip",
        },
    )

    assert response.status_code == 400


def test_create_repository_remote_requires_language(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    response = client.post(
        "/repositories",
        headers=auth_headers(admin),
        json={
            "application_id": application.id,
            "name": "backend",
            "local_path": str(tmp_path),
            "remote_url": "https://git.example.com/backend.git",
            "default_branch": "main",
            "language": "",
            "package_manager": "pip",
        },
    )

    assert response.status_code == 400


def test_create_repository_remote_requires_package_manager(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    response = client.post(
        "/repositories",
        headers=auth_headers(admin),
        json={
            "application_id": application.id,
            "name": "backend",
            "local_path": str(tmp_path),
            "remote_url": "https://git.example.com/backend.git",
            "default_branch": "main",
            "language": "python",
            "package_manager": "",
        },
    )

    assert response.status_code == 400


def test_get_repository(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    user = create_user(
        db_session,
        "user",
    )

    application = create_application(
        db_session,
    )

    repository = create_repository(
        db_session,
        application,
        tmp_path,
    )

    response = client.get(
        f"/repositories/{repository.id}",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == repository.id
    assert data["name"] == "backend"
    assert data["auth_method"] == GitAuthMethod.NONE.value


def test_get_repository_not_found(
    client: TestClient,
    db_session: Session,
) -> None:
    user = create_user(
        db_session,
        "user",
    )

    response = client.get(
        "/repositories/999999",
        headers=auth_headers(user),
    )

    assert response.status_code == 404


def test_update_repository(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    repository = create_repository(
        db_session,
        application,
        tmp_path,
    )

    response = client.patch(
        f"/repositories/{repository.id}",
        headers=auth_headers(admin),
        json={
            "default_branch": "develop",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["default_branch"] == "develop"


def test_update_repository_auth_method(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    repository = create_repository(
        db_session,
        application,
        tmp_path,
    )

    response = client.patch(
        f"/repositories/{repository.id}",
        headers=auth_headers(admin),
        json={
            "auth_method": GitAuthMethod.SSH.value,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["auth_method"] == GitAuthMethod.SSH.value


def test_update_repository_requires_authentication(
    client: TestClient,
) -> None:
    response = client.patch(
        "/repositories/999999",
        json={
            "default_branch": "develop",
        },
    )

    assert response.status_code == 401


def test_update_repository_requires_admin(
    client: TestClient,
    db_session: Session,
) -> None:
    user = create_user(
        db_session,
        "user",
    )

    response = client.patch(
        "/repositories/999999",
        headers=auth_headers(user),
        json={
            "default_branch": "develop",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Admin privileges required"


def test_update_repository_not_found(
    client: TestClient,
    db_session: Session,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    response = client.patch(
        "/repositories/999999",
        headers=auth_headers(admin),
        json={
            "default_branch": "develop",
        },
    )

    assert response.status_code == 404


def test_update_repository_duplicate_name(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    repository = create_repository(
        db_session,
        application,
        tmp_path,
        name="backend",
    )

    second_path = tmp_path / "frontend"
    second_path.mkdir()

    create_repository(
        db_session,
        application,
        second_path,
        name="frontend",
    )

    response = client.patch(
        f"/repositories/{repository.id}",
        headers=auth_headers(admin),
        json={
            "name": "frontend",
        },
    )

    assert response.status_code == 409


def test_update_repository_duplicate_path(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    repository = create_repository(
        db_session,
        application,
        tmp_path,
        name="backend",
    )

    second_path = tmp_path / "frontend"
    second_path.mkdir()

    create_repository(
        db_session,
        application,
        second_path,
        name="frontend",
    )

    response = client.patch(
        f"/repositories/{repository.id}",
        headers=auth_headers(admin),
        json={
            "local_path": str(second_path),
        },
    )

    assert response.status_code == 409


def test_update_repository_empty_name(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    repository = create_repository(
        db_session,
        application,
        tmp_path,
    )

    response = client.patch(
        f"/repositories/{repository.id}",
        headers=auth_headers(admin),
        json={
            "name": "",
        },
    )

    assert response.status_code == 400


def test_update_repository_empty_path(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    repository = create_repository(
        db_session,
        application,
        tmp_path,
    )

    response = client.patch(
        f"/repositories/{repository.id}",
        headers=auth_headers(admin),
        json={
            "local_path": "",
        },
    )

    assert response.status_code == 400


def test_update_repository_path_not_found(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    repository = create_repository(
        db_session,
        application,
        tmp_path,
    )

    response = client.patch(
        f"/repositories/{repository.id}",
        headers=auth_headers(admin),
        json={
            "local_path": "/path/that/does/not/exist",
        },
    )

    assert response.status_code == 400


def test_update_repository_remote_requires_default_branch(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    repository = create_repository(
        db_session,
        application,
        tmp_path,
    )

    response = client.patch(
        f"/repositories/{repository.id}",
        headers=auth_headers(admin),
        json={
            "remote_url": "https://git.example.com/backend.git",
            "default_branch": "",
        },
    )

    assert response.status_code == 400


def test_delete_repository(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    application = create_application(
        db_session,
    )

    repository = create_repository(
        db_session,
        application,
        tmp_path,
    )

    response = client.delete(
        f"/repositories/{repository.id}",
        headers=auth_headers(admin),
    )

    assert response.status_code == 204

    assert (
        db_session.get(
            Repository,
            repository.id,
        )
        is None
    )


def test_delete_repository_requires_authentication(
    client: TestClient,
) -> None:
    response = client.delete(
        "/repositories/999999",
    )

    assert response.status_code == 401


def test_delete_repository_requires_admin(
    client: TestClient,
    db_session: Session,
) -> None:
    user = create_user(
        db_session,
        "user",
    )

    response = client.delete(
        "/repositories/999999",
        headers=auth_headers(user),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Admin privileges required"


def test_delete_repository_not_found(
    client: TestClient,
    db_session: Session,
) -> None:
    admin = create_user(
        db_session,
        "admin",
        is_admin=True,
    )

    response = client.delete(
        "/repositories/999999",
        headers=auth_headers(admin),
    )

    assert response.status_code == 404


def test_list_repositories_requires_authentication(
    client: TestClient,
) -> None:
    response = client.get(
        "/repositories",
        params={"application_id": 1},
    )

    assert response.status_code == 401


def test_get_repository_requires_authentication(
    client: TestClient,
) -> None:
    response = client.get(
        "/repositories/999999",
    )

    assert response.status_code == 401
