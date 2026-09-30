from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from sentinel.security.jwt import create_access_token
from sentinel.services.auth_service import AuthService


def create_test_user(
    db_session: Session,
    username: str = "test-user",
    password: str = "TestPassword123!",
):
    service = AuthService(
        db_session,
    )

    user = service.create_user(
        username=username,
        password=password,
    )

    db_session.commit()
    db_session.refresh(user)

    return user


def test_get_current_user(
    client: TestClient,
    db_session: Session,
) -> None:

    user = create_test_user(
        db_session,
    )

    token = create_access_token(
        user_id=user.id,
        username=user.username,
    )

    response = client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data == {
        "id": user.id,
        "username": "test-user",
        "is_active": True,
        "is_admin": False,
    }


def test_get_current_user_requires_authentication(
    client: TestClient,
) -> None:

    response = client.get(
        "/auth/me",
    )

    assert response.status_code == 401


def test_get_current_user_rejects_invalid_token(
    client: TestClient,
) -> None:

    response = client.get(
        "/auth/me",
        headers={
            "Authorization": "Bearer invalid-token",
        },
    )

    assert response.status_code == 401


def test_get_current_user_rejects_inactive_user(
    client: TestClient,
    db_session: Session,
) -> None:

    user = create_test_user(
        db_session,
        username="inactive-user",
    )

    user.is_active = False
    db_session.commit()

    token = create_access_token(
        user_id=user.id,
        username=user.username,
    )

    response = client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401


def test_get_current_user_rejects_deleted_user(
    client: TestClient,
    db_session: Session,
) -> None:

    user = create_test_user(
        db_session,
        username="deleted-user",
    )

    token = create_access_token(
        user_id=user.id,
        username=user.username,
    )

    db_session.delete(user)
    db_session.commit()

    response = client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401
