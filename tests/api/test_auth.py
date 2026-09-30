from datetime import UTC
from datetime import datetime
from datetime import timedelta

import jwt
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from sentinel.config.settings import settings
from sentinel.models.user import User
from sentinel.security.jwt import create_access_token
from sentinel.services.auth_service import AuthService


def create_test_user(
    db_session: Session,
    *,
    username: str = "test-user",
    password: str = "TestPassword123!",
    is_admin: bool = False,
    is_active: bool = True,
) -> User:
    service = AuthService(
        db_session,
    )

    user = service.create_user(
        username=username,
        password=password,
        is_admin=is_admin,
    )

    user.is_active = is_active
    db_session.commit()
    db_session.refresh(user)

    return user


def test_login_success(
    client: TestClient,
    db_session: Session,
) -> None:
    create_test_user(
        db_session,
    )

    response = client.post(
        "/auth/login",
        json={
            "username": "test-user",
            "password": "TestPassword123!",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["access_token"]
    assert data["token_type"] == "bearer"


def test_login_invalid_password(
    client: TestClient,
    db_session: Session,
) -> None:
    create_test_user(
        db_session,
    )

    response = client.post(
        "/auth/login",
        json={
            "username": "test-user",
            "password": "WrongPassword123!",
        },
    )

    assert response.status_code == 401

    assert response.json() == {
        "detail": "Invalid username or password",
    }


def test_login_unknown_user(
    client: TestClient,
) -> None:
    response = client.post(
        "/auth/login",
        json={
            "username": "unknown-user",
            "password": "TestPassword123!",
        },
    )

    assert response.status_code == 401

    assert response.json() == {
        "detail": "Invalid username or password",
    }


def test_login_inactive_user(
    client: TestClient,
    db_session: Session,
) -> None:
    create_test_user(
        db_session,
        is_active=False,
    )

    response = client.post(
        "/auth/login",
        json={
            "username": "test-user",
            "password": "TestPassword123!",
        },
    )

    assert response.status_code == 401

    assert response.json() == {
        "detail": "Invalid username or password",
    }


def test_login_does_not_leak_user_existence(
    client: TestClient,
    db_session: Session,
) -> None:
    create_test_user(
        db_session,
    )

    existing_user_response = client.post(
        "/auth/login",
        json={
            "username": "test-user",
            "password": "WrongPassword123!",
        },
    )

    unknown_user_response = client.post(
        "/auth/login",
        json={
            "username": "unknown-user",
            "password": "WrongPassword123!",
        },
    )

    assert existing_user_response.status_code == 401
    assert unknown_user_response.status_code == 401

    assert existing_user_response.json() == unknown_user_response.json()


def test_get_me_requires_authentication(
    client: TestClient,
) -> None:
    response = client.get(
        "/auth/me",
    )

    assert response.status_code == 401


def test_get_me(
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

    assert response.json() == {
        "id": user.id,
        "username": "test-user",
        "is_active": True,
        "is_admin": False,
    }


def test_get_me_admin(
    client: TestClient,
    db_session: Session,
) -> None:
    user = create_test_user(
        db_session,
        is_admin=True,
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

    assert data["id"] == user.id
    assert data["username"] == user.username
    assert data["is_active"] is True
    assert data["is_admin"] is True


def test_get_me_invalid_token(
    client: TestClient,
) -> None:
    response = client.get(
        "/auth/me",
        headers={
            "Authorization": "Bearer invalid-token",
        },
    )

    assert response.status_code == 401

    assert response.json() == {
        "detail": "Invalid or expired access token",
    }

    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_get_me_tampered_token(
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

    parts = token.split(".")
    assert len(parts) == 3

    parts[1] = parts[1][::-1]

    tampered_token = ".".join(parts)

    response = client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {tampered_token}",
        },
    )

    assert response.status_code == 401

    assert response.json() == {
        "detail": "Invalid or expired access token",
    }


def test_get_me_expired_token(
    client: TestClient,
    db_session: Session,
) -> None:
    user = create_test_user(
        db_session,
    )

    now = datetime.now(UTC)

    token = jwt.encode(
        {
            "sub": str(user.id),
            "username": user.username,
            "iat": now - timedelta(minutes=10),
            "exp": now - timedelta(minutes=5),
        },
        settings.api_jwt_secret,
        algorithm=settings.api_jwt_algorithm,
    )

    response = client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401

    assert response.json() == {
        "detail": "Invalid or expired access token",
    }


def test_get_me_invalid_subject(
    client: TestClient,
) -> None:
    now = datetime.now(UTC)

    token = jwt.encode(
        {
            "sub": "not-an-integer",
            "username": "test-user",
            "iat": now,
            "exp": now + timedelta(minutes=30),
        },
        settings.api_jwt_secret,
        algorithm=settings.api_jwt_algorithm,
    )

    response = client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401

    assert response.json() == {
        "detail": "Invalid access token",
    }

    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_get_me_nonexistent_user(
    client: TestClient,
) -> None:
    token = create_access_token(
        user_id=999999,
        username="unknown-user",
    )

    response = client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401

    assert response.json() == {
        "detail": "User not found",
    }

    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_get_me_inactive_user(
    client: TestClient,
    db_session: Session,
) -> None:
    user = create_test_user(
        db_session,
        is_active=False,
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

    assert response.status_code == 401

    assert response.json() == {
        "detail": "Inactive user",
    }

    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_get_me_reflects_database_admin_status(
    client: TestClient,
    db_session: Session,
) -> None:
    user = create_test_user(
        db_session,
        is_admin=False,
    )

    token = create_access_token(
        user_id=user.id,
        username=user.username,
    )

    user.is_admin = True
    db_session.commit()

    response = client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 200
    assert response.json()["is_admin"] is True


def test_get_me_reflects_database_active_status(
    client: TestClient,
    db_session: Session,
) -> None:
    user = create_test_user(
        db_session,
        is_active=True,
    )

    token = create_access_token(
        user_id=user.id,
        username=user.username,
    )

    user.is_active = False
    db_session.commit()

    response = client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401

    assert response.json() == {
        "detail": "Inactive user",
    }
